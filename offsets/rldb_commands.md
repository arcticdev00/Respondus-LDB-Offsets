# RLDB Commands Reference

**Version:** 2.1.5.00
**Protocol:** RLDB (Respondus LockDown Browser) command protocol
**Source:** Browser URL parameter analysis + driver string analysis

---

## Overview

RLDB commands are URL-encoded parameters passed to the LockDown Browser via navigation events. They are processed by `CLDBDoSomeStuff` (the URL/navigation handler export in LDB.dll). Commands can be triggered by navigating the browser to `rldb://` protocol URLs or via `javascript:` URLs with RLDB parameters.

### Command Format

```
rldb://command?param=value
javascript:rldbcmd("command", "value")
```

Some commands accept boolean flags (`=1` to enable, `=0` to disable).

---

## 1. Security & Detection Commands

| Command | Parameters | Purpose | Origin |
|---------|-----------|---------|--------|
| `rldbdetect` | — | General detection request | EXE → LDB.dll |
| `rldbvm` | — | VM detection — checks for virtualization (CPUID hypervisor leaf) | EXE → LDB.dll |
| `rldbvcam` | — | Webcam detection | EXE → LDB.dll |
| `rldbsm` | `=0/1` | Screen monitor — detects screen sharing/recording software | EXE → LDB.dll |
| `rldbkh` | `=0/1` | Keyboard hook check — verifies WH_KEYBOARD_LL is installed | EXE → LDB.dll |
| `rldbfocus` | `=0/1/2` | Focus/window detection — alt-tab, window switch detection | EXE → LDB.dll |
| `rldbxb` | `=0/1` | Unknown — potentially exam browser verification | EXE → LDB.dll |
| `rldbqn` | `=0/1` | Quiz notification active — see quiz_active.md | EXE → LDB.dll |
| `rldbbdw` | — | Bandwidth check | EXE → LDB.dll |
| `rldbbt` | — | Bluetooth detection | EXE → LDB.dll |
| `rldbacv` | — | Audio capture validation | EXE → LDB.dll |
| `rldbarv` | — | Audio recording validation | EXE → LDB.dll |
| `rldbcv` | — | Camera/video check | EXE → LDB.dll |
| `rldbrv` | — | Recording verification | EXE → LDB.dll |

### Detection Bitmask

The `CLDBDoSomeOtherStuffs` export returns a bitmask indicating detection states:

| Bit | Value | Flag | Related Command |
|-----|-------|------|-----------------|
| 10 | `0x400` | LOCKDOWN_ACTIVE | — (internal state) |
| 11 | `0x800` | EXIT_ACTIVE | — (internal state) |
| 12 | `0x1000` | PROCTORING_ACTIVE | — (internal state) |

---

## 2. Process & Application Control Commands

| Command | Parameters | Purpose |
|---------|-----------|---------|
| `rldbbl` | — | Blacklist check — launches process blacklist scan |
| `rldbwl` | — | Whitelist validation — verifies allowed processes |
| `rldbmodified` | — | Detect browser/OS modifications |
| `rldbtk1` | — | Task killer — terminates blacklisted processes |
| `rldbtx2` | — | Unknown — potentially an extended task killer |

### Blacklist Architecture

- 3020+ entries stored as heap-allocated UTF-16LE strings
- Set via driver communication port (`CMD_ADD_BLOCKLIST`)
- Categories: Browsers, System Tools, Analysis Tools, Screen Recorders, VPN/Proxy, Remote Access, Communication, Installers, Updaters, Services (200+), Other (2668+)
- Detection methods:
  - Process name match
  - Window class match (via EnumWindows/FindWindowW)
  - Signature validation (via kernel driver `CiValidateFileObject`)

---

## 3. Input Control Commands

| Command | Parameters | Purpose |
|---------|-----------|---------|
| `rldbprt` | — | Print screen prevention |
| `rldbswipe` | — | Swipe detection (touchscreen) |
| `rldbsleep` | — | Sleep/hibernate detection |
| `rldbpl` | — | Paste lock protection |
| `rldbsp` | — | Screenshot prevention |
| `rldbsl` | — | Screen lock detection |

These commands map to specific keyboard hook filters in LDB.dll:

| Key Combination | Hook Handler | RLDB Command |
|----------------|-------------|--------------|
| `PrintScreen` | `rldbprt` | Block VK_SNAPSHOT |
| `Alt+Tab` | `rldbfocus=1` | Block alt-tab sequence |
| `Ctrl+V` | `rldbpl` | Block paste |
| `Win+D` | `rldbfocus=2` | Block show desktop |
| `Win+L` | `rldbsl` | Block lock screen |
| `Ctrl+Shift+Esc` | `rldbfocus` | Block task manager |

---

## 4. Quiz State Commands

| Command | Parameters | Purpose |
|---------|-----------|---------|
| `rldbqn` | `=0/1` | Set/clear quiz notification active flag |
| `rldbdetect` | — | Trigger all detection checks (quiz start) |

### Quiz Lifecycle

```
1. User navigates to exam URL (e.g., processattempt.php)
2. LDB.dll detects URL → triggers CLDBDoSomeStuff
3. rldbqn=1 → quiz_active flag set
4. All detection checks run (rldbvm, rldbkh, rldbfocus, etc.)
5. rldbdetect → full security scan
6. LOCKDOWN flag set → keyboard hooks activated
7. PROCTORING flag set if webcam enabled
8. ... exam in progress ...
9. EXIT password check → rldbqn=0 → quiz_active cleared
10. All flags cleared → hooks removed
```

---

## 5. Driver-Level Commands

These commands are sent directly to the kernel driver via the filter communication port, bypassing the URL-based RLDB protocol:

| Driver Command | RLDB Equivalent | Purpose |
|---------------|-----------------|---------|
| `CMD_QUIZ_ACTIVE` | `rldbqn` | Set quiz active state in kernel |
| `CMD_SET_HOOKS` | `rldbkh` | Enable/disable hooks at driver level |
| `CMD_BLOCK_INPUT` | `rldbprt`, `rldbpl` | Block specific input types |
| `CMD_ADD_BLOCKLIST` | `rldbbl` | Add processes to kernel blocklist |
| `CMD_EXAM_URL` | — | Register exam URL patterns in kernel |

---

## 6. Conditional Flag Tests in CLDBDoSomeStuff

The URL handler tests input value against these condition flags:

| Flag Value | Action String Offset | Purpose |
|-----------|---------------------|---------|
| `0x800000` | LDB+0x15D0 | Exam start / full lockdown |
| `0x400000` | LDB+0x15D0 | Exam start (alternative) |
| `0x20000` | LDB+0x1670 | Proctoring mode |
| `0x10000` | LDB+0x13D0 | Exit request |
| `0x4000` | LDB+0x1300 | URL/navigation event |
| Default | LDB+0x1760 | Unknown handler |

Each action string is pushed as parameter to `PUSH 13; CALL [IAT]` — the integer `13` is the action type identifier, and the string at the computed offset contains command data (potentially RLDB command names or serialized data).

---

## 7. The IAT Call Mechanism

All four exports use the same IAT-based dispatcher:

```
PUSH 13; CALL [IAT]   ; Action dispatcher with type 13
PUSH  7; CALL [IAT]   ; EXIT dispatcher with type 7
```

The IAT function resolves to an internal dispatcher that interprets:
- The `PUSH` value as an action type code
- The action string offset as the command data
- Return value determines flag state

Bypass: NOP the `PUSH imm; CALL [IAT]` sequences (5 bytes total: `6A xx FF 15 xx xx xx xx` → `90 90 90 90 90`).
