# Respondus LockDown Browser — Offsets, Signatures & Analysis

Latest offsets, IOCTL protocol, RLDB commands, and analysis scripts. Updated with every version.

**Latest versions:**
- EXE: `2.1.5.00` (Chrome/142.0.7444.135)
- DLL: `23.10.31.1` (LDB.dll)
- Driver: `2.15.0.1` (LockDownService215.sys — by ApriorIT)

**Updated:** 2026-07-02

---

## What's Inside

### Offsets (`offsets/`)

| File | Description |
| :--- | :--- |
| `offsets.hpp` | C++ header with all offsets, sigscans, IOCTL codes, RLDB codes, quiz_active, driver analysis constants |
| `exports.md` | DLL export function map (both v2.1.3.09 & v2.1.5.00) |
| `process_blacklist.hpp` | 3020+ blacklisted process entries in UTF-16LE |
| `ioctl.md` | Driver IOCTL communication protocol specification |
| `rldb_commands.md` | RLDB URL command reference (25+ commands documented) |
| `quiz_active.md` | Quiz active flag analysis (user-mode and kernel-mode) |
---

## Target: LockDownBrowser.dll (LDB.dll)

| Target | Type |
| :--- | :--- |
| `.cldb` flag setters (LOCKDOWN/PROCTORING/EXIT) | Static RVA + Sigscan |
| **quiz_active flag** (new) | Static RVA near `.cldb` + Sigscan |
| DLL exports (4 functions) | Static RVA + Sigscan |
| SetWindowsHookEx call sites (21 total) | Static RVA + Sigscan |
| Keyboard hook callback procedure | Static RVA |
| Action strings and dispatcher codes | Static RVA |
| **RLDB command handlers** (new) | URL parameter → condition flag mapping |

### Logic Patterns

* **Find `.cldb` section:** 
  `Walk PE sections` → `match name .cldb` → `get VirtualAddress`
* **Find flag setters:** 
  `Scan .text for 89 0D / 89 3D / C7 05` → `resolve disp32` → `check if target falls in .cldb range`
* **Find quiz_active:** 
  `Scan .text for C7 05 [disp32] 01/00` → `resolve disp32` → `check if target near .cldb end`
* **Find exports:** 
  `Parse PE export directory` → `match ?CLDBDo prefix string`
* **Find hook call sites:** 
  `Scan .text for FF 15` → `resolve IAT` → `check if user32!SetWindowsHookEx`

---

## Target: LockDownService215.sys (Tuff lil ApriorIT driver)

| Target | Type |
| :--- | :--- |
| **Filter Communication Port** | IOCTL codes + message protocol |
| **DeviceIoControl commands** | Reconstructed command codes |
| **Kernel notifications** | Event types (process/thread/image/quiz) |
| **Crypto subsystem** | BCrypt AES-256-CBC + RSA-2048 |
| **Process/thread/image callbacks** | PsSetCreateProcessNotifyRoutineEx, etc. |
| **Code integrity** | CiValidateFileObject signature validation |
| **KDMapper detection** | Limited, heard people say "kdmapper is dtc"; it isnt |

See `ioctl.md` for complete protocol documentation.

---

## Target: LockDownBrowser.exe (Main EXE)

| Target | Type |
| :--- | :--- |
| Window class blacklist | Static strings |
| Process blacklist (3020+ entries) | Heap-allocated, UTF-16LE strings |
| Registry flags (`active`, `tvc`, `tvd`) | `HKCU\SOFTWARE\Respondus\` |
| Exam URL triggers | Obfuscated at rest |
| **RLDB command strings** | Embedded in `.rdata` |
| Driver communication | `CreateFileW(\\.\LockDownService)` + `DeviceIoControl` |

---

## New in This Update

### 1. IOCTL Communication Protocol (`ioctl.md`)
Complete specification of the driver communication architecture:
- Filter Communication Port (`FltCreateCommunicationPort`) — primary encrypted channel
- DeviceIoControl (`\\.\LockDownService`) — secondary channel
- 14+ command codes reconstructed from binary analysis
- 10 kernel notification event types
- Crypto subsystem (AES-256-CBC + RSA-2048)

### 2. Quiz Active Flag (`quiz_active.md`)
The master gating flag that controls all monitoring:
- User-mode location (near `.cldb` section in LDB.dll)
- Kernel-mode tracking (via `CMD_QUIZ_ACTIVE = 0x00000030`)
- Registry persistence (`HKCU\...\active`)
- 4 state values (INACTIVE, ACTIVE, PROCTORING, LOCKED)
- Sigscan patterns for dynamic discovery

### 3. RLDB Commands (`rldb_commands.md`)
Complete command reference (25+ commands):
- Security/detection commands (rldbdetect, rldbvm, rldbkh, rldbfocus, etc.)
- Quiz state commands (rldbqn)
- Input control commands (rldbprt, rldbpl, rldbsp, etc.)
- Process/application control commands (rldbbl, rldbwl, etc.)
- Condition flag → action string mapping
- IAT dispatcher mechanism (PUSH 13/PUSH 7)

### 4. Analysis Scripts (`analysis/`)
- **driver_analyzer.ps1** — Interactive driver analysis (status, registry, filter manager, device handles, string analysis, vulnerability assessment)
- **offset_scanner.py** — Automated PE scanning for all offset types with JSON output and patch generation
- **rldb_cmd_monitor.ps1** — Real-time monitoring (process, driver, hooks, registry, blacklist)

---

## Version Differences

| Component | v2.1.3.09 (32-bit) | v2.1.5.00 (x64) |
|-----------|-------------------|-----------------|
| LDB.dll | 32-bit | x64 (PE32+) |
| CLDBDoSomeOtherStuffs | `+0x10B0` | `+0x10E0` |
| CLDBDoSomeStuff | `+0x10E0` | `+0x1110` |
| CLDBDoYetMoreStuff | `+0x12A0` | `+0x1330` |
| Driver version | — | `2.15.0.1` |
| Chrome base | 129 | 142 |

---

## Credits

If you repost or use this, please credit one of the following:

* **GitHub:** [arcticdev00](https://github.com/arcticdev00)
* **Discord:** [Join the server](https://discord.gg/GyBxnYZsXN)
