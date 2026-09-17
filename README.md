# Respondus LockDown Browser — Offsets, Signatures & Analysis

Latest offsets, IOCTL protocol, RLDB commands, and analysis. Updated with every version.

**Latest versions:**
- EXE: `2.1.6.00` (Chrome/150.0.0.0)
- DLL: `23.10.31.1` (LDB.dll)
- Driver: `2.16.0.0` (LockDownService215.sys — by ApriorIT)

**Updated:** 2026-09-16

---

## What's Inside

### Offsets (`offsets/`)

| File | Description |
| :--- | :--- |
| `offsets.hpp` | C++ header with all offsets, sigscans, IOCTL codes, RLDB codes, quiz_active, driver analysis constants |
| `exports.md` | DLL export function map |
| `process_blacklist.hpp` | 3020+ blacklisted process entries in UTF-16LE |
| `ioctl.md` | Driver communication protocol specification (filter port opcodes read from the dispatcher) |
| `rldb_commands.md` | RLDB URL command reference (57 commands documented) |
| `quiz_active.md` | Quiz active flag analysis (user-mode and kernel-mode) |

---

## Target: LockDownBrowser.dll (LDB.dll)

| Target | Type |
| :--- | :--- |
| `.cldb` flag slots (LOCKDOWN/PROCTORING/EXIT) | Static RVA + 32 verified x64 access sites |
| DLL exports (4 functions, ordinals 1-4) | Static RVA + Sigscan |
| Keyboard hook callback procedures | Static RVA |
| **VK_F12 block (removed in 2.1.6.0.0)** | Byte pattern `83 F9 7B` — 0 occurrences |
| Action strings and dispatcher codes | Static RVA |
| **RLDB command handlers** | URL parameter → condition flag mapping |

### Logic Patterns

* **Find `.cldb` section:** 
  `Walk PE sections` → `match name .cldb` → `get VirtualAddress` (expect `0x1C000` on x64)
* **Find flag sites:** 
  `Scan .text for RIP-relative 48 89 / 48 8B / 48 83 3D / 48 39` → `resolve disp32 (target = insn_addr + insn_len + disp)` → `check if target falls in .cldb range`
* **Find quiz_active:** 
  `Scan .text for C7 05 [disp32] 01/00` → `resolve disp32` → `check if target in .data`
* **Find exports:** 
  `Parse PE export directory` → `match ?CLDBDo prefix string`
* **Find hook call sites:** 
  `Scan .text for FF 15` → `resolve IAT` → `check if user32!SetWindowsHookExA`

---

## Target: LockDownService215.sys (Tuff lil ApriorIT driver)

| Target | Type |
| :--- | :--- |
| **Filter Communication Port** (`\ApDriverPort`) | Opcodes read from the dispatcher + reply framing |
| **Connection gate** | Strict PID allowlist, forced disconnect on mismatch |
| **Kernel notifications** | PsSetCreateProcessNotifyRoutineEx, PsSetCreateThreadNotifyRoutine, PsSetLoadImageNotifyRoutine |
| **Crypto subsystem** | BCrypt AES-256-CBC + RSA-2048 |
| **Code integrity** | CiValidateFileObject signature validation |
| **Overlay detection** | DwmImageResolver, BrowserImageResolver |
| **DriverLogger (new)** | Kernel-side logging to `C:\Users\Public\Documents\` |
| **Whole-process fileless scan (new)** | Opcode `0x14` — batch thread verification |

See `ioctl.md` for complete protocol documentation.

---

## Target: LockDownBrowser.exe (Main EXE)

| Target | Type |
| :--- | :--- |
| Window class blacklist | Static strings |
| Process blacklist (3020+ entries) | Heap-allocated, UTF-16LE strings |
| Registry flags (`active`, `tvc`, `tvd`) | `HKCU\SOFTWARE\Respondus\` |
| **RLDB command strings** | Embedded in `.rdata` |
| **AKD detection subsystem (new)** | Encrypted driver channel via `akd_mediator` |
| **CheckDetours hook detection** | JMP rel32 (`0xE9`) test confirmed by emulation |
| **Client-side driver install (new)** | `FilterLoad` + `SetupAPI` |
| Driver communication | `CreateFileW` + `DeviceIoControl`, filtered via `fltlib` |

---

## New in This Update

### 1. DriverLogger (`ioctl.md` §11)
Kernel-side logging subsystem:
- Writes timestamped lines to `\??\C:\Users\Public\Documents\<YYYY-MM-DD>.log`
- Six new functions; source of all 12 new driver imports
- Filename is date-derived with numeric-suffix rotation
- Line prefix `[YYYY-MM-DD HH:MM:SS]`

### 2. Whole-Process Fileless Scan (opcode `0x14`)
User mode supplies a PID plus a thread-ID array and gets one verdict:
- Per thread: `ZwQueryInformationThread(Win32StartAddress)` → `ZwQueryVirtualMemory(MemoryBasicInformation)`
- If the start address does not resolve to a file-backed image section → verdict 3 (fileless/injected code)
- Per-thread state cache at `+0xD0` avoids re-probing
- Driven by the EXE's AKD subsystem for both the browser process and DWM

### 3. AKD Detection Subsystem (EXE)
New usermode detection layer talking to the driver over an encrypted filter-port channel:
- `GlobalSecurityObject::AKD_DetectReflectionLoad`
- `AKD_DetectThreadHacks` (`m_browser` / `m_dwm` flags)
- `akd_mediator.connect()` + `dllMonitor->start()`
- Includes a DWM integrity check with an explicit refusal path

### 4. Three New Port Opcodes (`ioctl.md`)
- `0x11` — version query (reply `0x12` + two version qwords)
- `0x13` — state flag set (writes the state byte at `ApDriver+0x91`)
- `0x14` — whole-process fileless scan (reply `0x15` + verdict)

### 5. VK_F12 No Longer Blocked (HookDLL)
The three `WH_KEYBOARD_LL` hook procedures no longer contain the `cmp ecx, 0x7b` (VK_F12) arm that swallowed F12 key-down and key-up globally. Byte pattern `83 F9 7B` went from 3 occurrences to 0. Whether the block was relocated (CEF accelerator path / obfuscated EXE code) or dropped entirely needs a runtime test.

### 6. Client-Side Driver Installation (EXE)
Newly imports `FLTLIB.DLL: FilterLoad`, four `SETUPAPI.dll` calls, `KERNEL32: VirtualQueryEx`, plus a `SeLoadDriverPrivilege` string.

---

## Credits

If you repost or use this, please credit one of the following:

* **GitHub:** [arcticdev00](https://github.com/arcticdev00)
* **Discord:** [Join the server](https://discord.gg/GyBxnYZsXN)
