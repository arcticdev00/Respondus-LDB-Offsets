# Driver Communication Protocol

**Target:** LockDownService215.sys (ApriorIT minifilter driver)
**Version:** 2.16.0.0
**Architecture:** x64 (PE32+)
**Altitude:** 47777 (FSFilter Bottom)
**Generated:** 2026-09-16

---

## Overview

The driver communicates with user-mode through a **Filter Communication Port** (`FltCreateCommunicationPort`). Everything labelled *observed* below was read out of the decompiled message dispatcher `FUN_1400015c0`. Everything labelled *inferred* is structure that has been reasoned about but not read.

> **Note:** the minifilter registers **no file-operation callbacks** (`OperationRegistration = NULL`). It is a minifilter only to own a filter handle and a communication port; it does not sit in the filesystem I/O path.

---

## 1. Filter Communication Port (Primary)

### Setup

```
Kernel: FltCreateCommunicationPort(filter, &port, SD, NULL,
                                    ConnectCallback, DisconnectCallback, MessageCallback)
Port:   L"\ApDriverPort"   (UTF-16LE, verified in the image)
```

Handlers: `CommunicationPortBase::initialize`, `CommunicationPortBase::sendMessage` (`FltSendMessage`), `disconnectNotifyCallback`, `BrowserCommunicationPort::onConnect`, `BrowserCommunicationPort::onDisconnect`.

The dispatcher for messages arriving at the port is `FUN_1400015c0` (2397 bytes).

### Connection Gate (observed, `BrowserCommunicationPort::onConnect`)

```
pid = PsGetCurrentProcessId()
if (g_expectedBrowserPid == 0)                     return 0xC0000184  STATUS_INVALID_DEVICE_STATE
if (!pidMatches(g_expectedBrowserPid, pid)) {      return 0xC0000022  STATUS_ACCESS_DENIED
                                                   + forced disconnect }
else {  reset port state; store pid at +0x11; clear the byte at +0x91;
        log "Detect new browser PID %d";           return 0 STATUS_SUCCESS }
```

> **Note:** only the process whose PID the driver has resolved as the browser may attach. A PID mismatch is not merely refused — the connection is torn down through the port's vtable (`__guard_dispatch_icall`, i.e. CFG is enabled).

### Message Flow

```
User-Mode (LockDownBrowser.exe)
    |
    |  input buffer:  param_2[0] = opcode, remaining words opcode-specific
    v
LockDownService215.sys <--- MessageCallback(param_1..param_6)
    |
    |-- KeGetCurrentIrql() > 2                    -> 0xC0000184
    |-- param_6 == NULL                           -> 0xC000000D, *param_6 = 0
    |-- param_3 < 4  or  param_2 == NULL          -> 0xC0000206
    |-- switch (param_2[0]) -> opcode table below
    |
    `-- reply written to param_4, count to *param_6
```

---

## 2. Request Layout

| Parameter | Meaning |
| :--- | :--- |
| `param_2` | pointer to the input buffer (`uint*`) |
| `param_3` | input length in bytes |
| `param_4` | pointer to the output buffer |
| `param_5` | output buffer capacity |
| `param_6` | pointer to receive the bytes written |

---

## 3. Opcode Table (observed)

`reply` is the first dword written to the output buffer. `enc` marks opcodes that are encryption-gated.

| Opcode | Handled | Reply | Observed Behaviour |
| :--- | :--- | :--- | :--- |
| `0x00` | yes | — | passes `(ApDriver+0x98, param_4, param_5)` to `FUN_140005b2c` — a BCrypt-backed operation on the output buffer directly |
| `0x01` | yes | — | `FUN_140005fe8(ApDriver+0x98, {param_2+2, param_2[1_]})` — BCrypt operation on caller data |
| `0x02` | yes | — | `FUN_140005de0(ApDriver+0x98, {param_2+1, 0x100})`; on success sets the **encryption-enabled byte at `ApDriver+0x90`** |
| `0x03` | yes | — | **enc only** (`if (!cVar2) return 0xC0000010`). Allocates `param_2[0x41] + 0x108`, decrypts into it via `FUN_140005754`, then dispatches through the vtable at `__guard_dispatch_icall(param_1, buf+0x21, *(u32*)(buf+0x104), …)` |
| `0x04` | yes | `5` | requires `DAT_14000f080`; if the AVL table at `+0xd0` is empty, calls `FUN_140008738`; replies count at `+4`, then a per-entry array of `0xf0c` bytes |
| `0x06` | yes | `7` | requires `DAT_14000f088`; replies count at `+4`, then a per-entry array of `0x710` bytes |
| `0x08` | yes | `9` | requires `DAT_14000f088`; replies a dword derived from `[obj+0x318]` at `+4`, then a per-entry array of `0x710` bytes |
| `0x0c` | yes | `0xE` | requires `DAT_14000f080`; replies count at `+4`, then `4`-byte entries |
| `0x0d` | yes | `0xF` | requires `DAT_14000f080`; replies count at `+4`, then `4`-byte entries |
| `0x0f` | yes | `0x10` | requires `DAT_14000f090`; replies `FUN_140009140(mon, 0)` at `+4` and `FUN_140009140(mon, 1)` at `+8` |
| `0x11` | yes | `0x12` | version query — see §5 |
| `0x13` | yes | none | state flag set — see §6 |
| `0x14` | yes | `0x15` | whole-process fileless scan — see §4 |
| `0x05`, `0x07` | no | — | falls through to `return 0` |
| `0x09`–`0x0b`, `0x0e`, `0x10`, `0x12`, `0x15+` | no | — | falls through to `return 0` |

The `0x04` / `0x06` / `0x0c` / `0x0d` opcodes are **enumeration** requests: they report a count and then a fixed-stride array of records. The strides (`0xf0c` and `0x710` bytes) are consistent and are the natural starting point for mapping the tracked-object tables. *Which* table each one enumerates is not established.

> **Protocol quirk:** an **unrecognised opcode returns `STATUS_SUCCESS` (0) with no output written.** Only explicit failure paths return an error. A caller cannot distinguish "opcode not supported" from "opcode succeeded silently" by status alone.

---

## 4. Opcode `0x14` — Whole-Process Fileless Scan

User mode hands over a process plus its entire thread list and gets a single verdict.

### Request

```c
struct WholeProcessScan {
    uint32_t Opcode;      /* +0x00  = 0x14 */
    uint32_t ProcessId;   /* +0x04 */
    uint32_t ThreadCount; /* +0x08 */
    uint32_t ThreadIds[]; /* +0x0C  ThreadCount entries */
};
```

### Validation (observed)

```c
if (param_3 < 0x10)                          return 0xC0000206;
n = (param_2[2] < 2) ? 0 : param_2[2] - 1;
if (param_3 < n * 4 + 0x10)                  return 0xC0000206;   /* == 0x0C + ThreadCount*4 */
if (DAT_14000f090 == 0)                      return 0xC0000184;
```

### Reply

```c
struct WholeProcessScanReply {
    uint32_t Subtype;  /* +0x00 = 0x15 */
    uint32_t Verdict;  /* +0x04 = FUN_140008fe0(...) */
};
```

### What the Verdict Means

`FUN_140008fe0` copies the thread IDs into a `kf::vector` (pool tag `'C++n'`) and calls the per-thread probe for each one, returning early if the probe returns `-1` (error) or `3` (fileless). The probe, `ThreadMonitor::verifyFilelessExecution`, does:

```
PsLookupProcessByProcessId(pid)                        -> EPROCESS
ObOpenObjectByPointer(EPROCESS, PsProcessType, 0x400)  -> process handle
PsLookupThreadByThreadId(tid)                          -> ETHREAD
ObOpenObjectByPointer(ETHREAD, PsThreadType, 0x40)     -> thread handle
ZwQueryInformationThread(thread, ThreadQuerySetWin32StartAddress, ...)
ZwQueryVirtualMemory(process, start, MemoryBasicInformation, ...)
     == 0xC0000141 (STATUS_INVALID_ADDRESS) or 0xC0000098
     -> verdict 3 : code with no file behind it
```

If the thread's start address does not resolve to a file-backed image section (no `ImageFileObject` behind the memory region), the thread is running injected or reflected code.

A per-thread state cache at `+0xd0` stops the same thread being re-probed. The system information query used for module enumeration is retried: `"ZwQuerySystemInformation() failed after 10 retries | status = 0x%08X"`.

---

## 5. Opcode `0x11` — Version Query (observed)

```c
ApDriver = FUN_140002b90();
v1 = *(uint64_t *)(ApDriver + 0x700);
v2 = *(uint64_t *)(ApDriver + 0x708);
/* reply: dword 0x12, then v1, then v2 */
```

The two qwords are populated from the image's `VS_VERSION_INFO` at init, so this simply reports the driver's own version — `2.16.0.0` for this build. It is informational.

---

## 6. Opcode `0x13` — State Flag Set (observed)

```c
FltAcquireResourceExclusive(ApDriver + 0x1b);
*(char *)(ApDriver + 0x91) = (char)param_2[1];
FltReleaseResource(ApDriver + 0x1b);
return STATUS_SUCCESS;                 /* no reply written */
```

Writes the state byte at `ApDriver+0x91` — the same byte `onConnect` clears. It is not a detection opcode.

---

## 7. Encrypted Replies and the `0x108` Prefix (observed)

`cVar2 = (char)*(ApDriver + 0x90)` — the encryption-enabled byte, set by opcode `0x02`.

When encryption is **off**, replies are written at `param_4 + 0` and the reported size is the plaintext size.

When encryption is **on**:

```c
FUN_140005cbc(ApDriver+0x98, plaintext_size, &required);   /* size query */
*param_6 = required + 0x108;
/* struct is written at param_4 + 0x108 */
```

So an encrypted reply carries a **`0x108`-byte (264-byte) envelope** before the plaintext structure. The envelope contents were not determined; the offset is taken from the encryption subsystem's size query. A client that assumes the reply starts at offset 0 will misparse every reply on an encrypted port.

Other observed reply-framing details:

* `param_5 < size` → `0xC0000023` (STATUS_BUFFER_TOO_SMALL) — so a caller can probe for the exact size by sending a zero-capacity buffer.
* `param_4 == NULL` → `0xC000000D`.
* `*param_6` is set **before** the capacity check, so the required size is always reported.

### Crypto Subsystem (`CryptoKernel`)

```
CryptoKernel class:
  ├── BCryptGenRandom              — IV generation
  ├── BCryptGenerateSymmetricKey / setAesKey
  ├── BCryptEncrypt / BCryptDecrypt        — AES-CBC
  ├── BCryptGenerateKeyPair / BCryptImportKeyPair / BCryptExportKey / BCryptFinalizeKeyPair  — RSA
  └── BCryptCreateHash / HashData / FinishHash  — SHA-1
```

---

## 8. DeviceIoControl — Not Established

The strings `DeviceIoControl` and `CreateFileW` do appear in the **EXE**, and the minifilter registers no `IRP_MJ_DEVICE_CONTROL` operation callback, so there is no evidence of an IRP-based command interface in the driver. **Treat the existence of a DeviceIoControl command channel as unconfirmed.**

---

## 9. DriverLogger

Six functions:

```
DriverLogger::buildTodaysLogFilePath
DriverLogger::createLogFile
DriverLogger::deleteLogFile
DriverLogger::deleteOldLogFiles
DriverLogger::findNextLogFileSuffix
DriverLogger::log
```

* **Directory is hardcoded** in the `ApDriver` constructor:
  `param_1[0xe3] = L"\??\C:\Users\Public\Documents\";`
* **Filename** is date-derived (`%04hd-%02hd-%02hd`) with a `.log` suffix; `findNextLogFileSuffix` appends a numeric suffix when today's file already exists.
* **Line prefix** is a local-time stamp: `[%04hd-%02hd-%02hd %02hd:%02hd:%02hd] ` (`ExSystemTimeToLocalTime` + `RtlTimeToTimeFields`), formatted with `_vsnwprintf_s`.
* `createLogFile` uses `ZwCreateFile(GENERIC_WRITE, FILE_SHARE_READ, FILE_OVERWRITE_IF, 0x20, OA.Attributes = 0x240)`, then takes `FltAcquireResourceExclusive` on the logger's ERESOURCE, closes any previous handle, stores the new handle at `+0x10` and resets a byte counter at `+0x80`.
* Rotation uses `ZwQueryDirectoryFile` + `ZwDeleteFile`.
* The logger object sits at `ApDriver+0xe2` (size `0x88`) with its own ERESOURCE, and its init is the **first** step of `ApDriver::initialize` — logging is enabled before the filter registers.

Imports added by this subsystem: `ZwCreateFile`, `ZwWriteFile`, `ZwDeleteFile`, `ZwQueryDirectoryFile`, `ExSystemTimeToLocalTime`, `RtlTimeToTimeFields`, `RtlAppendUnicodeToString`, `RtlPrefixUnicodeString`, `RtlUnicodeStringToInteger`, `_vsnwprintf_s`, `__chkstk`, `FltAcquireResourceShared`.

> **Note:** the driver writes structured telemetry into `C:\Users\Public\Documents\`, a directory any interactive user can also read and write. That is both a forensic artefact and an interaction surface.

---

## 10. Locating the Driver on a Live System

```
sc query LockDownService215
fltmc filters
fltmc instances
fltmc volumes
```

Registry:

```
HKLM\SYSTEM\CurrentControlSet\Services\LockDownService215
    ImagePath  = \SystemRoot\System32\drivers\LockDownService215.sys
    Type       = 2     (SERVICE_FILE_SYSTEM_DRIVER)
    Start      = 1     (SERVICE_SYSTEM_START)
    Group      = "FSFilter Bottom"
    DependOnService = FltMgr
```

Values above are read from `Service/x64/LockDownService215.inf`. INF constants: `DriverVer=08/28/2026,2.16.0.0`, `Class=Bottom`, `ClassGuid={21D41938-DAA8-4615-86AE-E37344C18BD8}`, `PnpLockdown=1`, `SupportedFeatures=0xb`, `Instance1.Altitude="47777"`, `Instance1.Flags=0x0` (allow all attachments), service description *"LockDown Browser system integrity and security monitoring service"*.
