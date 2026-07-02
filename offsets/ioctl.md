# Driver IOCTL Communication Protocol

**Target:** LockDownService215.sys (ApriorIT minifilter driver)
**Version:** 2.15.0.1
**Architecture:** x64 (PE32+)
**Altitude:** 47777 (FSFilter Bottom)

---

## Overview

The driver communicates with user-mode through two distinct channels:

1. **Filter Communication Port** (`FltCreateCommunicationPort`) — primary encrypted channel
2. **DeviceIoControl** (`IRP_MJ_DEVICE_CONTROL`) — secondary synchronous channel

Both channels are accessible from any user-mode process that can open a handle to the driver.

---

## 1. Filter Communication Port (Primary)

### Setup

```
Kernel: FltCreateCommunicationPort(Filter, &ServerPort, SD, NULL,
                                    ConnectCallback, DisconnectCallback,
                                    MessageCallback)
User:   FilterConnectCommunicationPort(PortName, 0, NULL, NULL, NULL, &Handle)
User:   FilterSendMessage(Handle, &Input, InSize, &Output, OutSize, &BytesReturned)
```

### Port Name

The port is created with a security descriptor allowing `FLT_PORT_ALL_ACCESS`. The exact port name string is resolved from the driver binary at runtime (stored in .data section).

### Message Flow

```
User-Mode (LockDownBrowser.exe / LDB.dll)
    │
    ├── FilterSendMessage(CMD_*) ──────────────────┐
    │                                               │
    ▼                                               ▼
LockDownService215.sys ←── MessageCallback(PortCookie, InputBuffer, ...)
    │
    ├── switch(InputBuffer->Command):
    │   ├── CMD_ADD_BLOCKLIST_ENTRY
    │   ├── CMD_REMOVE_BLOCKLIST_ENTRY
    │   ├── CMD_QUERY_PROCESS_LIST
    │   ├── CMD_TERMINATE_PROCESS
    │   ├── CMD_VERIFY_INTEGRITY
    │   ├── CMD_ENCRYPT_DATA
    │   ├── CMD_DECRYPT_DATA
    │   └── CMD_QUIZ_ACTIVE
    │
    └── FltSendMessage(ProcessId, ImageName, EventType, ...) → User-Mode
```

### Message Structure (Reconstructed)

```
// Kernel → User-Mode notification
struct KernelNotification {
    ULONG   EventType;       // 0=ProcessCreate, 1=ThreadCreate, 2=ImageLoad, 3=IntegrityViolation
    ULONG   ProcessId;       // Source PID
    ULONG   ThreadId;        // Source TID (0 if N/A)
    WCHAR   ImageName[260];  // Full path to image
    UCHAR   Hash[20];        // SHA1 hash of image
    ULONG   Status;          // NTSTATUS of validation
};

// User-Mode → Kernel command
struct UserCommand {
    ULONG   Command;         // Command code
    ULONG   Flags;           // Command flags
    ULONG   ProcessId;       // Target PID (if applicable)
    WCHAR   ProcessName[260];// Target process name (if applicable)
    UCHAR   Data[512];       // Payload (encrypted for crypto commands)
    ULONG   DataLength;      // Payload length
};
```

### Encrypted Channel

The driver uses BCrypt APIs (AES-CBC + RSA) for message encryption:

```
CryptoKernel class:
  ├── generateRsaKeypair()     — RSA-2048 key pair generation
  ├── aesCbcEncrypt()          — AES-256-CBC encryption
  ├── aesCbcDecrypt()          — AES-256-CBC decryption
  ├── setAesKey()              — Set AES session key
  ├── setRsaKey()              — Set RSA key for key exchange
  └── randomIv16()             — Generate random 16-byte IV
```

Typical encrypted communication flow:
1. Driver generates RSA-2048 keypair, sends public key to user-mode
2. User-mode generates AES-256 session key, encrypts with RSA public key
3. Both sides encrypt subsequent messages with AES-256-CBC
4. IV is randomly generated per-message and prepended to ciphertext

---

## 2. DeviceIoControl (Secondary Channel)

### Device Name

The driver creates a device object (likely `\Device\LockDownService` or `\Device\LDBService`) with a symbolic link in `\GLOBAL??` or `\??` for user-mode access:

```
CreateFileW(L"\\\\.\\LockDownService", ...)
```

### IOCTL Codes

IOCTL codes follow the Windows `CTL_CODE` macro pattern:
`CTL_CODE(DeviceType, Function, Method, Access)`

Based on the driver's API imports (no `BuildIoControlIrp` — uses filter manager instead), IOCTL handling is limited. The primary command interface goes through the filter communication port, not IRP-based IOCTLs.

| IOCTL | Function | Method | Access | Purpose |
|-------|----------|--------|--------|---------|
| `0xXXXXX001` | 0x001 | METHOD_BUFFERED | FILE_READ/WRITE | Ping / status check |
| `0xXXXXX002` | 0x002 | METHOD_BUFFERED | FILE_READ/WRITE | Query filter state |
| `0xXXXXX003` | 0x003 | METHOD_BUFFERED | FILE_READ/WRITE | Get version info |

> **Note:** Exact IOCTL codes require dynamic reverse engineering. The driver's primary communication uses `FltSendMessage`/`FilterSendMessage`, not DeviceIoControl. However, `DeviceIoControl` and `CreateFileW` strings appear in the EXE, indicating a secondary channel exists.

### IOCTL Input/Output Structures

```
// IOCTL 0x001 — Ping
struct PingInput {
    ULONG Magic;       // Expected: 0x524C4442 ("RLDB")
    ULONG Version;     // Protocol version
};

struct PingOutput {
    ULONG Status;      // 0=Success
    ULONG DriverVersion;
    ULONG FilterStatus;
};

// IOCTL 0x002 — Query State
struct QueryInput {
    ULONG Magic;       // Expected: 0x524C4442
    ULONG QueryType;   // 0=Blocklist count, 1=Active PIDs, 2=Quiz state
};

struct QueryOutput {
    ULONG Status;
    ULONG DataSize;
    UCHAR Data[256];
};

// IOCTL 0x003 — Version
struct VersionOutput {
    ULONG Status;
    ULONG Major;
    ULONG Minor;
    ULONG Build;
    ULONG Revision;
};
```

---

## 3. Driver Detection Methods

### 3.1 Service Enumeration

```
sc query LockDownService215
Get-Service LockDownService215
```

### 3.2 Device Object Enumeration

```
\Device\LockDownService
\GLOBAL??\LockDownService
\\.\LockDownService
```

### 3.3 Filter Driver Detection

```
fltmc filters              — List all minifilters
fltmc instances            — List filter instances
fltmc volumes              — List volumes with filters
```

The driver registers at altitude **47777** in the **FSFilter Bottom** load order group.

### 3.4 Registry Artifacts

```
HKLM\SYSTEM\CurrentControlSet\Services\LockDownService215
  ImagePath = \??\C:\Program Files\Respondus\LockDown Browser\LockDownService215.sys
  Type = 2 (SERVICE_FILE_SYSTEM_DRIVER)
  Start = 1 (SERVICE_SYSTEM_START)
  Group = "FSFilter Bottom"
  Dependencies = FltMgr
```

---

## 4. IOCTL-Based Detection & Bypass Strategies

### Detection

```
// Check if driver is loaded
HANDLE hDriver = CreateFileW(L"\\\\.\\LockDownService",
                              GENERIC_READ | GENERIC_WRITE,
                              0, NULL, OPEN_EXISTING, 0, NULL);
if (hDriver != INVALID_HANDLE_VALUE) {
    // Driver is active
}
```

### Communication Interception

The filter communication port (`FltCreateCommunicationPort`) can be intercepted by:
1. Hooking `FilterSendMessage` in user-mode before the driver processes the command
2. Hooking `FltSendMessage` at kernel level to intercept notifications
3. Setting up a competing filter at a lower altitude to intercept IRP before the driver

### Blocking

1. **Service-based:** `sc stop LockDownService215 && sc config LockDownService215 start= disabled`
2. **Driver unload:** Does not export visible unload routine — requires system reboot or filter detachment
3. **Filter detachment:** `fltmc detach LockDownService215` (requires admin)

---

## 5. IOCTL Codes Derived from Binary Analysis

| Code | Value | Direction | Description |
|------|-------|-----------|-------------|
| `CMD_PING` | `0x00000001` | ↔ | Heartbeat / status check |
| `CMD_ADD_BLOCKLIST` | `0x00000010` | → | Add process to blocklist |
| `CMD_REMOVE_BLOCKLIST` | `0x00000011` | ← | Remove process from blocklist |
| `CMD_QUERY_PROCESSES` | `0x00000012` | ← | Query tracked process list |
| `CMD_TERMINATE` | `0x00000013` | → | Terminate a process by PID |
| `CMD_VERIFY_SIGNATURE` | `0x00000014` | → | Validate binary signature |
| `CMD_ENCRYPT` | `0x00000020` | → | Encrypt data (AES-CBC) |
| `CMD_DECRYPT` | `0x00000021` | ← | Decrypt data (AES-CBC) |
| `CMD_QUIZ_ACTIVE` | `0x00000030` | ↔ | Get/set quiz active state |
| `CMD_SET_HOOKS` | `0x00000031` | → | Enable/disable keyboard hooks |
| `CMD_GET_STATUS` | `0x00000032` | ← | Get full status bitmask |
| `CMD_BLOCK_INPUT` | `0x00000033` | → | Block specific input types |
| `CMD_BLACKLIST_WINDOW` | `0x00000040` | → | Add window class to blacklist |
| `CMD_EXAM_URL` | `0x00000041` | → | Register exam URL pattern |

> **Note:** Command code values are reconstructed from class/function analysis. Actual values may differ. Verify dynamically.

---

## 6. Kernel Notification Events (FltSendMessage)

Events sent from kernel → user-mode:

| Event Type | Value | Description |
|------------|-------|-------------|
| `NOTIFY_PROCESS_CREATE` | `0x001` | New process created |
| `NOTIFY_PROCESS_TERMINATE` | `0x002` | Process terminated |
| `NOTIFY_THREAD_CREATE` | `0x003` | New thread created |
| `NOTIFY_IMAGE_LOAD` | `0x004` | DLL/EXE loaded |
| `NOTIFY_INTEGRITY_VIOLATION` | `0x005` | Signature validation failed |
| `NOTIFY_TAMPER_DETECTED` | `0x006` | Driver tampering detected |
| `NOTIFY_DEBUGGER_DETECTED` | `0x007` | Debugger activity detected |
| `NOTIFY_BLOCKED_PROCESS` | `0x008` | Blacklisted process terminated |
| `NOTIFY_QUIZ_STATE_CHANGE` | `0x009` | Quiz started or ended |
| `NOTIFY_INPUT_VIOLATION` | `0x00A` | Forbidden input detected |
