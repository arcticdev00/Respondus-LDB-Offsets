# Quiz Active Flag

**Target:** LockDownBrowser.dll + LockDownService215.sys
**Flag Command:** `rldbqn=1` / `rldbqn=0`

---

## Overview

The **quiz_active** flag indicates whether a quiz/exam is currently in progress. It is the master gating flag: when set, all security monitoring is active; when clear, monitoring is relaxed or disabled.

The flag exists in two locations:

1. **User-mode:** Within LDB.dll's `.cldb` shared memory section (or adjacent memory)
2. **Kernel-mode:** Within LockDownService215.sys's internal tracking state

---

## 1. User-Mode Quiz Active Flag (LDB.dll)

### Location

The flag is NOT in the standard `.cldb` section (which only has LOCKDOWN/PROCTORING/EXIT at +0x00/+0x04/+0x08). Based on analysis of `rldbqn=1` behavior:

| Location | Offset (from LDB.dll base) | Size | Description |
|----------|---------------------------|------|-------------|
| `.data` section | ~LDB+0x17010 to LDB+0x17020 | 4 bytes | Active quiz session flag |
| `.data` section | ~LDB+0x17014 | 4 bytes | Quiz ID / session token |
| `.data` section | ~LDB+0x17018 | 4 bytes | Timer / remaining time |

> **Note:** Exact offsets require dynamic verification. The `.cldb` section size is 12 bytes (LDB+0x17000 to LDB+0x1700C). The quiz_active flag is in adjacent memory beyond `.cldb`.

### State Values

| Value | State | Description |
|-------|-------|-------------|
| `0x00000000` | Inactive | No quiz running, monitoring inactive |
| `0x00000001` | Active | Quiz in progress, monitoring active |
| `0x00000002` | Proctoring | Quiz with webcam proctoring active |
| `0xFFFFFFFF` | Locked | Exit password required, cannot dismiss |

### Behavior

When `rldbqn=1`:
1. The `.cldb` LOCKDOWN flag is set (or confirmed set)
2. Keyboard hooks enter full enforcement mode
3. Process blacklist checks run continuously
4. Focus/window switching is blocked
5. PrintScreen, paste, and other forbidden input is blocked

When `rldbqn=0`:
1. The `.cldb` LOCKDOWN flag may be cleared
2. Keyboard hooks may be removed or relaxed
3. Process monitoring may continue (driver-level)
4. Focus/window switching is allowed
5. Input is no longer filtered

### Sigscan Pattern

The quiz_active flag is set via a write to the `.data` section. Patterns to search for:

```
// Setting quiz_active = 1 (MOV DWORD [addr], 1)
C7 05 ?? ?? ?? ?? 01 00 00 00
// Setting quiz_active = 0 (MOV DWORD [addr], 0)
C7 05 ?? ?? ?? ?? 00 00 00 00
// Comparing quiz_active (CMP DWORD [addr], 0)
83 3D ?? ?? ?? ?? 00
```

Search within LDB.dll's `.text` section for these patterns, then resolve the displacement to find the flag address.

---

## 2. Kernel-Mode Quiz Active Flag (Driver)

### Location

The driver maintains internal state in its device extension or a global structure allocated via `ExAllocatePool2`. The quiz_active flag is likely:

```
driver_global + 0x00:  Flags bitmask (bit 0 = quiz_active)
driver_global + 0x04:  Current PID of quiz process
driver_global + 0x08:  Notification flags
```

### Access

The kernel flag is set via `CMD_QUIZ_ACTIVE` (IOCTL code `0x00000030`) through the filter communication port:

```
// User-mode sends:
struct {
    ULONG Command;      // = 0x00000030 (CMD_QUIZ_ACTIVE)
    ULONG QuizActive;   // = 1 (start) or 0 (end)
    ULONG ProcessId;    // = PID of LockDownBrowser.exe (for verification)
} CmdQuizActive;

// Driver stores in internal state, returns:
struct {
    ULONG Status;       // = 0 (success)
    ULONG PreviousState;// = previous quiz_active value
    ULONG CurrentFlags; // = current driver flags
} CmdQuizActiveReply;
```

### Effect on Driver Behavior

When kernel quiz_active is set:
- `PsSetCreateProcessNotifyRoutineEx` callback terminates blacklisted processes immediately
- `PsSetLoadImageNotifyRoutine` callback validates all DLL loads against blocklist
- `PsSetCreateThreadNotifyRoutine` callback rejects suspicious thread creation
- File system filtering is active at maximum level
- User-mode disconnect triggers process termination (anti-tamper)

When kernel quiz_active is clear:
- Process notification callbacks still fire but log only (no termination)
- Image load callbacks validate but don't block
- Thread creation monitoring is relaxed
- User-mode disconnect is allowed

---

## 3. Registry Persistence

The quiz_active state is also reflected in the registry:

```
HKCU\SOFTWARE\Respondus\Respondus LockDown Browser-2
    active = 1          ← quiz_active flag
    tvc    = 0          ← trial validation
    tvd    = 1          ← trial version detected
```

The `active` registry value is set to `1` when a quiz starts and `0` when it ends. This persists across application restarts.

---

## 4. Bypass Strategies

### User-Mode Flag Manipulation

```
// Direct memory write to clear quiz_active
DWORD zero = 0;
WriteProcessMemory(hLDB, LDB_base + 0x17010, &zero, 4, NULL);
```

### Kernel Flag Override via IOCTL

```
// Send CMD_QUIZ_ACTIVE with QuizActive=0
HANDLE hDriver = CreateFileW(L"\\\\.\\LockDownService", ...);
DWORD cmd[] = { 0x00000030, 0, 0 };  // Command, QuizActive=0, PID=0
FilterSendMessage(hDriver, cmd, sizeof(cmd), &reply, sizeof(reply), &ret);
```

### Registry Override

```
// Clear registry flag
Set-ItemProperty -Path "HKCU:\SOFTWARE\Respondus\Respondus LockDown Browser-2" -Name "active" -Value 0
```

> **Warning:** The kernel driver independently tracks quiz state. Registry/user-mode manipulation may not fully disable driver enforcement. The kernel flag (`CMD_QUIZ_ACTIVE`) is the authoritative source.
