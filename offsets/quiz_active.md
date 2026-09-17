# Quiz Active Flag

**Target:** LockDownBrowser.exe + LockDownService215.sys
**Flag Command:** `rldbqn=1` / `rldbxb=1`
**Generated:** 2026-09-16

---

## Overview

The **quiz_active** flag indicates whether a quiz/exam is currently in progress. It is the master gating flag: when set, all security monitoring is active; when clear, monitoring is relaxed or disabled.

Key fact established this revision: `rldbqn=1` is a string in **LockDownBrowser.exe** (`.rdata`, VA `0x140B1CAE0`) and is consumed by an **EXE** function. The HookDLL never sees it. It is parsed and stored in EXE `.data`, not in LDB.dll's `.cldb` shared memory section.

---

## 1. User-Mode Quiz Active Flag (LockDownBrowser.exe)

### The Handler

`rldbqn=1` and `rldbxb=1` are referenced by the **same** function:

```
rldbqn=1  VA 0x140B1CAE0   ref 0x14006DDC5
rldbxb=1  VA 0x140B1CAD0   ref 0x14006DD57
both in function   0x14006BCA0 - 0x14006E360     (9,920 bytes)
```

The two strings sit adjacent in memory (`0x…AD0` and `0x…AE0`) and in the same handler — consistent with one parsing routine.

### Location

The strong candidate is **`LockDownBrowser.exe + 0xCAC708`** (RVA `0xCAC708`, in `.data`):

```asm
14006c2e5  cmp  byte  ptr [rip + 0xc404c4], 0     -> 0x140CAC7B0   ; gate byte
14006c2ee  cmp  esi,  dword ptr [rip + 0xc404cc]  -> 0x140CAC7C0   ; compare to input
14006c360  cmp  dword ptr [rip + 0xc403a1], 0     -> 0x140CAC708   ; already active?
14006c367  je   0x14006c442                                        ; yes -> skip
14006c40a  mov  qword ptr [rip + 0xc403a7], rdi   -> 0x140CAC7B8
14006c437  mov  dword ptr [rip + 0xc40383], edi   -> 0x140CAC7C0
14006c56f  mov  dword ptr [rip + 0xc4015b], esi   -> 0x140CAC6D0
14006c575  mov  dword ptr [rip + 0xc40189], 1     -> 0x140CAC708   ; set active
14006c57f  call 0x14013a840
```

Why this is the best candidate:
- The handler **tests it against 0** then **stores a literal `1`** in the "not already active" path — the textbook *if(!active) active = 1* shape
- It is stored with the exact `C7 05 disp32 01 00 00 00` form that has been the documented sigscan for this flag all along
- It is read from a second, unrelated function (`cmp dword ptr [0x140CAC708], esi` at `0x1401932EB`, in `0x140191EA0`-`0x140193B8A`) — what you expect of a state flag

### Neighbouring State (unidentified)

These sit in `.data` alongside it and are all touched by the same handler:

| Address | RVA | Observed Use |
|---------|-----|--------------|
| `0x140CAC6D0` | `0xCAC6D0` | stored from `esi` (`mov dword [..], esi`) |
| `0x140CAC7B0` | `0xCAC7B0` | byte tested against 0 — a gate |
| `0x140CAC7B8` | `0xCAC7B8` | qword stored from `rdi` |
| `0x140CAC7C0` | `0xCAC7C0` | dword compared to `esi`, then stored from `edi` |

Whether one of these is the "proctoring"/"locked" value is unknown.

> **Note:** this is a candidate, not a confirmation. What would confirm it: a runtime read (set `rldbqn=1`, watch the dword flip 0 → 1) or a decompile of `0x14006bca0` showing the value reaching a "monitoring enabled" decision. Neither has been done.

### Sigscan Pattern

```
// Setting quiz_active = 1 (MOV DWORD [addr], 1)
C7 05 ?? ?? ?? ?? 01 00 00 00
// Setting quiz_active = 0 (MOV DWORD [addr], 0)
C7 05 ?? ?? ?? ?? 00 00 00 00
// Comparing quiz_active (CMP DWORD [addr], 0)
83 3D ?? ?? ?? ?? 00
39 35 ?? ?? ?? ??               (cmp dword [rip+d], esi)
```

For x64, resolve the displacement as `insn_addr + insn_len + disp32`, and make sure `C7 05` is included — a register-form-only scanner will miss the write.

> **Tooling caveat:** a naive RIP-relative byte index matches register-form `mov`/`lea` RIP operands and REX-prefixed forms but **skips non-REX `C7 05 disp32 imm32`** — exactly how this flag is written. Such an index finds the *read* at `0x1401932EB` and misses the *write* at `0x14006C575`. Also, a full `.text` linear sweep desyncs in the obfuscated regions; sweep per-function (`.pdata` boundaries) and include `C7 05` / `C6 05` / `89 05` / `89 0D` forms explicitly.

---

## 2. Kernel-Mode State (Driver)

The driver holds no observed "quiz active" flag. What it does track, verified from decompilation:

| State | Location | Set/Cleared By |
|-------|----------|----------------|
| Encryption-enabled byte | `ApDriver+0x90` | port opcode `0x02` |
| State byte | `ApDriver+0x91` | cleared by `BrowserCommunicationPort::onConnect`, set by port opcode `0x13` |
| Monitored-data object | `ApDriver+0xb9` | guarded by two `ExInitializeResourceLite` |
| Tracked browser PID | `g_expectedBrowserPid` | connection gate; unknown PID → `0xC0000184` |

See `ioctl.md` for the opcode set read from the dispatcher.

---

## 3. Registry Persistence

The quiz state is also reflected in the registry:

```
HKCU\SOFTWARE\Respondus\Respondus LockDown Browser-2
    active = 1          ← quiz_active flag
    tvc    = 0          ← trial validation
    tvd    = 1          ← trial version detected
```

> **Warning:** the registry values are read at startup and are not the in-memory state this document is about. Clearing the registry `active` value does not disable the in-memory flag.

---

## 4. What the Command Does

`rldbqn=1` is processed in the EXE, which sets a process-local state dword and, on the `rldbxb=1` path, compares against another. What that state then gates — monitoring, hook enforcement, server reporting — has not been traced and should not be asserted.
