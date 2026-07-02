# LDB.dll Export Function Map

**Version:** v2.1.3.09 (LDB 32-bit) / v2.1.5.00 (LDB x64)
**Module:** LockDownBrowser.dll (LDB.dll)
**Generated:** 2026-07-02

---

## Overview

LDB.dll exports 4 functions called by LockDownBrowser.exe. All four manipulate the `.cldb` shared memory flags (LOCKDOWN, PROCTORING, EXIT). Understanding these exports reveals the complete lockdown lifecycle.

All four functions share:
- **Return type:** `int` (`H` in MSVC mangling)
- **Parameter:** single `int*` (pointer to int, `PEAH`)
- **Calling convention:** `__cdecl` (`A`)
- **Prefix:** `CLDB` (`C` + `LockDownBrowser`)
- **Deliberately obfuscated names:** `DoSomeStuff`, `DoSomeOtherStuff`, etc.

---

## Export Table Comparison

| Export | v2.1.3.09 RVA | v2.1.5.00 RVA | Ordinal | Purpose |
|--------|---------------|---------------|---------|---------|
| `CLDBDoSomeOtherStuff` | `+0x1000` | `+0x1000` | 0 | Main lockdown engine |
| `CLDBDoSomeOtherStuffs` | `+0x10B0` | `+0x10E0` | 1 | Status reporter (bitmask) |
| `CLDBDoSomeStuff` | `+0x10E0` | `+0x1110` | 2 | URL/navigation handler |
| `CLDBDoYetMoreStuff` | `+0x12A0` | `+0x1330` | 3 | EXIT password handler |

**Note:** v2.1.5.00 is x64 (PE32+) while v2.1.3.09 is 32-bit. The RVAs shifted between versions for all exports except `CLDBDoSomeOtherStuff`.

---

## CLDBDoSomeOtherStuff (+0x1000) — Main Lockdown Engine

**Purpose:** The primary lockdown activation function. Reads the current state, processes condition flags, calls into Windows APIs with action strings, and sets/clears the LOCKDOWN flag based on results.

**Flow:**
1. `MOV ECX, [LOCKDOWN]` — Read current LOCKDOWN flag
2. If set: `PUSH ECX; CALL [IAT]` — Notify handler of current state
3. `MOV [LOCKDOWN], 0` — Clear LOCKDOWN to 0
4. Load argument from `[EBP+8]` — Get input pointer from caller (EXE)
5. Test condition flags in sequence against the input:
   - `0x800000` (EXAM_START_1)
   - `0x400000` (EXAM_START_2)
   - `0x20000` (PROCTORING_MODE)
   - `0x10000` (EXIT_REQUEST)
   - `0x4000` (URL_EVENT)
6. Pick action string based on which flag matched:
   - Option 1/2 → `LDB+0x15D0`
   - Option 3 → `LDB+0x1670`
   - Option 4 → `LDB+0x13D0`
   - Option 5 → `LDB+0x1300`
   - Default → `LDB+0x1760`
7. `PUSH 13; CALL [IAT]` — Call Windows API with action string + parameter
8. `MOV [LOCKDOWN], ECX` — Set LOCKDOWN from API return value
9. If result != 0: `OR [ESI], 0x80000` — Set output flag in caller's struct
10. Return 1 if LOCKDOWN ended up set, 0 otherwise

**.cldb accesses:**
- `+0x1003`: READ LOCKDOWN
- `+0x1016`: WRITE LOCKDOWN ← ECX (clear to 0)
- `+0x1083`: WRITE LOCKDOWN ← ECX (set from IAT result)
- `+0x1093`: READ LOCKDOWN
- `+0x11D9`: WRITE EXIT ← ECX

**IAT calls:** 2

---

## CLDBDoSomeOtherStuffs — Status Reporter

### v2.1.3.09 (+0x10B0)

**Purpose:** Returns a bitmask indicating which lockdown flags are currently active. Read-only — no side effects on `.cldb`.

**Flow:**
1. `XOR EAX, EAX` — Clear return value
2. `CMP [LOCKDOWN], 0x400; CMOVNZ EAX, 0x400` — Set bit if LOCKDOWN active
3. `CMP [PROCTORING], 0; JZ skip; OR EAX, 0x1000` — Set bit if PROCTORING active
4. `CMP [EXIT], 0; JZ skip; OR EAX, 0x800` — Set bit if EXIT active
5. `RET` — Return bitmask in EAX

### v2.1.5.00 (+0x10E0)

The function shifted to `+0x10E0` in x64 build but maintains identical return bitmask semantics.

**Return bitmask:**

| Bit | Value | Flag |
|-----|-------|------|
| 10 | `0x400` | LOCKDOWN active |
| 11 | `0x800` | EXIT active |
| 12 | `0x1000` | PROCTORING active |

**Note:** This function shares code with `CLDBDoSomeStuff`. The export entry at `+0x10B0` (v2.1.3.09) / `+0x10E0` (v2.1.5.00) falls through into the same function body. They are the same function with different entry offsets.

---

## CLDBDoSomeStuff — URL/Navigation Handler

### v2.1.3.09 (+0x10E0) / v2.1.5.00 (+0x1110)

**Purpose:** Processes browser navigation events and URL checks. This is the function triggered when the browser navigates to an LMS exam URL (e.g., `processattempt.php`). Contains the full flag clearing sequence and keyboard hook installation.

**Flow:**
1. `PUSH EBP; MOV EBP, ESP; SUB ESP, 32` — Function prologue with 32 bytes of locals
2. `MOV ECX, [ECX]; XOR EDI, EDI` — Load input, clear EDI
3. Complex bit manipulation on input value (shifts, masks)
4. Same condition flag test sequence as `CLDBDoSomeOtherStuff`:
   - Tests `0x800000`, `0x400000`, `0x20000`, `0x10000`, `0x4000`
   - Pushes same action strings
5. `PUSH 13; CALL [IAT]` — Process action
6. `CMP [PROCTORING], 0; JZ skip` — Check proctoring
7. `PUSH 0; PUSH [global]; MOV [...]` — Additional IAT calls
8. **Full flag clearing sequence:**
   - `MOV [LOCKDOWN], EDI` — Clear LOCKDOWN
   - `MOV [PROCTORING], EDI` — Clear PROCTORING
   - `MOV [EXIT], EDI` — Clear EXIT
9. `MOV ESP, EBP; POP EBP; RET` — Clean return

**.cldb accesses (v2.1.3.09):**
- `+0x11D9`: WRITE EXIT ← ECX
- `+0x120F`: READ LOCKDOWN
- `+0x1256`: READ LOCKDOWN
- `+0x125E`: WRITE LOCKDOWN ← EDI (clear)
- `+0x1264`: READ PROCTORING
- `+0x1270`: WRITE PROCTORING ← EDI (clear)
- `+0x1276`: READ EXIT
- `+0x1282`: WRITE EXIT ← EDI (clear)

**IAT calls:** 2 (including SetWindowsHookEx at `+0x1250`)

**Key discovery:** `CLDBDoSomeOtherStuffs` and `CLDBDoSomeStuff` share the same function body. The export table lists them at different RVAs but they execute identical code.

---

## CLDBDoYetMoreStuff — EXIT Password Handler

### v2.1.3.09 (+0x12A0) / v2.1.5.00 (+0x1330)

**Purpose:** Handles the EXIT password requirement. Reads the EXIT flag, notifies handlers if set, clears it, then optionally re-sets it based on IAT call results.

**Flow:**
1. `PUSH EBP; MOV EBP, ESP`
2. `MOV EAX, [EXIT]` — Read EXIT flag
3. If set: `PUSH EAX; CALL [IAT]` — Notify handler
4. `MOV DWORD [EXIT], 0` — Clear EXIT to 0
5. Load argument, test condition flag
6. Pick string: `LDB+0x19A0` or `LDB+0x1840`
7. `PUSH 7; CALL [IAT]` — Process exit request
8. `MOV ECX, EAX` — Save IAT return
9. `XOR EAX, EAX` — Clear return value
10. `TEST ECX, ECX`
11. `MOV [EXIT], ECX` — Set EXIT from IAT result
12. `SETNZ AL` — Return 1 if EXIT ended up set, 0 otherwise
13. `POP EBP; RET`

**.cldb accesses:**
- `+0x12A3`: READ EXIT
- `+0x12B3`: CLEAR EXIT (MOV DWORD [EXIT], 0)
- `+0x12EA`: WRITE EXIT ← ECX (set from IAT result)

---

## Conditional Flag Test Sequence

All four exports test the input argument against the same flags:

| Flag | Purpose | Action String | Dispatcher |
|------|---------|---------------|------------|
| `0x800000` | Exam start / full lockdown | `LDB+0x15D0` | `PUSH 13` |
| `0x400000` | Exam start (alternative) | `LDB+0x15D0` | `PUSH 13` |
| `0x20000` | Proctoring mode | `LDB+0x1670` | `PUSH 13` |
| `0x10000` | Exit request | `LDB+0x13D0` | `PUSH 13` |
| `0x4000` | URL/navigation event | `LDB+0x1300` | `PUSH 13` |
| Default | Unknown | `LDB+0x1760` | `PUSH 13` |

---

## Summary

All four exports follow the same pattern:
1. **Read** `.cldb` flags
2. **Call** Windows/system APIs via IAT with action strings
3. **Write** results back to `.cldb`

The exports can be patched at their entry points (`31 C0 C3` = XOR EAX,EAX; RET) to return 0 without executing any lockdown logic. Alternatively, the individual `.cldb` flag setters can be NOPped to prevent specific flags from being written.

For **RLDB command handling**, see `rldb_commands.md`. The condition flags tested in these exports map directly to RLDB command types.
