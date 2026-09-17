# LDB.dll Export Function Map

**Version:** v2.1.6.00 (LDB x64)
**Module:** LockDownBrowser.dll (LDB.dll)
**Generated:** 2026-09-16

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

## Export Table

| Export | RVA | Ordinal | Purpose |
|--------|-----|---------|---------|
| `CLDBDoSomeOtherStuff` | `+0x1000` | 1 | Main lockdown engine |
| `CLDBDoSomeOtherStuffs` | `+0x10E0` | 2 | Status reporter (bitmask) |
| `CLDBDoSomeStuff` | `+0x1110` | 3 | URL/navigation handler |
| `CLDBDoYetMoreStuff` | `+0x1330` | 4 | EXIT password handler |

Mangled names as they appear in the export table:

```
?CLDBDoSomeOtherStuff@@YAHPEAH@Z     rva 0x1000  ord 1
?CLDBDoSomeOtherStuffs@@YAHPEAH@Z    rva 0x10e0  ord 2
?CLDBDoSomeStuff@@YAHPEAH@Z          rva 0x1110  ord 3
?CLDBDoYetMoreStuff@@YAHPEAH@Z       rva 0x1330  ord 4
```

---

## The `.cldb` Section

```
section name : .cldb
RVA          : 0x1C000
VA           : 0x18001C000     (image base 0x180000000)
virtual size : 0x18  (24)
characteristics : 0xD0000040 = CNT_INITIALIZED_DATA | MEM_SHARED | MEM_READ | MEM_WRITE
```

`MEM_SHARED` confirms it is the cross-process flag block the exports are built around. Contents in the shipped file — all three flags set:

```
+0x00 : 01 00 00 00 00 00 00 00      -> qword 1
+0x08 : 01 00 00 00 00 00 00 00      -> qword 1
+0x10 : 01 00 00 00 00 00 00 00      -> qword 1
```

### Verified x64 Access Sites (32 total)

Resolved by scanning `.text` for RIP-relative operands landing in `[0x18001C000, 0x18001C018)`. RVAs (RVA = VA − 0x180000000):

| slot | RVAs |
| :--- | :--- |
| `+0x00` (LOCKDOWN) | `0x100A` `0x1026` `0x10AB` `0x10BD` `0x10E7` `0x11C8` `0x122F` `0x126B` `0x12C3` `0x12D0` `0x1451` `0x16BC` `0x178C` `0x18A8` `0x19B0` |
| `+0x08` (PROCTORING) | `0x1100` `0x1201` `0x1239` `0x12F0` `0x1302` `0x133F` `0x1351` `0x1386` `0x1A1A` `0x1AAB` `0x1B56` |
| `+0x10` (EXIT) | `0x10F1` `0x11DA` `0x1248` `0x12D7` `0x12E9` `0x1B92` |

> **Note:** the x64 build touches all three slots with 64-bit `mov`/`cmp` only. The slot *names* are carried over from the 32-bit build's analysis; the offsets and widths are verified for x64.

---

## CLDBDoSomeOtherStuff (+0x1000) — Main Lockdown Engine

**Purpose:** The primary lockdown activation function. Reads the current state, processes condition flags, calls into Windows APIs with action strings, and sets/clears the LOCKDOWN flag based on results.

**Flow:**
1. Read current LOCKDOWN flag (`0x100A`)
2. If set: notify handler of current state
3. Clear LOCKDOWN to 0 (`0x1026`, `0x10AB` — writes)
4. Load argument from caller (EXE)
5. Test condition flags in sequence against the input (see table below)
6. Pick action string based on which flag matched
7. `PUSH 13; CALL [IAT]` — Call Windows API with action string + parameter
8. Set LOCKDOWN from API return value
9. If result != 0: set output flag `0x80000` in caller's struct
10. Return 1 if LOCKDOWN ended up set, 0 otherwise

**Verified x64 access order:** read `+0x00` (`0x100A`), write `+0x00` (`0x1026`, `0x10AB`), read `+0x00` (`0x10BD`), then the three-slot test at `0x10E7`/`0x10F1`/`0x1100`.

---

## CLDBDoSomeOtherStuffs (+0x10E0) — Status Reporter

**Purpose:** Returns a bitmask indicating which lockdown flags are currently active. Read-only — no side effects on `.cldb`.

**Flow:**
1. Test slot 1 (`0x10E7`) — set bit if LOCKDOWN active
2. Test slot 3 (`0x10F1`) — set bit if EXIT active
3. Test slot 2 (`0x1100`) — set bit if PROCTORING active
4. Return bitmask in EAX

**Return bitmask:**

| Bit | Value | Flag |
|-----|-------|------|
| 10 | `0x400` | LOCKDOWN active |
| 11 | `0x800` | EXIT active |
| 12 | `0x1000` | PROCTORING active |

---

## CLDBDoSomeStuff (+0x1110) — URL/Navigation Handler

**Purpose:** Processes browser navigation events and URL checks. This is the function triggered when the browser navigates to an LMS exam URL (e.g., `processattempt.php`). Contains the full flag clearing sequence and hook installation.

**Flow:**
1. Load input, run the condition flag test sequence (same as `CLDBDoSomeOtherStuff`)
2. `PUSH 13; CALL [IAT]` — Process action
3. Check PROCTORING slot
4. **Full flag clearing sequence:** clear LOCKDOWN, PROCTORING and EXIT slots
5. Install hooks

**Verified x64:** writes slot 1 at `0x11C8` and `0x12D0`, slot 3 at `0x11DA` and `0x12E9`, slot 2 at `0x1201`.

---

## CLDBDoYetMoreStuff (+0x1330) — EXIT Password Handler

**Purpose:** Handles the EXIT password requirement. Reads the EXIT flag, notifies handlers if set, clears it, then optionally re-sets it based on IAT call results.

**Flow:**
1. Read EXIT flag
2. If set: notify handler
3. Clear EXIT to 0
4. Load argument, test condition flag
5. `PUSH 7; CALL [IAT]` — Process exit request
6. Set EXIT from IAT result
7. Return 1 if EXIT ended up set, 0 otherwise

**Verified x64:** writes slot 2 at `0x1351` and `0x1386`, slot 1 at `0x1451`.

> **Note:** "EXIT password handler" (from the slot mapping) vs "`WH_MOUSE` handler" are both in circulation. 

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

The exports can be patched at their entry points (`31 C0 C3` = XOR EAX,EAX; RET) to return 0 without executing any lockdown logic. Alternatively, the RIP-relative `.cldb` writes listed above can be NOPped to prevent specific flags from being written. Bluntest option: `.cldb` is `MEM_SHARED`, so zeroing all 24 bytes at runtime clears all three flags at once — which is exactly what the flag-readers are there to notice.

For **RLDB command handling**, see `rldb_commands.md`. The condition flags tested in these exports map directly to RLDB command types.

> **Note:** the HookDLL's notable behavioural trait in 2.1.6.0.0 is unrelated to `.cldb` — the global `VK_F12` block (`cmp ecx, 0x7b`) is absent from the three keyboard hook procedures at `0x13a0`, `0x162c` and `0x18e0`. See `../README.md`.
