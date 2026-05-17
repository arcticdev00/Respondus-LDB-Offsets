# CLDBDoSomeOtherStuff (+0x1000) — THE MAIN LOCKDOWN ENGINE

**Flow:**
```
1. `MOV ECX, [LOCKDOWN]` ; Read current state
2. If set: `PUSH` it, `CALL [IAT]` ; Notify handler
3. `MOV [LOCKDOWN], 0` ; CLEAR it
4. Load arg from `[EBP+8]` ; Get input pointer
5. Test condition flags in sequence (`0x800000`, `0x400000`, `0x20000`, `0x10000`, `0x4000`)
6. Pick action string based on which flag is set:
   * `0x709515D0` (LDB+0x15D0) ; option 1 & 2
   * `0x70951670` (LDB+0x1670) ; option 3
   * `0x709513D0` (LDB+0x13D0) ; option 4
   * `0x70951300` (LDB+0x1300) ; option 5
   * `0x70951760` (LDB+0x1760) ; default
7. `PUSH 13`, `CALL [IAT]` ; Process the action
8. `MOV [LOCKDOWN], ECX` ; SET LOCKDOWN from result
9. If result != 0: `OR [ESI], 0x80000` ; Set output flag
10. Return 1 if LOCKDOWN ended up set
```
---

# CLDBDoSomeOtherStuffs (+0x10B0) — STATUS REPORTER

Returns bitmask in `EAX`:
* Tests `PROCTORING` → sets `0x1000`
* Tests `EXIT` → sets `0x800`
* LOCKDOWN check via `CMP [LOCKDOWN], 0x400` → `CMOVNZ EAX, 0x400`

*Read-only, no writes to .cldb*

---

# CLDBDoSomeStuff (+0x10E0) — URL/NAVIGATION HANDLER

Same code as `CLDBDoSomeOtherStuffs` but at a different entry point. Both share the same function body. The export table lists them as separate ordinals but they execute identical code.

* Full flag clearing sequence at `+0x125E` - `+0x1282`
* Calls `SetWindowsHookEx` at `+0x1250`

---

# CLDBDoYetMoreStuff (+0x12A0) — EXIT PASSWORD HANDLER

**Flow:**
1. `MOV EAX, [EXIT]` ; Read EXIT flag
2. If set: `PUSH` it, `CALL [IAT]` ; Notify
3. `MOV DWORD [EXIT], 0` ; CLEAR EXIT
4. Test condition, pick string (`0x19A0` or `0x1840`)
5. `PUSH 7`, `CALL [IAT]` ; Process exit request
6. `MOV [EXIT], ECX` ; SET EXIT from result
7. Return 1 if EXIT ended up set
