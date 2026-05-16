# Respondus LockDown Browser — Offsets & Signature Patterns

Latest offsets & patterns, updated with every version.

**Latest version:** `2.1.3.09` (CLDB 2.1.3.09; Chrome/129.0.0.0)  
**Updated:** 2026-05-16

---

## What's Inside

| Target | Type | Confidence |
| :--- | :--- | :--- |
| `.cldb` flag setters (LOCKDOWN/PROCTORING/EXIT) | Static RVA + Sigscan | 13/13 accesses confirmed |
| DLL exports (4 functions) | Static RVA + Sigscan | PE export directory |
| SetWindowsHookEx call sites (21 total) | Static RVA + Sigscan | 95% — IAT resolved |
| Keyboard hook callback procedure | Static RVA | push-argument traced |
| Process blacklist (3020 entries) | Heap-allocated, UTF-16LE strings | Runtime-only |
| Window class blacklist | Heap-allocated | Runtime-only |
| Exam URL triggers | Obfuscated at rest | Runtime construction |

All static offsets come with byte-pattern sigscans. If a new version shifts the RVAs, the patterns still work:

### Logic Patterns

*   **Find `.cldb` section:** 
    `Walk PE sections` → `match name .cldb` → `get VirtualAddress`
*   **Find flag setters:** 
    `Scan .text for 89 0D / 89 3D / C7 05` → `resolve disp32` → `check if target falls in .cldb range`
*   **Find exports:** 
    `Parse PE export directory` → `match ?CLDBDo prefix string`
*   **Find hook call sites:** 
    `Scan .text for FF 15` → `resolve IAT` → `check if user32!SetWindowsHookEx`

---

## Credits

If you repost or use this, please credit one of the following:

*   **GitHub:** [arcticdev00](https://github.com/arcticdev00)
*   **Discord:** [Join the server](https://discord.gg/GyBxnYZsXN)
