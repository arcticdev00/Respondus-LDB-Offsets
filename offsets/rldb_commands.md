# RLDB Commands Reference

**Version:** 2.1.6.00
**Protocol:** RLDB (Respondus LockDown Browser) command protocol
**Source:** EXE `.rdata` string analysis + handler tracing
**Generated:** 2026-09-16

---

## Overview

RLDB commands are tokens embedded in `LockDownBrowser.exe`'s `.rdata` and matched against navigation/parameter input. **57** `rldb*` strings are embedded in the EXE.

The observed literals are plain parameter-ish tokens (`rldbsm`, `rldbsm=`, `rldbsm=1`, `rldbfocus=1`), consistent with plain substring/query matching on the navigation URL. No scheme string like `rldb://` was found in the binary.

### Command Format

```
rldbsm        — bare token
rldbsm=       — token with separator
rldbsm=1      — token carrying an explicit value
```

> **Note:** everything below other than the VA and the literal text is `[inferred]` from the token name. No handler for these has been decompiled beyond those listed in §5, so no command's effect should be treated as established.

---

## 1. Security & Detection Commands

| Command | VA | Purpose |
|---------|-----|---------|
| `rldbdetect` | `0x140B2DA88` | detection channel marker `[inferred]` |
| `rldbvm` | `0x140B2DA7C` | VM detection |
| `rldbvcam` | `0x140B2DAA8` | webcam |
| `rldbvcamH` | `0x140209ECC` | same token + suffix |
| `rldbmodified` | `0x140B30EE0` | browser/OS modification detection |
| `rldbkh=1` | `0x140B1BD78` | keyboard hook |
| `rldbfocus=1` | `0x140B2DE18` | focus/window switching |
| `rldbfocus=2` | `0x140B2DE28` | second focus mode |

---

## 2. Screen & Input Control Commands

| Command | VA | Purpose |
|---------|-----|---------|
| `rldbsm` | `0x140B2DCF8` | screen monitor |
| `rldbsl` | `0x140B2DCF0` | screen lock |
| `rldbsp` | `0x140B2DD00` | screenshot prevention |
| `rldbswipe` | `0x140B2DA48` | touchscreen swipe |
| `rldbsleep` | `0x140B2DA60` | sleep/hibernate |
| `rldbprt` | `0x140B2DDB8` | print-screen |
| `rldbpl` | `0x140B2DD94` | paste lock |

Separator forms: `rldbtl=` `0x140B2DCE8`, `rldbsh=` `0x140B2BF48`, `rldbsl=` `0x140B2BF30`, `rldbsm=` `0x140B2BF38`, `rldbsp=` `0x140B2BF40`, `rldbsv=` `0x140B2BF50`.

---

## 3. Media & Bandwidth Commands

| Command | VA | Purpose |
|---------|-----|---------|
| `rldbbdw` | `0x140B1B7A8` | bandwidth |
| `rldbbt` | `0x140B2DA9C` | Bluetooth |
| `rldbacv` | `0x140B2BED0` | audio capture validation |
| `rldbarv` | `0x140B2BF10` | audio recording validation |
| `rldbcv` | `0x140B1B704` | camera/video |
| `rldbrv` | `0x140B1B70C` | recording verification |

---

## 4. Process Control & Misc Commands

| Command | VA | Purpose |
|---------|-----|---------|
| `rldbbl` | `0x140B2DD9C` | blocklist |
| `rldbwl` | `0x140B2DDA4` | whitelist |
| `rldbtk1` | `0x140B2DCD8` | task killer |
| `rldbtx2` | `0x140B2DBC8` | |
| `rldballow` | `0x140B2DAB8` | |
| `rldbdata` | `0x140B2DA70` | |
| `rldbsh` | `0x140B2DD20` | |
| `rldbsv` | `0x140B2DD28` | |
| `rldbsi` | `0x140B1B714` | |
| `rldbci` | `0x140B1B71C` | |
| `rldbid` | `0x140B1B7B0` | |
| `rldbtxt` | `0x140B2BF60` | |
| `rldbwn` | `0x140B2BF68` | |
| `rldbxb` | `0x140B2BF58` | |
| `rldbep` | `0x140B2DD30` | |
| `rldber` | `0x140B2DDC0` | |
| `rldbapw` | `0x140B2DD38` | |
| `rldbpwd` | `0x140B2DD40` | |
| `rldbclc` | `0x140B2DDB0` | |
| `rldbrp` | `0x140B2DDC8` | |

### Tokens Carrying an Explicit Value

| Command | VA | Notes |
|---------|-----|-------|
| `rldbqn=1` | `0x140B1CAE0` | quiz notification active — see `quiz_active.md` |
| `rldbxb=1` | `0x140B1CAD0` | adjacent to `rldbqn=1`, parsed by the same handler |
| `rldbsm=1` | `0x140B1D368` | |
| `rldbsv=1` | `0x140B1D358` | |
| `rldbet=1` | `0x140B2DE38` | |
| `rldbpt=1` | `0x140B2DE78` | |
| `rldbcancel=1` | `0x140B2DE08` | |

### Non-Command Strings

| String | VA | Notes |
|--------|-----|-------|
| `rldb_prestart_finished` | `0x140B2C628` | state name |
| `rldb_prestart_finished();` | `0x140B2C018` | the same name as a **call site in injected/inline JavaScript** — so at least part of this protocol is evaluated as script |
| `rldb:zz:manual-launch` | `0x140B2BD88` | `[inferred]` manual-launch escape hatch |

---

## 5. Resolved Handler Functions

Where a string was traced to its owning `.pdata` function (method: `find_refs.py`, which recovers RIP-relative references even in regions Ghidra never disassembled):

| String | Reference Site | Owning Function |
|--------|----------------|-----------------|
| `rldbqn=1` | `0x14006DDC5` | `0x14006BCA0`-`0x14006E360` |
| `rldbxb=1` | `0x14006DD57` | `0x14006BCA0`-`0x14006E360` |
| | `0x1401C5831` | `0x1401C5700`-`0x1401C5988` |
| | `0x1401C5AC1` | `0x1401C5990`-`0x1401C5C18` |
| | `0x1401C70C4`, `0x1401C73BA` | `0x1401C5C20`-`0x1401C761D` |
| `rldbkh=1` | `0x140071BC8` | `0x140071320`-`0x140072E83` |
| `rldbsv=1` | `0x14007F3C7` | `0x14007F050`-`0x14007FD22` |
| `rldbsm=1` | `0x14007F3F4` | `0x14007F050`-`0x14007FD22` |
| | `0x1401EDBD9` | `0x1401EDA80`-`0x1401EDD2E` |
| | `0x1401EDEC7` | `0x1401EDD30`-`0x1401EE3D2` |
| `rldbdetect` | `0x140209B87` | `0x140209690`-`0x14020A385` |
| | `0x14028FB75`, `0x140290741` | `0x14028FB10`-`0x140290807` |
| `rldbmodified` | `0x1402906B4` | `0x14028FB10`-`0x140290807` |

> **Note:** `0x14028FB10`-`0x140290807` sits **inside the obfuscated Layer A security module** (`0x140274320`-`0x1402931EA`). So `rldbdetect` and `rldbmodified` are handled by obfuscated code — consistent with them being detection triggers rather than UI commands. They are the ones worth treating as detection triggers.

---

## 6. Blacklist Architecture

From `process_blacklist.hpp` — **3,020** entries, as heap-allocated UTF-16LE strings:

| Category | Count |
|----------|------:|
| Browsers | 10 |
| System Tools | 26 |
| Analysis & Debugging Tools | 6 |
| Screen Recorders | 10 |
| VPN & Proxy | 3 |
| Remote Access | 6 |
| Chat & Communication | 10 |
| Installers | 42 |
| Updaters | 38 |
| Services | 201 |
| Other | 2,668 |
| **total** | **3,020** |

Detection surfaces, as far as they are established:
- Process name match
- Window class match (`Chrome_WidgetWin_1`, `Chrome_WidgetWin_0`, `MozillaWindowClass`, `MozillaCompositorWindowClass` are the verified class strings)
- Kernel-side signature validation via `CodeIntegrity::validateSignature` → `CiValidateFileObject`

> **Note:** the EXE carries no local blocklist vocabulary strings (`AllowAutoTyping`, `AllowSpyrix`, `AllowVoiceTyping`, `BlockCitrix`, `BlockILPBrowsers` are absent), consistent with blocklists being server-delivered configuration rather than compiled in.

---

## 7. Driver-Level Commands

**Not documented here.** There is no established mapping from an `rldb*` string to a driver opcode. The opcode set read from the dispatcher (`FUN_1400015c0`) — `0x00`-`0x04`, `0x06`, `0x08`, `0x0C`, `0x0D`, `0x0F`, `0x11`, `0x13`, `0x14` — is in **`ioctl.md`**.

---

## 8. Where the AKD Checks Sit Relative to This Protocol

The AKD detection subsystem talks to the driver over the **same filter port**, not through `rldb*` command strings. The recovered request paths:

| Path | Function | Request |
|------|----------|---------|
| reflection status | `0x14002E170`-`0x14002F719` | reflection-status request → encrypted response |
| thread info | `0x14002F720`-`0x140030A12` | two thread-info requests, second is the DWM integrity check → driver opcode `0x14` |

Both paths **skip the whole check if the driver link (a global mediator pointer) is null** — i.e. if `akd_mediator.connect()` never succeeded, the checks silently do not run.
