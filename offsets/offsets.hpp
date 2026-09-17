#pragma once

#include <cstddef>
#include <cstdint>

// ============================================================================
// Respondus LockDown Browser — Offsets & Signature Patterns
// Version: 2.1.6.00 (CLDB 2.1.6.00; Chrome/150.0.0.0)
// Generated: 2026-09-16
// Includes: .cldb flags, exports, hooks, VM detection, anti-debug,
//           driver IOCTL, quiz_active flag, RLDB command codes
// ============================================================================

namespace respondus_offsets {

    // ========================================================================
    // Module: LockDownBrowser.dll (LDB.dll)
    // x64 DLL (v2.1.6.00), loaded by LockDownBrowser.exe
    // ========================================================================
    namespace lockdownbrowser_dll {

        // ====================================================================
        // .cldb Shared Memory Section (SHARED|WRITE|READ)
        // 24 bytes of runtime flags. Write 24 zero bytes to disable all.
        // Find dynamically by walking PE sections for ".cldb" name.
        // ====================================================================
        namespace cldb {

            // --- Static offsets (relative to LDB.dll base) ---
            // v2.1.6.00: RVA_SECTION = 0x1C000
            constexpr uint32_t RVA_SECTION = 0x1C000;
            constexpr uint32_t SIZE = 0x18;

            // Flag qword offsets within .cldb section
            // (x64 build touches all three slots with 64-bit mov/cmp only)
            enum class FlagOffset : uint32_t {
                LOCKDOWN_ENABLED = 0x00,       // keyboard hooks, navigation block
                PROCTORING_ENABLED = 0x08,     // webcam/microphone recording
                EXIT_PASSWORD_ENABLED = 0x10,  // require password to exit
            };

            // Runtime .cldb flag structure (24 bytes)
            struct Flags {
                uint64_t lockdown;      // +0x00 — non-zero = lockdown active
                uint64_t proctoring;    // +0x08 — non-zero = proctoring active
                uint64_t exit_password; // +0x10 — non-zero = exit password required
            };

            // Verified x64 access sites (2.1.6.0.0)
            // Found by scanning .text for RIP-relative operands landing in
            // [0x18001C000, 0x18001C018). 32 sites, all 64-bit.
            namespace access_sites_x64 {
                // slot +0x00
                constexpr uint32_t SLOT00[] = {
                    0x100A, 0x1026, 0x10AB, 0x10BD, 0x10E7, 0x11C8, 0x122F, 0x126B,
                    0x12C3, 0x12D0, 0x1451, 0x16BC, 0x178C, 0x18A8, 0x19B0,
                };
                // slot +0x08
                constexpr uint32_t SLOT08[] = {
                    0x1100, 0x1201, 0x1239, 0x12F0, 0x1302, 0x133F, 0x1351, 0x1386,
                    0x1A1A, 0x1AAB, 0x1B56,
                };
                // slot +0x10
                constexpr uint32_t SLOT10[] = {
                    0x10F1, 0x11DA, 0x1248, 0x12D7, 0x12E9, 0x1B92,
                };
                constexpr uint32_t SITE_COUNT = 32;
            }

            // sigscan method:
            // 1. Parse LDB.dll PE -> find .cldb section VirtualAddress
            // 2. cldb_runtime = ldb_base + VirtualAddress
            // 3. Scan .text for RIP-relative qword forms: 48 89 / 48 8B / 48 83 3D / 48 39
            // 4. For each: resolve disp32 (target = insn_addr + insn_len + disp)
            //    -> if target in [cldb_runtime, cldb_runtime+0x18] it's a .cldb access.
            //       offset from section start tells you the slot; opcode tells you read vs write.
        } // namespace cldb


        // ====================================================================
        // Quiz Active Flag
        // Set via rldbqn=1 command. Controls whether all monitoring is active.
        // v2.1.6.00: EXE-side candidate at 0x140CAC708 (.data, RVA 0xCAC708)
        // ====================================================================
        namespace quiz_active {
            // "rldbqn=1" is a string in LockDownBrowser.exe (VA 0x140B1CAE0),
            // handled by an EXE function — the HookDLL never sees it.
            // The EXE-side handler is 0x14006BCA0-0x14006E360
            // (it references BOTH "rldbqn=1" and "rldbxb=1").
            constexpr uint32_t EXE_HANDLER_START = 0x14006BCA0;
            constexpr uint32_t EXE_HANDLER_END   = 0x14006E360;

            // Strong candidate (not yet confirmed at runtime). In the handler:
            //   14006C360  cmp dword ptr [0x140CAC708], 0   ; already active?
            //   14006C575  mov dword ptr [0x140CAC708], 1   ; set active (C7 05 form)
            // and it is read from a second function (cmp at 0x1401932EB).
            constexpr uint32_t EXE_FLAG_CANDIDATE_VA  = 0x140CAC708;
            constexpr uint32_t EXE_FLAG_CANDIDATE_RVA = 0xCAC708;

            // Sigscan pattern: C7 05 [disp32] 01 00 00 00  (MOV DWORD [addr], 1)
            // Sigscan pattern: C7 05 [disp32] 00 00 00 00  (MOV DWORD [addr], 0)
            // Resolve disp32; if target is in .data -> quiz_active
            // (include C7 05 — a register-form-only scanner will miss the write)
        } // namespace quiz_active


        // ====================================================================
        // VM Detection — CPUID-based hypervisor check
        // ====================================================================
        namespace vm_detection {
            struct CpuidHypervisorOutput {
                uint32_t eax;
                uint32_t ebx;
                uint32_t ecx;
                uint32_t edx;
            };

            enum class HypervisorSignature : uint32_t {
                VMWARE       = 0x6000601,  // "VMwareVMware"
                MICROSOFT_HV = 0x6000602,  // "Microsoft Hv"
                XEN          = 0x6000603,  // "XenVMMXenVMM"
                KVM          = 0x6000603,  // "KVMKVMKVM"
            };
        } // namespace vm_detection


        // ====================================================================
        // Anti-Debug — ICEBP instructions (opcode 0xF1)
        // ====================================================================
        namespace anti_debug {
            constexpr uint8_t ICEBP_OPCODE = 0xF1;
            constexpr uint8_t NOP_OPCODE   = 0x90;

            // Confirmed trap site (x64 build, scan ICEBP traps for others):
            // LDB+0x113A — inside export CLDBDoSomeOtherStuff (+0x1000)
        } // namespace anti_debug


        // ====================================================================
        // DLL Exports — called by LockDownBrowser.exe
        // v2.1.6.00: CLDBDoSomeOtherStuff=0x1000, CLDBDoSomeOtherStuffs=0x10E0,
        //             CLDBDoSomeStuff=0x1110, CLDBDoYetMoreStuff=0x1330
        // ====================================================================
        namespace exports {
            enum class Functions : uint32_t {  // v2.1.6.00
                CLDBDoSomeOtherStuff  = 0x1000,
                CLDBDoSomeOtherStuffs = 0x10E0,
                CLDBDoSomeStuff       = 0x1110,
                CLDBDoYetMoreStuff    = 0x1330,
            };

            enum class StatusFlags : uint32_t {
                LOCKDOWN_ACTIVE   = 0x400,   // LOCKDOWN flag is set
                PROCTORING_ACTIVE = 0x1000,  // PROCTORING flag is set
                EXIT_ACTIVE       = 0x800,   // EXIT flag is set
            };
        } // namespace exports


        // ====================================================================
        // Keyboard Hook Procedures (WH_KEYBOARD_LL)
        // ====================================================================
        namespace hook_procedures {
            constexpr uint32_t KEYBOARD_HOOK_PROC_1 = 0x13A0;  // 249 B
            constexpr uint32_t KEYBOARD_HOOK_PROC_2 = 0x162C;  // 187 B (tail of 0x14A0)
            constexpr uint32_t KEYBOARD_HOOK_PROC_3 = 0x18E0;  // 256 B
        } // namespace hook_procedures


        // ====================================================================
        // VK_F12 — not blocked in 2.1.6.0.0 (HookDLL)
        // The F12 key (Chrome DevTools) block is absent from the 3 keyboard
        // hook procs. Byte pattern "cmp ecx, 0x7b" (83 F9 7B) has 0
        // occurrences in .text.
        // ====================================================================
        namespace vk_f12 {
            constexpr uint32_t HOOK_PROC_1 = 0x13A0;  // WH_KEYBOARD_LL
            constexpr uint32_t HOOK_PROC_2 = 0x162C;  // WH_KEYBOARD_LL
            constexpr uint32_t HOOK_PROC_3 = 0x18E0;  // WH_KEYBOARD_LL

            // The (absent) instruction pattern: cmp ecx, 0x7b (VK_F12)
            constexpr uint8_t CMP_VK_F12_OPCODE = 0x83;
            constexpr uint8_t CMP_VK_F12_OPERAND = 0x7B;
        } // namespace vk_f12

    } // namespace lockdownbrowser_dll


    // ========================================================================
    // RLDB Command Protocol Codes
    // URL parameters passed to LDB.dll via CLDBDoSomeStuff
    // ========================================================================
    namespace rldb_commands {

        // Condition flags tested in CLDBDoSomeStuff
        enum class ActionFlag : uint32_t {
            EXAM_START_1      = 0x800000,  // Full lockdown (option 1)
            EXAM_START_2      = 0x400000,  // Full lockdown (option 2)
            PROCTORING_MODE   = 0x20000,   // Enable proctoring
            EXIT_REQUEST      = 0x10000,   // Request exit
            URL_EVENT         = 0x4000,    // URL/navigation event
        };

        // Action string offsets within LDB.dll
        enum class ActionString : uint32_t {
            OPTION_1_2  = 0x15D0,  // Used for EXAM_START flags
            OPTION_3    = 0x1670,  // Used for PROCTORING_MODE
            OPTION_4    = 0x13D0,  // Used for EXIT_REQUEST
            OPTION_5    = 0x1300,  // Used for URL_EVENT
            DEFAULT     = 0x1760,  // Default handler
        };

        // IAT dispatcher types
        constexpr uint32_t DISPATCHER_ACTION = 13;  // PUSH 13; CALL [IAT]
        constexpr uint32_t DISPATCHER_EXIT   = 7;   // PUSH 7;  CALL [IAT]

    } // namespace rldb_commands


    // ========================================================================
    // Driver IOCTL Codes — LockDownService215.sys Communication Protocol
    // Primary: Filter Communication Port (FltCreateCommunicationPort)
    // Secondary: DeviceIoControl (\\.\LockDownService)
    // ========================================================================
    namespace driver_ioctl {

        // Device names
        constexpr wchar_t DEVICE_NAME[]     = L"LockDownService";
        constexpr wchar_t SYMLINK_NAME[]    = L"\\\\.\\LockDownService";
        constexpr wchar_t SERVICE_NAME[]    = L"LockDownService215";
        constexpr uint32_t ALTITUDE         = 47777;

        // User-Mode -> Kernel opcodes (via the filter port; arrive at the port
        // dispatcher FUN_1400015c0). All read from the 2.1.6.0.0 dispatcher.
        // "reply" = the first dword written to the output buffer.
        // Protocol detail: offsets/ioctl.md
        enum class CommandCode : uint32_t {
            CRYPTO_OUT         = 0x00,  // BCrypt op on the output buffer directly
            CRYPTO_IN          = 0x01,  // BCrypt op on caller data (param_2+2, param_2[1])
            ENABLE_ENCRYPTION  = 0x02,  // on success sets the byte at ApDriver+0x90
            ENCRYPTED_REQUEST  = 0x03,  // requires encryption on (else 0xC0000010); vtable dispatch
            ENUM_A             = 0x04,  // reply 0x05 + count, records of 0xf0c bytes
            ENUM_B             = 0x06,  // reply 0x07 + count, records of 0x710 bytes
            ENUM_C             = 0x08,  // reply 0x09 + dword(obj+0x318) + records of 0x710 bytes
            ENUM_D             = 0x0c,  // reply 0x0E + count, 4-byte records
            ENUM_E             = 0x0d,  // reply 0x0F + count, 4-byte records
            STATUS_TWO_DWORDS  = 0x0f,  // reply 0x10 + FUN_140009140(mon,0) + FUN_140009140(mon,1)
            GET_VERSION        = 0x11,  // reply 0x12 + the two version qwords at ApDriver+0x700/+0x708
            SET_STATE_FLAG     = 0x13,  // FltAcquireResourceExclusive; *(char*)(ApDriver+0x91) = (char)param_2[1]; no reply
            WHOLE_PROCESS_SCAN = 0x14,  // PID + thread-ID array; requires param_3 >= 0x10; 0xC0000184 when
                                        // DAT_14000f090 == 0; calls FUN_140008fe0; reply 0x15 + verdict.
                                        // For each thread: ZwQueryInformationThread(Win32StartAddress) ->
                                        // ZwQueryVirtualMemory(MemoryBasicInformation); if the start address
                                        // does not resolve to a file-backed image section -> verdict 3
                                        // (fileless / injected code). Per-thread cache at +0xD0.
        };
        // Unhandled opcodes (0x05, 0x07, 0x09-0x0b, 0x0e, 0x10, 0x12, 0x15+) fall
        // through to `return 0` = STATUS_SUCCESS with NO output written. A caller
        // cannot distinguish "unsupported" from "succeeded silently" by status alone.

        // Dispatcher input validation, read from FUN_1400015c0
        constexpr uint32_t DISPATCHER_MAX_IRQL        = 2;          // KeGetCurrentIrql() > 2 -> 0xC0000184
        constexpr uint32_t STATUS_INVALID_PARAMETER   = 0xC000000D; // param_6 == NULL or param_4 == NULL
        constexpr uint32_t STATUS_INVALID_BUFFER_SIZE = 0xC0000206; // param_3 < 4, or param_2 == NULL
        constexpr uint32_t STATUS_BUFFER_TOO_SMALL    = 0xC0000023; // param_5 < required size
        constexpr uint32_t STATUS_INVALID_DEVICE_STATE_NT = 0xC0000184;
        constexpr uint32_t STATUS_ACCESS_DENIED_NT        = 0xC0000022;

        // When the port is in encrypted mode, the reply STRUCT sits after a 0x108-byte
        // (264-byte) envelope and *param_6 = required + 0x108. A client that assumes
        // the reply starts at offset 0 will misparse every encrypted reply.
        constexpr uint32_t ENCRYPTED_REPLY_PREFIX = 0x108;

        // Reply subtypes observed as the first dword of the output buffer
        enum class ReplySubtype : uint32_t {
            ENUM_A_REPLY      = 0x05,
            ENUM_B_REPLY      = 0x07,
            ENUM_C_REPLY      = 0x09,
            ENUM_D_REPLY      = 0x0E,
            ENUM_E_REPLY      = 0x0F,
            STATUS_REPLY      = 0x10,
            VERSION_REPLY     = 0x12,  // reply to GET_VERSION (opcode 0x11)
            FILELESS_SCAN     = 0x15,  // reply to WHOLE_PROCESS_SCAN (opcode 0x14)
        };

        // Kernel -> User-Mode notification path.
        // The driver exposes CommunicationPortBase::sendMessage (FltSendMessage),
        // so a kernel->user notification path exists, but its message format is
        // not documented here (requires dynamic verification).

        // Driver crypto subsystem (BCrypt AES-256-CBC + RSA-2048)
        namespace crypto {
            constexpr uint32_t AES_KEY_SIZE   = 32;   // 256 bits
            constexpr uint32_t AES_IV_SIZE    = 16;   // 128 bits
            constexpr uint32_t RSA_KEY_SIZE   = 256;  // 2048 bits
            constexpr uint32_t SHA1_HASH_SIZE = 20;
        }

        // Driver tracking structures
        namespace tracking {
            constexpr uint32_t MAX_BLOCKLIST_ENTRIES = 4096;
            constexpr uint32_t MAX_PROCESS_NAME_LEN  = 260;  // WCHAR
        }

    } // namespace driver_ioctl


    // ========================================================================
    // Module: LockDownBrowser.exe (x64, ~20MB, Chromium 150 based)
    // v2.1.6.00: 20,827,072 bytes, 19,538 functions
    // No .cldb accesses in EXE — all flag manipulation is in LDB.dll.
    // ========================================================================
    namespace lockdownbrowser_exe {

        namespace window_blacklist {
            constexpr wchar_t CHROME_WIDGETWIN_1[] = L"Chrome_WidgetWin_1";
            constexpr wchar_t CHROME_WIDGETWIN_0[] = L"Chrome_WidgetWin_0";
            constexpr wchar_t MOZILLA_WINDOW_CLASS[] = L"MozillaWindowClass";
            constexpr wchar_t MOZILLA_COMPOSITOR_CLASS[] = L"MozillaCompositorWindowClass";
        }

        namespace process_blacklist {
            // see process_blacklist.hpp (3020+ entries)
        }

        // Registry flags
        namespace registry {
            constexpr wchar_t KEY_STANDALONE[] = L"SOFTWARE\\Respondus\\Respondus LockDown Browser-2";
            constexpr wchar_t KEY_OEM[]        = L"SOFTWARE\\Respondus\\LockDown Browser OEM-2";
            constexpr wchar_t VALUE_ACTIVE[]   = L"active";
            constexpr wchar_t VALUE_TVC[]      = L"tvc";
            constexpr wchar_t VALUE_TVD[]      = L"tvd";
        }

    } // namespace lockdownbrowser_exe


    // ========================================================================
    // Driver Analysis Constants — LockDownService215.sys
    // ========================================================================
    namespace driver_analysis {
        constexpr wchar_t DRIVER_NAME[]       = L"LockDownService215.sys";
        constexpr wchar_t DRIVER_PATH[]       = L"\\SystemRoot\\System32\\drivers\\LockDownService215.sys";
        constexpr uint32_t EXPECTED_SIZE      = 71944;  // ~70KB
        constexpr uint32_t ALTITUDE           = 47777;
        constexpr wchar_t LOAD_GROUP[]        = L"FSFilter Bottom";

        // Key kernel APIs used by the driver
        namespace apis {
            constexpr wchar_t PROCESS_CALLBACK[]    = L"PsSetCreateProcessNotifyRoutineEx";
            constexpr wchar_t THREAD_CALLBACK[]     = L"PsSetCreateThreadNotifyRoutine";
            constexpr wchar_t IMAGE_CALLBACK[]      = L"PsSetLoadImageNotifyRoutine";
            constexpr wchar_t CODE_INTEGRITY[]      = L"CiValidateFileObject";
            constexpr wchar_t CROSS_PROCESS_ATTACH[] = L"KeStackAttachProcess";
            constexpr wchar_t DYNAMIC_RESOLVER[]    = L"MmGetSystemRoutineAddress";
            // DriverLogger imports
            constexpr wchar_t ZW_CREATE_FILE[]     = L"ZwCreateFile";
            constexpr wchar_t ZW_WRITE_FILE[]      = L"ZwWriteFile";
            constexpr wchar_t ZW_DELETE_FILE[]     = L"ZwDeleteFile";
            constexpr wchar_t ZW_QUERY_DIR_FILE[]  = L"ZwQueryDirectoryFile";
            constexpr wchar_t EX_SYS_TIME_LOCAL[]  = L"ExSystemTimeToLocalTime";
            constexpr wchar_t RTL_TIME_FIELDS[]    = L"RtlTimeToTimeFields";
            constexpr wchar_t FLT_ACQUIRE_RES[]    = L"FltAcquireResourceShared";
        }

        // Internal class names (found as ASCII strings in driver)
        namespace classes {
            constexpr wchar_t COMM_PORT_BASE[]     = L"CommunicationPortBase";
            constexpr wchar_t BROWSER_PORT[]       = L"BrowserCommunicationPort";
            constexpr wchar_t PROCESS_MONITOR[]    = L"ProcessMonitor";
            constexpr wchar_t THREAD_MONITOR[]     = L"ThreadMonitor";
            constexpr wchar_t USERMODE_DETECTOR[]  = L"UserModeDetector";
            constexpr wchar_t CODE_INTEGRITY[]     = L"CodeIntegrity";
            constexpr wchar_t CRYPTO_KERNEL[]      = L"CryptoKernel";
            constexpr wchar_t DYNAMIC_FUNCTIONS[]  = L"DynamicFunctionsKm";
            constexpr wchar_t CMD_WRAPPER[]        = L"CmdWrapper";
            constexpr wchar_t DWM_RESOLVER[]       = L"DwmImageResolver";
            constexpr wchar_t BROWSER_RESOLVER[]   = L"BrowserImageResolver";
            // New in 2.1.6.0.0
            constexpr wchar_t DRIVER_LOGGER[]      = L"DriverLogger";
        }

        // Connection gate — only the browser process can connect;
        // PID mismatch -> forced disconnect
        namespace port_gate {
            constexpr uint32_t STATUS_INVALID_DEVICE_STATE = 0xC0000184;  // No browser PID known
            constexpr uint32_t STATUS_ACCESS_DENIED        = 0xC0000022;  // PID mismatch
        }
    } // namespace driver_analysis


    // Convenience aliases
    namespace cldb     = lockdownbrowser_dll::cldb;
    namespace exports  = lockdownbrowser_dll::exports;
    namespace kbproc   = lockdownbrowser_dll::hook_procedures;
    namespace vmdet    = lockdownbrowser_dll::vm_detection;
    namespace adbg     = lockdownbrowser_dll::anti_debug;
    namespace quiz     = lockdownbrowser_dll::quiz_active;
    namespace vkf12    = lockdownbrowser_dll::vk_f12;
    namespace rldb     = rldb_commands;
    namespace ioctl    = driver_ioctl;
    namespace drv      = driver_analysis;

} // namespace respondus_offsets
