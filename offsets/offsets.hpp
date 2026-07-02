#pragma once

#include <cstddef>
#include <cstdint>

// ============================================================================
// Respondus LockDown Browser — Offsets & Signature Patterns
// Version: 2.1.5.00 (CLDB 2.1.5.00; Chrome/142.0.7444.135)
// Generated: 2026-07-02
// Includes: .cldb flags, exports, hooks, VM detection, anti-debug,
//           driver IOCTL, quiz_active flag, RLDB command codes
// ============================================================================

namespace respondus_offsets {

    // ========================================================================
    // Module: LockDownBrowser.dll (LDB.dll)
    // 32-bit DLL (v2.1.3.09) or x64 (v2.1.5.00), loaded by LockDownBrowser.exe
    // ========================================================================
    namespace lockdownbrowser_dll {

        // ====================================================================
        // .cldb Shared Memory Section (SHARED|WRITE|READ)
        // 12 bytes of runtime flags. Write 12 zero bytes to disable all.
        // Find dynamically by walking PE sections for ".cldb" name.
        // ====================================================================
        namespace cldb {

            // --- Static offsets (relative to LDB.dll base) ---
            // v2.1.3.09: RVA_SECTION = 0x17000
            // v2.1.5.00: RVA_SECTION = (verify dynamically)
            constexpr uint32_t RVA_SECTION = 0x17000;
            constexpr uint32_t SIZE = 12;

            // Flag byte offsets within .cldb section
            enum class FlagOffset : uint32_t {
                LOCKDOWN_ENABLED = 0x00,  // keyboard hooks, navigation block
                PROCTORING_ENABLED = 0x04,  // webcam/microphone recording
                EXIT_PASSWORD_ENABLED = 0x08,  // require password to exit
            };

            // Runtime .cldb flag structure (12 bytes)
            struct Flags {
                uint32_t lockdown;      // +0x00 — non-zero = lockdown active
                uint32_t proctoring;    // +0x04 — non-zero = proctoring active
                uint32_t exit_password; // +0x08 — non-zero = exit password required
            };

            // .cldb Flag Setters (NOP these to permanently disable lockdown)
            namespace setters_lockdown {
                constexpr uint32_t SETTER_ECX_1 = 0x1016;  // 89 0D [cldb+0x00], ECX
                constexpr uint32_t SETTER_ECX_2 = 0x1083;  // 89 0D [cldb+0x00], ECX
                constexpr uint32_t SETTER_EDI = 0x125E;  // 89 3D [cldb+0x00], EDI
                // Patch: 6 bytes of 0x90 (NOP)
            }

            namespace setters_proctoring {
                constexpr uint32_t SETTER_EDI = 0x1270;  // 89 3D [cldb+0x04], EDI
            }

            namespace setters_exit {
                constexpr uint32_t SETTER_ECX_1 = 0x11D9;  // 89 0D [cldb+0x08], ECX
                constexpr uint32_t SETTER_EDI = 0x1282;  // 89 3D [cldb+0x08], EDI
                constexpr uint32_t SETTER_ECX_2 = 0x12EA;  // 89 0D [cldb+0x08], ECX
                constexpr uint32_t CLEARER = 0x12B3;  // C7 05 [cldb+0x08], 0x00000000
            }

            // .cldb flag readers (informational)
            namespace readers {
                constexpr uint32_t READ_LOCKDOWN_1 = 0x120F;  // A1 [cldb+0x00]
                constexpr uint32_t READ_LOCKDOWN_2 = 0x1256;  // A1 [cldb+0x00]
                constexpr uint32_t READ_PROCTORING = 0x1264;  // A1 [cldb+0x04]
                constexpr uint32_t READ_EXIT_1 = 0x1276;  // A1 [cldb+0x08]
                constexpr uint32_t READ_EXIT_2 = 0x12A3;  // A1 [cldb+0x08]
            }

            // Version-proof sigscan method:
            // 1. Parse LDB.dll PE -> find .cldb section VirtualAddress
            // 2. cldb_runtime = ldb_base + VirtualAddress
            // 3. Scan .text for: 89 0D | 89 3D | 89 05 | C7 05 | A1
            // 4. For each: resolve disp32 -> if target in [cldb_runtime, cldb_runtime+12]
            //    -> it's a .cldb access. opcode tells you read vs write.
        } // namespace cldb


        // ====================================================================
        // Quiz Active Flag (adjacent to .cldb section)
        // Set via rldbqn=1 command. Controls whether all monitoring is active.
        // v2.1.3.09: ~LDB+0x17010 (in .data, after .cldb)
        // v2.1.5.00: ~LDB+0x???? (verify dynamically)
        // ====================================================================
        namespace quiz_active {
            constexpr uint32_t RVA_OFFSET_FROM_CLDB = 0x10;  // 16 bytes after .cldb start

            enum class State : uint32_t {
                INACTIVE   = 0x00000000,  // No quiz, monitoring inactive
                ACTIVE     = 0x00000001,  // Quiz in progress
                PROCTORING = 0x00000002,  // Quiz with webcam proctoring
                LOCKED     = 0xFFFFFFFF,  // Exit password required
            };

            // Sigscan pattern: C7 05 [disp32] 01 00 00 00  (MOV DWORD [addr], 1)
            // Sigscan pattern: C7 05 [disp32] 00 00 00 00  (MOV DWORD [addr], 0)
            // Resolve disp32; if target is near .cldb end or in .data -> quiz_active
        } // namespace quiz_active


        // ====================================================================
        // VM Detection — CPUID-based hypervisor check
        // v2.1.3.09: FUNC_RVA = 0x23E7
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

            constexpr uint32_t FUNC_RVA = 0x23E7;
            constexpr uint8_t SIG16[] = {
                0x8D, 0x7D, 0xDC, 0x53, 0x0F, 0xA2, 0x8B, 0xF3,
                0x5B, 0x90, 0x89, 0x07, 0x89, 0x77, 0x04, 0x89
            };
            constexpr uint8_t SIG32[] = {
                0x8D, 0x7D, 0xDC, 0x53, 0x0F, 0xA2, 0x8B, 0xF3,
                0x5B, 0x90, 0x89, 0x07, 0x89, 0x77, 0x04, 0x89,
                0x4F, 0x08, 0x33, 0xC9, 0x89, 0x57, 0x0C, 0x8B,
                0x45, 0xDC, 0x8B, 0x7D, 0xE0, 0x89, 0x45, 0xF4
            };

            constexpr uint32_t CPUID_VENDOR   = 0x23EB;  // CPUID 0x40000000
            constexpr uint32_t CPUID_BRAND    = 0x2427;  // CPUID 0x40000001
            constexpr uint32_t CPUID_FEATURE  = 0x249F;  // CPUID 0x40000002
            constexpr uint32_t RDTSC_CHECK    = 0x2516;  // RDTSC timing check
        } // namespace vm_detection


        // ====================================================================
        // Anti-Debug — ICEBP instructions (opcode 0xF1)
        // ====================================================================
        namespace anti_debug {
            constexpr uint32_t ICEBP_1 = 0x94;    // Inside CLDBDoSomeOtherStuff
            constexpr uint32_t ICEBP_2 = 0x1F97;  // Mid-function trap
            constexpr uint32_t ICEBP_3 = 0x28C9;  // Before VM detection function

            constexpr uint8_t ICEBP_OPCODE = 0xF1;
            constexpr uint8_t NOP_OPCODE   = 0x90;

            // Containing function signatures for version-proof finding:
            // ICEBP_1: inside export CLDBDoSomeOtherStuff (+0x1000)
            // ICEBP_2: LDB+0x1F10 — SIG: 55 8B EC 8B 45 08 56 8B 48 3C 03 C8 0F B7 41 14
            // ICEBP_3: LDB+0x28AA — SIG: 55 8B EC FF 75 08 FF 15 48 E0 95 70 85 C0 74 11
        } // namespace anti_debug


        // ====================================================================
        // DLL Exports — called by LockDownBrowser.exe
        // Returns bitmask on v2.1.3.09; same signature on v2.1.5.00 but RVAs differ.
        // v2.1.5.00: CLDBDoSomeOtherStuff=0x1000, CLDBDoSomeOtherStuffs=0x10E0,
        //             CLDBDoSomeStuff=0x1110, CLDBDoYetMoreStuff=0x1330
        // ====================================================================
        namespace exports {
            enum class FunctionsV1 : uint32_t {  // v2.1.3.09
                CLDBDoSomeOtherStuff  = 0x1000,
                CLDBDoSomeOtherStuffs = 0x10B0,
                CLDBDoSomeStuff       = 0x10E0,
                CLDBDoYetMoreStuff    = 0x12A0,
            };

            enum class FunctionsV2 : uint32_t {  // v2.1.5.00
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
        // SetWindowsHookEx Call Sites — 21 total (v2.1.3.09)
        // v2.1.5.00: verify dynamically with IAT scan
        // ====================================================================
        namespace hook_callsites {
            constexpr uint32_t SETHOOK_CALL_0  = 0x100E;
            constexpr uint32_t SETHOOK_CALL_1  = 0x107B;
            constexpr uint32_t SETHOOK_CALL_2  = 0x1250;
            constexpr uint32_t SETHOOK_CALL_3  = 0x12AD;
            constexpr uint32_t SETHOOK_CALL_4  = 0x12DE;
            constexpr uint32_t SETHOOK_CALL_5  = 0x1396;
            constexpr uint32_t SETHOOK_CALL_6  = 0x1411;
            constexpr uint32_t SETHOOK_CALL_7  = 0x1500;
            constexpr uint32_t SETHOOK_CALL_8  = 0x15B7;
            constexpr uint32_t SETHOOK_CALL_9  = 0x1661;
            constexpr uint32_t SETHOOK_CALL_10 = 0x1746;
            constexpr uint32_t SETHOOK_CALL_11 = 0x1826;
            constexpr uint32_t SETHOOK_CALL_12 = 0x1857;
            constexpr uint32_t SETHOOK_CALL_13 = 0x18C0;
            constexpr uint32_t SETHOOK_CALL_14 = 0x18E8;
            constexpr uint32_t SETHOOK_CALL_15 = 0x1969;
            constexpr uint32_t SETHOOK_CALL_16 = 0x198F;
            constexpr uint32_t SETHOOK_CALL_17 = 0x19B8;
            constexpr uint32_t SETHOOK_CALL_18 = 0x1A59;
            constexpr uint32_t SETHOOK_CALL_19 = 0x1A7F;
            constexpr uint32_t SETHOOK_CALL_20 = 0x1AAD;
        } // namespace hook_callsites


        namespace hook_procedures {
            constexpr uint32_t KEYBOARD_HOOK_PROC = 0x13D0;
        } // namespace hook_procedures

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

        // User-Mode -> Kernel command codes (via FilterSendMessage)
        enum class CommandCode : uint32_t {
            PING              = 0x00000001,  // Heartbeat / status
            ADD_BLOCKLIST     = 0x00000010,  // Add process to blocklist
            REMOVE_BLOCKLIST  = 0x00000011,  // Remove process from blocklist
            QUERY_PROCESSES   = 0x00000012,  // Query tracked processes
            TERMINATE         = 0x00000013,  // Terminate a process by PID
            VERIFY_SIGNATURE  = 0x00000014,  // Validate binary signature
            ENCRYPT           = 0x00000020,  // AES-CBC encrypt
            DECRYPT           = 0x00000021,  // AES-CBC decrypt
            QUIZ_ACTIVE       = 0x00000030,  // Get/set quiz active state
            SET_HOOKS         = 0x00000031,  // Enable/disable hooks
            GET_STATUS        = 0x00000032,  // Get full status bitmask
            BLOCK_INPUT       = 0x00000033,  // Block specific input types
            BLACKLIST_WINDOW  = 0x00000040,  // Add window class to blacklist
            EXAM_URL          = 0x00000041,  // Register exam URL pattern
        };

        // Kernel -> User-Mode notification event types (via FltSendMessage)
        enum class NotifyEvent : uint32_t {
            PROCESS_CREATE        = 0x001,
            PROCESS_TERMINATE     = 0x002,
            THREAD_CREATE         = 0x003,
            IMAGE_LOAD            = 0x004,
            INTEGRITY_VIOLATION   = 0x005,
            TAMPER_DETECTED       = 0x006,
            DEBUGGER_DETECTED     = 0x007,
            BLOCKED_PROCESS       = 0x008,
            QUIZ_STATE_CHANGE     = 0x009,
            INPUT_VIOLATION       = 0x00A,
        };

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
    // Module: LockDownBrowser.exe (x64, ~20MB, Chromium 142 based)
    // v2.1.5.00: 20,669,376 bytes, no ASLR/DEP/CFG
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
        constexpr uint32_t EXPECTED_SIZE      = 62720;  // ~61KB
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
        }
    } // namespace driver_analysis


    // Convenience aliases
    namespace cldb     = lockdownbrowser_dll::cldb;
    namespace exports  = lockdownbrowser_dll::exports;
    namespace hooks    = lockdownbrowser_dll::hook_callsites;
    namespace kbproc   = lockdownbrowser_dll::hook_procedures;
    namespace lset     = lockdownbrowser_dll::cldb::setters_lockdown;
    namespace pset     = lockdownbrowser_dll::cldb::setters_proctoring;
    namespace eset     = lockdownbrowser_dll::cldb::setters_exit;
    namespace cread    = lockdownbrowser_dll::cldb::readers;
    namespace vmdet    = lockdownbrowser_dll::vm_detection;
    namespace adbg     = lockdownbrowser_dll::anti_debug;
    namespace quiz     = lockdownbrowser_dll::quiz_active;
    namespace rldb     = rldb_commands;
    namespace ioctl    = driver_ioctl;
    namespace drv      = driver_analysis;

} // namespace respondus_offsets
