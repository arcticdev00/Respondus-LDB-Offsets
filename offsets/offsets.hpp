#pragma once

#include <cstddef>
#include <cstdint>

// ============================================================================
// Respondus LockDown Browser — Offsets & Signature Patterns
// Version: 2.1.3.09 (CLDB 2.1.3.09; Chrome/129.0.0.0)
// Generated: 2026-05-16
// From Arctic 
// ============================================================================

namespace respondus_offsets {

    // ========================================================================
    // Module: LockDownBrowser.dll (LDB.dll)
    // 32-bit DLL, loaded by LockDownBrowser.exe
    // PE sections: .text(+0x1000) .rdata(+0xE000) .data(+0x15000)
    //              .cldb(+0x17000) .rsrc(+0x18000) .reloc(+0x19000)
    // ========================================================================
    namespace lockdownbrowser_dll {

        // ====================================================================
        // .cldb Shared Memory Section (SHARED|WRITE|READ)
        // 12 bytes of runtime flags. Write 12 zero bytes to disable all.
        // Find dynamically by walking PE sections for ".cldb" name.
        // ====================================================================
        namespace cldb {

            // --- Static offsets (relative to LDB.dll base, v2.1.3.09) ---
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

            // ================================================================
            // .cldb Flag Setters (write 1 → activate lockdown)
            // NOP these to permanently disable lockdown enforcement.
            // All locations are RVAs relative to LDB.dll base.
            // ================================================================

            // LOCKDOWN setters (write to .cldb+0x00)
            namespace setters_lockdown {
                constexpr uint32_t SETTER_ECX_1 = 0x1016;  // 89 0D [cldb+0x00], ECX
                constexpr uint32_t SETTER_ECX_2 = 0x1083;  // 89 0D [cldb+0x00], ECX
                constexpr uint32_t SETTER_EDI = 0x125E;  // 89 3D [cldb+0x00], EDI

                // Sigscan: 89 0D ?? ?? ?? ?? | 89 3D ?? ?? ?? ??
                // Resolve disp32; if target == .cldb+0x00 → LOCKDOWN setter
                // Patch: 6 bytes of 0x90 (NOP)
            }

            // PROCTORING setter (writes to .cldb+0x04)
            namespace setters_proctoring {
                constexpr uint32_t SETTER_EDI = 0x1270;  // 89 3D [cldb+0x04], EDI

                // Sigscan: 89 3D ?? ?? ?? ??
                // Resolve disp32; if target == .cldb+0x04 → PROCTORING setter
                // Patch: 6 bytes of 0x90 (NOP)
            }

            // EXIT setters (write to .cldb+0x08)
            namespace setters_exit {
                constexpr uint32_t SETTER_ECX_1 = 0x11D9;  // 89 0D [cldb+0x08], ECX
                constexpr uint32_t SETTER_EDI = 0x1282;  // 89 3D [cldb+0x08], EDI
                constexpr uint32_t SETTER_ECX_2 = 0x12EA;  // 89 0D [cldb+0x08], ECX
                constexpr uint32_t CLEARER = 0x12B3;  // C7 05 [cldb+0x08], 0x00000000

                // Sigscan: 89 0D ?? ?? ?? ?? | 89 3D ?? ?? ?? ??
                // Resolve disp32; if target == .cldb+0x08 → EXIT setter
                // Patch setters: 6 bytes of 0x90 (NOP)
                // Note: CLEARER writes 0 — don't patch unless you want to prevent exit clearing
            }

            // .cldb flag readers (informational — no patching needed)
            namespace readers {
                constexpr uint32_t READ_LOCKDOWN_1 = 0x120F;  // A1 [cldb+0x00]
                constexpr uint32_t READ_LOCKDOWN_2 = 0x1256;  // A1 [cldb+0x00]
                constexpr uint32_t READ_PROCTORING = 0x1264;  // A1 [cldb+0x04]
                constexpr uint32_t READ_EXIT_1 = 0x1276;  // A1 [cldb+0x08]
                constexpr uint32_t READ_EXIT_2 = 0x12A3;  // A1 [cldb+0x08]

                // Sigscan: A1 ?? ?? ?? ?? (MOV EAX, [disp32])
                // Resolve disp32; if target in .cldb range → flag reader
            }

            // Version-proof sigscan method:
            // 1. Parse LDB.dll PE → find .cldb section VirtualAddress
            // 2. cldb_runtime = ldb_base + VirtualAddress
            // 3. Scan .text for: 89 0D | 89 3D | 89 05 | C7 05 | A1
            // 4. For each: resolve disp32 → if target in [cldb_runtime, cldb_runtime+12]
            //    → it's a .cldb access. opcode tells you read vs write.

        } // namespace cldb


        // ====================================================================
        // VM Detection — CPUID-based hypervisor check
        // Located in LDB.dll .text section
        // Contains 3 CPUID calls checking hypervisor vendor/brand/features
        // Also contains RDTSC timing checks and ICEBP anti-debug traps
        // ====================================================================
        namespace vm_detection {

            // CPUID hypervisor leaf output structure
            struct CpuidHypervisorOutput {
                uint32_t eax;
                uint32_t ebx;  // Vendor string part 1
                uint32_t ecx;  // Vendor string part 2
                uint32_t edx;  // Vendor string part 3
            };

            // Known hypervisor signatures checked by this function
            enum class HypervisorSignature : uint32_t {
                VMWARE = 0x6000601,  // "VMwareVMware"
                MICROSOFT_HV = 0x6000602, // "Microsoft Hv"
                XEN = 0x6000603,  // "XenVMMXenVMM"
                KVM = 0x6000603,  // "KVMKVMKVM" 
            };

            // Signature pattern from first CPUID cluster:
            // LEA EDI,[EBP-0x24]; PUSH EBX; CPUID; MOV ESI,EBX; POP EBX; NOP
            constexpr uint32_t FUNC_RVA = 0x23E7;

            // Unique byte pattern (16 bytes) 
            constexpr uint8_t SIG16[] = {
                0x8D, 0x7D, 0xDC, 0x53, 0x0F, 0xA2, 0x8B, 0xF3,
                0x5B, 0x90, 0x89, 0x07, 0x89, 0x77, 0x04, 0x89
            };

            // Extended pattern (32 bytes)
            constexpr uint8_t SIG32[] = {
                0x8D, 0x7D, 0xDC, 0x53, 0x0F, 0xA2, 0x8B, 0xF3,
                0x5B, 0x90, 0x89, 0x07, 0x89, 0x77, 0x04, 0x89,
                0x4F, 0x08, 0x33, 0xC9, 0x89, 0x57, 0x0C, 0x8B,
                0x45, 0xDC, 0x8B, 0x7D, 0xE0, 0x89, 0x45, 0xF4
            };

            // Individual CPUID instruction locations 
            constexpr uint32_t CPUID_VENDOR = 0x23EB;  // CPUID 0x40000000 — vendor string
            constexpr uint32_t CPUID_BRAND = 0x2427;  // CPUID 0x40000001 — brand/version
            constexpr uint32_t CPUID_FEATURE = 0x249F;  // CPUID 0x40000002 — features

            // RDTSC timing check (anti-VM via instruction timing analysis)
            constexpr uint32_t RDTSC_CHECK = 0x2516;  // RDTSC before timing comparison
        } // namespace vm_detection


        // ====================================================================
        // Anti-Debug — ICEBP instructions (opcode 0xF1)
        // Scattered throughout LDB.dll .text as debugger traps
        // Also 17,000+ instances in EXE
        // ====================================================================
        namespace anti_debug {

            // Sample ICEBP locations in LDB.dll (verified)
            constexpr uint32_t ICEBP_1 = 0x94;    // Inside CLDBDoSomeOtherStuff export
            constexpr uint32_t ICEBP_2 = 0x1F97;  // Mid-function trap
            constexpr uint32_t ICEBP_3 = 0x28C9;  // Before VM detection function

            // Opcodes
            constexpr uint8_t ICEBP_OPCODE = 0xF1;  // ICEBP (Ice Breakpoint)
            constexpr uint8_t NOP_OPCODE = 0x90;  // NOP replacement

            // Containing function signatures for version-proof finding:
            // ICEBP_1: inside export CLDBDoSomeOtherStuff (+0x1000)
            // ICEBP_2: LDB+0x1F10 — SIG: 55 8B EC 8B 45 08 56 8B 48 3C 03 C8 0F B7 41 14
            // ICEBP_3: LDB+0x28AA — SIG: 55 8B EC FF 75 08 FF 15 48 E0 95 70 85 C0 74 11

            // To find all ICEBP: scan .text for byte 0xF1, replace with 0x90

        } // namespace anti_debug


        // ====================================================================
        // DLL Exports — called by LockDownBrowser.exe to activate lockdown
        // All return 0 on success.
        // ====================================================================
        namespace exports {

            enum class Functions : uint32_t {
                CLDBDoSomeOtherStuff = 0x1000,  // Main lockdown init + flag setter
                CLDBDoSomeOtherStuffs = 0x10B0,  // Status reporter (returns bitmask)
                CLDBDoSomeStuff = 0x10E0,  // URL/navigation handler
                CLDBDoYetMoreStuff = 0x12A0,  // EXIT flag handler + clearer
            };

            // Export function status bitmask (returned by CLDBDoSomeOtherStuffs)
            enum class StatusFlags : uint32_t {
                LOCKDOWN_ACTIVE = 0x400,   // LOCKDOWN flag is set
                PROCTORING_ACTIVE = 0x1000,  // PROCTORING flag is set
                EXIT_ACTIVE = 0x800,   // EXIT flag is set
            };

            // Sigscan: "?CLDBDo" string prefix in .rdata export name table
            // Pattern bytes: 3F 43 4C 44 42 44 6F ("?CLDBDo")
            // Walk export directory → match name → resolve ordinal → get RVA

        } // namespace exports


        // ====================================================================
        // SetWindowsHookEx Call Sites — 21 total
        // NOP to prevent keyboard hook installation.
        // Sigscan: FF 15 ?? ?? ?? ?? → resolve IAT → check if user32!SetWindowsHookEx
        // ====================================================================
        namespace hook_callsites {
            constexpr uint32_t SETHOOK_CALL_0 = 0x100E;
            constexpr uint32_t SETHOOK_CALL_1 = 0x107B;
            constexpr uint32_t SETHOOK_CALL_2 = 0x1250;
            constexpr uint32_t SETHOOK_CALL_3 = 0x12AD;
            constexpr uint32_t SETHOOK_CALL_4 = 0x12DE;
            constexpr uint32_t SETHOOK_CALL_5 = 0x1396;
            constexpr uint32_t SETHOOK_CALL_6 = 0x1411;
            constexpr uint32_t SETHOOK_CALL_7 = 0x1500;
            constexpr uint32_t SETHOOK_CALL_8 = 0x15B7;
            constexpr uint32_t SETHOOK_CALL_9 = 0x1661;
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



        // ====================================================================
        // Keyboard Hook Callback Procedure
        // NOP the callback to intercept keystrokes without blocking them.
        // Sigscan: PUSH imm32 before SetWindowsHookEx CALL → imm32 = proc RVA
        // ====================================================================
        namespace hook_procedures {
            constexpr uint32_t KEYBOARD_HOOK_PROC = 0x13D0;
        } // namespace hook_procedures

    } // namespace lockdownbrowser_dll


    // ========================================================================
    // Module: LockDownBrowser.exe (32-bit, ~14MB, Chromium 129 based)
    // 19 code regions. Respondus code in early regions (+0x0 to +0x1D2000).
    // No .cldb accesses found in EXE — all flag manipulation is in LDB.dll.
    // ========================================================================
    namespace lockdownbrowser_exe {

        // Window class blacklist (checked via EnumWindows/FindWindowW)
        namespace window_blacklist {
            constexpr wchar_t CHROME_WIDGETWIN_1[] = L"Chrome_WidgetWin_1";
            constexpr wchar_t CHROME_WIDGETWIN_0[] = L"Chrome_WidgetWin_0";
            constexpr wchar_t MOZILLA_WINDOW_CLASS[] = L"MozillaWindowClass";
            constexpr wchar_t MOZILLA_COMPOSITOR_CLASS[] = L"MozillaCompositorWindowClass";
        }

        // Process blacklist: 3020 entries, heap-allocated at runtime
        // No static RVAs. Scan memory for UTF-16LE strings at runtime.
        namespace process_blacklist {
            // see process_blacklist.hpp
        }

    } // namespace lockdownbrowser_exe


    // Convenience aliases
    namespace cldb = lockdownbrowser_dll::cldb;
    namespace exports = lockdownbrowser_dll::exports;
    namespace hooks = lockdownbrowser_dll::hook_callsites;
    namespace kbproc = lockdownbrowser_dll::hook_procedures;
    namespace lset = lockdownbrowser_dll::cldb::setters_lockdown;
    namespace pset = lockdownbrowser_dll::cldb::setters_proctoring;
    namespace eset = lockdownbrowser_dll::cldb::setters_exit;
    namespace cread = lockdownbrowser_dll::cldb::readers;
    namespace vmdet = lockdownbrowser_dll::vm_detection;
    namespace adbg = lockdownbrowser_dll::anti_debug;

} // namespace respondus_offsets
