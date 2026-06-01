#include <iostream>
#include <windows.h>
#include <vector>
#include "Inlinehook.h"
#include "MidHook.h"

using TargetFunc_t = int(__fastcall*)(int);
using FloatFunc_t = float(*)(float, float);

IHook* g_Hook1 = nullptr;
IHook* g_Hook2 = nullptr;
IHook* g_Hook3 = nullptr;

// -------------------------------------------------------------------------
// Proxy Interceptors (Standard Hooks)
// -------------------------------------------------------------------------
int __fastcall ProxyFunction1(int value) {
    std::cout << "  [Proxy 1] Intercepted! Calling original trampoline...\n";
    if (g_Hook1 && g_Hook1->GetOriginal()) {
        auto original = reinterpret_cast<TargetFunc_t>(g_Hook1->GetOriginal());
        return original(value);
    }
    return -1;
}

int __fastcall ProxyFunction2(int value) {
    std::cout << "  [Proxy 2] Intercepted! Calling original trampoline...\n";
    if (g_Hook2 && g_Hook2->GetOriginal()) {
        auto original = reinterpret_cast<TargetFunc_t>(g_Hook2->GetOriginal());
        return original(value);
    }
    return -1;
}

int __fastcall ProxyFunction3(int value) {
    std::cout << "  [Proxy 3] Intercepted! Calling original trampoline...\n";
    if (g_Hook3 && g_Hook3->GetOriginal()) {
        auto original = reinterpret_cast<TargetFunc_t>(g_Hook3->GetOriginal());
        return original(value);
    }
    return -1;
}

// -------------------------------------------------------------------------
// MidHook Interceptors (Context Manipulation)
// -------------------------------------------------------------------------
void __cdecl MidHookProxy(RegisterContext* regs) {
    std::cout << "  [MidHook Proxy] Intercepted Live Thread Context!\n";
    std::cout << "    RCX (Input Argument) : " << std::dec << regs->rcx << "\n";
    std::cout << "    RAX (Current State)  : 0x" << std::hex << std::uppercase << regs->rax << "\n";
    std::cout << "    RFLAGS               : 0x" << std::hex << std::uppercase << regs->rflags << "\n";

    // DEMONSTRATION: Modify the live register context dynamically!
    std::cout << "    -> Changing live RCX value from " << std::dec << regs->rcx << " to 100...\n";
    regs->rcx = 100;
}

void __cdecl FloatMidHookProxy(RegisterContext* regs) {
    std::cout << "  [Float MidHook Proxy] Intercepted Vector Context!\n";

    // Cast the lower 32-bits of the 128-bit XMM records to raw floats
    float* xmm0_ptr = reinterpret_cast<float*>(&regs->xmm0.low);
    float* xmm1_ptr = reinterpret_cast<float*>(&regs->xmm1.low);

    std::cout << "    XMM0 (Input Float 1) : " << *xmm0_ptr << "\n";
    std::cout << "    XMM1 (Input Float 2) : " << *xmm1_ptr << "\n";

    // DEMONSTRATION: Intercept the scalar multiplier and bump it on the fly
    std::cout << "    -> Changing live XMM1 value from " << *xmm1_ptr << " to 10.0...\n";
    *xmm1_ptr = 10.0f;
}

// -------------------------------------------------------------------------
// Helper Utility
// -------------------------------------------------------------------------
uintptr_t CreateExecutableTarget(const std::vector<uint8_t>& opcodes) {
    void* exec_mem = VirtualAlloc(NULL, opcodes.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!exec_mem) return 0;
    memcpy(exec_mem, opcodes.data(), opcodes.size());
    return reinterpret_cast<uintptr_t>(exec_mem);
}

int main() {
    std::cout << "==================================================\n";

    // -------------------------------------------------------------------------
    // TEST CASE 1: Short Conditional Jump Promotion (0x74 -> 0x0F 0x84)
    // -------------------------------------------------------------------------
    std::cout << "[TEST 1] Testing Short Conditional Jump Promotion (0x74)\n";

    std::vector<uint8_t> cond_jump_shellcode = {
        0x85, 0xC9,                   // 0: test ecx, ecx         (2 bytes)
        0x74, 0x12,                   // 2: jz +0x12 -> Target is 4 + 18 = Offset 22
        0x90, 0x90, 0x90, 0x90, 0x90, // 4-13: 10 NOPs to perfectly fulfill 14-byte hook window
        0x90, 0x90, 0x90, 0x90, 0x90,
        0x31, 0xC0,                   // 14: xor eax, eax         (2 bytes) -> Jump-back target!
        0xC3,                         // 16: ret                  (1 byte)
        0x90, 0x90, 0x90, 0x90, 0x90, // 17-21: Padding to map exactly to jump target offset
        0xB8, 0x02, 0x00, 0x00, 0x00, // 22: mov eax, 2           (5 bytes) -> Pristine target location
        0xC3,                         // 27: ret                  (1 byte)
        0x90, 0x90, 0x90, 0x90        // 28-31: Disassembler safety runway padding
    };

    uintptr_t target1_addr = CreateExecutableTarget(cond_jump_shellcode);
    TargetFunc_t Target1 = reinterpret_cast<TargetFunc_t>(target1_addr);

    g_Hook1 = new Inlinehook(target1_addr, reinterpret_cast<uintptr_t>(&ProxyFunction1));

    if (g_Hook1->Hook()) {
        std::cout << "  -> Hook applied successfully!\n";
        std::cout << std::dec;
        std::cout << "  Executing hooked function now...\n";
        std::cout << "  With Hook (input 0)   : " << Target1(0) << "\n";

        if (g_Hook1->Unhook())
            std::cout << "Unhooked successfully\n";
    }
    else {
        std::cout << "  !! Hook 1 failed to apply.\n";
    }
    delete g_Hook1;
    VirtualFree(reinterpret_cast<void*>(target1_addr), 0, MEM_RELEASE);

    std::cout << "--------------------------------------------------\n";

    // -------------------------------------------------------------------------
    // TEST CASE 2: Unconditional Short Jump Promotion (0xEB -> 0xE9)
    // -------------------------------------------------------------------------
    std::cout << "[TEST 2] Testing Unconditional Short Jump Promotion (0xEB)\n";

    std::vector<uint8_t> short_jmp_shellcode = {
        0x90, 0x90,                   // 0: NOPs                  (2 bytes)
        0xEB, 0x12,                   // 2: jmp +0x12 -> Target is 4 + 18 = Offset 22
        0x90, 0x90, 0x90, 0x90, 0x90, // 4-13: 10 NOPs to pad out 14-byte stolen size window
        0x90, 0x90, 0x90, 0x90, 0x90,
        0x31, 0xC0,                   // 14: xor eax, eax         (2 bytes)
        0xC3,                         // 16: ret                  (1 byte)
        0x90, 0x90, 0x90, 0x90, 0x90, // 17-21: Padding to map directly to target offset
        0xB8, 0x14, 0x00, 0x00, 0x00, // 22: mov eax, 20          (5 bytes) -> Pristine target location
        0xC3,                         // 27: ret                  (1 byte)
        0x90, 0x90, 0x90, 0x90        // 28-31: Runway padding
    };

    uintptr_t target2_addr = CreateExecutableTarget(short_jmp_shellcode);
    TargetFunc_t Target2 = reinterpret_cast<TargetFunc_t>(target2_addr);

    std::cout << "  Before Hook : " << Target2(0) << " (Expected: 20)\n";

    g_Hook2 = new Inlinehook(target2_addr, reinterpret_cast<uintptr_t>(&ProxyFunction2));

    if (g_Hook2->Hook()) {
        std::cout << "  -> Hook applied successfully!\n";
        std::cout << "  With Hook   : " << Target2(0) << " (Expected: 20)\n";

        if (g_Hook2->Unhook())
            std::cout << "Unhooked successfully\n";
    }
    else {
        std::cout << "  !! Hook 2 failed to apply.\n";
    }
    delete g_Hook2;
    VirtualFree(reinterpret_cast<void*>(target2_addr), 0, MEM_RELEASE);

    std::cout << "--------------------------------------------------\n";

    // -------------------------------------------------------------------------
    // TEST CASE 3: Near 32-bit Relative Jump Fix (0xE9 Displacement Adjustment)
    // -------------------------------------------------------------------------
    std::cout << "[TEST 3] Testing Near 32-bit Relative Jump Fix (0xE9)\n";

    std::vector<uint8_t> near_jmp_shellcode = {
        0xE9, 0x0B, 0x00, 0x00, 0x00, // 0: jmp near_label        (5 bytes) -> Target is 5 + 11 = Offset 16
        0x90, 0x90, 0x90, 0x90, 0x90, // 5-14: 10 NOPs to pad out stolen window to 15 bytes total
        0x90, 0x90, 0x90, 0x90, 0x90,
        0xC3,                         // 15: ret                  (1 byte)
        0xB8, 0x2A, 0x00, 0x00, 0x00, // 16: mov eax, 42          (5 bytes) -> Pristine target location
        0xC3,                         // 21: ret                  (1 byte)
        0x90, 0x90, 0x90, 0x90        // 22-25: Runway padding
    };

    uintptr_t target3_addr = CreateExecutableTarget(near_jmp_shellcode);
    TargetFunc_t Target3 = reinterpret_cast<TargetFunc_t>(target3_addr);

    std::cout << "  Before Hook : " << Target3(0) << " (Expected: 42)\n";

    g_Hook3 = new Inlinehook(target3_addr, reinterpret_cast<uintptr_t>(&ProxyFunction3));

    if (g_Hook3->Hook()) {
        std::cout << "  -> Hook applied successfully!\n";
        std::cout << "  With Hook   : " << Target3(0) << " (Expected: 42)\n";

        if (g_Hook3->Unhook())
            std::cout << "Unhooked successfully\n";
    }
    else {
        std::cout << "  !! Hook 3 failed to apply.\n";
    }
    delete g_Hook3;
    VirtualFree(reinterpret_cast<void*>(target3_addr), 0, MEM_RELEASE);

    std::cout << "==================================================\n";

    // -------------------------------------------------------------------------
    // TEST CASE 4: MidHook Context Interception & Register Manipulation
    // -------------------------------------------------------------------------
    std::cout << "[TEST 4] Testing MidHook Register Context Interception\n";

    std::vector<uint8_t> midhook_shellcode = {
        0x89, 0xC8,         // 0: mov eax, ecx         (2 bytes) -> Hook location
        0x6B, 0xC0, 0x05,   // 2: imul eax, eax, 5     (3 bytes) -> Stolen up to offset 5
        0xC3                // 5: ret                  (1 byte)
    };

    uintptr_t target4_addr = CreateExecutableTarget(midhook_shellcode);
    TargetFunc_t Target4 = reinterpret_cast<TargetFunc_t>(target4_addr);

    std::cout << "  Executing target before hook with input (2)...\n";
    std::cout << "  Before Hook : " << std::dec << Target4(2) << " (Expected: 10)\n\n";

    std::cout << "[x64dbg Debug Info]\n";
    std::cout << "  Target Function Address : 0x" << std::hex << std::uppercase << target4_addr << "\n";
    std::cout << "  MidHook Proxy Address   : 0x" << std::hex << std::uppercase << reinterpret_cast<uintptr_t>(&MidHookProxy) << "\n";

    std::cout << "[!] Press ENTER to execute the MidHook pipeline...\n";
    std::cin.get();

    MidHook* g_MidHook = new MidHook(target4_addr, reinterpret_cast<uintptr_t>(&MidHookProxy));

    if (g_MidHook->Hook()) {
        std::cout << "  -> MidHook applied successfully!\n\n";
        std::cout << "  Executing hooked function with input (2)...\n";
        int result = Target4(2);

        std::cout << "\n  Execution Returned from MidHook Framework!\n";
        std::cout << "  Final Return Value : " << std::dec << result << " (Expected: 500 if context modification succeeded)\n\n";

        if (g_MidHook->Unhook()) {
            std::cout << "  MidHook removed successfully.\n";
            std::cout << "  Executing post-unhook with input (2): " << Target4(2) << " (Expected: 10)\n";
        }
    }
    else {
        std::cout << "  !! MidHook failed to apply.\n";
    }

    delete g_MidHook;
    VirtualFree(reinterpret_cast<void*>(target4_addr), 0, MEM_RELEASE);

    std::cout << "==================================================\n";

    // -------------------------------------------------------------------------
    // TEST CASE 5: MidHook Vector Context Interception & XMM Manipulation
    // -------------------------------------------------------------------------
    std::cout << "[TEST 5] Testing MidHook Floating-Point (XMM) Context Interception\n";

    std::vector<uint8_t> float_shellcode = {
        0xF3, 0x0F, 0x10, 0xD0, // 0: movss xmm2, xmm0 (4 bytes) -> Hook location
        0xF3, 0x0F, 0x59, 0xC1, // 4: mulss xmm0, xmm1 (4 bytes) -> Total 8 bytes stolen
        0xC3                    // 8: ret              (1 byte)
    };

    uintptr_t target5_addr = CreateExecutableTarget(float_shellcode);
    FloatFunc_t Target5 = reinterpret_cast<FloatFunc_t>(target5_addr);

    std::cout << "  Executing target before hook with inputs (5.0, 3.0)...\n";
    std::cout << "  Before Hook : " << Target5(5.0f, 3.0f) << " (Expected: 15.0)\n\n";

    std::cout << "[x64dbg Debug Info]\n";
    std::cout << "  Target Float Address    : 0x" << std::hex << std::uppercase << target5_addr << "\n";
    std::cout << "  Float Proxy Address     : 0x" << std::hex << std::uppercase << reinterpret_cast<uintptr_t>(&FloatMidHookProxy) << "\n";

    std::cout << "[!] Press ENTER to execute the Float MidHook pipeline...\n";
    std::cin.get();

    MidHook* g_FloatMidHook = new MidHook(target5_addr, reinterpret_cast<uintptr_t>(&FloatMidHookProxy));

    if (g_FloatMidHook->Hook()) {
        std::cout << "  -> Float MidHook applied successfully!\n\n";
        std::cout << "  Executing hooked float function with inputs (5.0, 3.0)...\n";
        float float_result = Target5(5.0f, 3.0f);

        std::cout << "\n  Execution Returned from Float MidHook Framework!\n";
        // Input A (5.0f) * Modified Input B (10.0f) = 50.0f
        std::cout << "  Final Return Value : " << float_result << " (Expected: 50.0 if XMM modification succeeded)\n\n";

        if (g_FloatMidHook->Unhook()) {
            std::cout << "  Float MidHook removed successfully.\n";
            std::cout << "  Executing post-unhook with inputs (5.0, 3.0): " << Target5(5.0f, 3.0f) << " (Expected: 15.0)\n";
        }
    }
    else {
        std::cout << "  !! Float MidHook failed to apply.\n";
    }

    delete g_FloatMidHook;
    VirtualFree(reinterpret_cast<void*>(target5_addr), 0, MEM_RELEASE);

    std::cout << "==================================================\n";
    system("pause");
    return 0;
}

