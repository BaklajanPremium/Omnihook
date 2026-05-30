#include <iostream>
#include <windows.h>
#include <vector>
#include "Inlinehook.h"

using TargetFunc_t = int(__fastcall*)(int);

IHook* g_Hook1 = nullptr;
IHook* g_Hook2 = nullptr;
IHook* g_Hook3 = nullptr;

// -------------------------------------------------------------------------
// Proxy Interceptors
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
    std::cout << std::hex << target1_addr << std::endl;
    TargetFunc_t Target1 = reinterpret_cast<TargetFunc_t>(target1_addr);

    std::cout << "\n[x64dbg Debug Info]\n";
    std::cout << "  Target Function Address : 0x" << std::hex << std::uppercase << target1_addr << "\n";
    std::cout << "  Proxy Interceptor Addr  : 0x" << std::hex << std::uppercase << reinterpret_cast<uintptr_t>(&ProxyFunction1) << "\n";

    g_Hook1 = new Inlinehook(target1_addr, reinterpret_cast<uintptr_t>(&ProxyFunction1));

    if (g_Hook1->Hook()) {
        std::cout << "  Trampoline Address      : 0x" << std::hex << std::uppercase << g_Hook1->GetOriginal() << "\n\n";
        std::cout << "  -> Hook applied successfully!\n";

        // 2. CRITICAL PAUSE: Halt execution so you can attach x64dbg
        std::cout << "[!] Press ENTER here to execute...\n";
        std::cin.get();

        std::cout << std::dec;

        std::cout << "  Executing hooked function now...\n";
        std::cout << "  With Hook (input 0)   : " << Target1(0) << "\n";

        g_Hook1->Unhook();
        std::cin.get();
        std::cin.get();

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

        g_Hook2->Unhook();
        std::cout << "  -> Unhooked cleanly.\n";
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

        g_Hook3->Unhook();
        std::cout << "  -> Unhooked cleanly.\n";
    }
    else {
        std::cout << "  !! Hook 3 failed to apply.\n";
    }
    delete g_Hook3;
    VirtualFree(reinterpret_cast<void*>(target3_addr), 0, MEM_RELEASE);

    std::cout << "==================================================\n";
    system("pause");
    return 0;
}