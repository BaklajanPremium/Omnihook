# Omnihook

Omnihook is a lightweight, versatile x64 function hooking library for Windows. It provides several ways to intercept execution, from standard inline hooking to register-level mid-function hooks.

It uses **Zydis** internally to decode and relocate instructions when placing hooks.

## Features

* **Inline Hooking**: Standard detour hooks that patch the prologue. Relocates overwritten instructions safely using a disassembler.
* **Mid-Function Hooking**: Hook arbitrary instructions inside a function body. Passes a full `RegisterContext` (including RAX-R15, EFLAGS, and YMM0-YMM15) to a callback, letting you read/write registers before resuming.
* **Hardware Breakpoints**: Hooks execution using CPU debug registers (`DR0` - `DR3`) and a Vectored Exception Handler (VEH).
* **VMT (Virtual Method Table) Hooking**: Hooks virtual methods of an object instance. Supports direct vtable replacement and shadow vtable copying.

---

## API & Usage

All functions are available under the `Omnihook` namespace.

### 1. Inline Hooking
Replaces the beginning of a function with a jump to your detour.

```cpp
#include "Omnihook.h"
#include <iostream>

typedef int(__fastcall* tMessageBoxA)(HWND, LPCSTR, LPCSTR, UINT);
tMessageBoxA oMessageBoxA = nullptr;

int __fastcall hkMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
    std::cout << "Intercepted MessageBoxA!" << std::endl;
    return oMessageBoxA(hWnd, "Hooked!", lpCaption, uType);
}

void Setup() {
    auto status = Omnihook::CreateInlineHook(
        &MessageBoxA, 
        &hkMessageBoxA, 
        reinterpret_cast<void**>(&oMessageBoxA)
    );

    if (status == Omnihook::Status::Success) {
        if (Omnihook::EnableHook(&MessageBoxA) == Omnihook::Status::Success) {
            std::cout << "Successfully hooked MessageBoxA!" << std::endl;
        }
    }
}
```

### 2. Mid-Function Hooking
Intercepts execution in the middle of a function, giving you full control over the CPU registers.

```cpp
#include "Omnihook.h"
#include <iostream>

void MyMidHookCallback(Omnihook::RegisterContext* regs) {
    // Read registers
    std::cout << "RAX: 0x" << std::hex << regs->rax << std::endl;
    
    // Modify registers if needed
    regs->rax = 0x1337;
}

void Setup() {
    void* targetAddress = ...; // Address inside function body
    
    auto status = Omnihook::CreateMidHook(targetAddress, &MyMidHookCallback);
    if (status == Omnihook::Status::Success) {
        if (Omnihook::EnableHook(targetAddress) == Omnihook::Status::Success) {
            std::cout << "Mid-hook successfully enabled!" << std::endl;
        }
    }
}
```

### 3. Hardware Breakpoints
Set a breakpoint at a specific address without modifying any code bytes.

```cpp
#include "Omnihook.h"

void __fastcall hkTargetFunction() {
    // Note: Control flow redirections using HWBP will jump directly here
}

void Setup() {
    void* targetAddress = ...;
    
    auto status = Omnihook::CreateHWBPHook(targetAddress, &hkTargetFunction);
    if (status == Omnihook::Status::Success) {
        if (Omnihook::EnableHook(targetAddress) == Omnihook::Status::Success) {
            std::cout << "Hardware breakpoint hook successfully enabled!" << std::endl;
        }
    }
}
```

### 4. VMT Hooking
Redirect virtual functions on an object instance.

```cpp
#include "Omnihook.h"

// Original virtual function detour signature
typedef void(* tVirtualFunc)(void*);

void Setup(void* objectInstance) {
    void* detourFunc = ...;
    int vtableIndex = 2; // Index of the function in the vtable

    // HookType::Default (Direct replacement) or HookType::Shadow (Copy vtable)
    auto status = Omnihook::CreateVMTHook(objectInstance, detourFunc, vtableIndex, Omnihook::HookType::Shadow);
    if (status == Omnihook::Status::Success) {
        if (Omnihook::EnableHook(objectInstance) == Omnihook::Status::Success) {
            std::cout << "VMT hook successfully enabled!" << std::endl;
        }
    }
}
```

### Hook Lifecycle Management

```cpp
// Enable/Disable individual hooks by their target address
Omnihook::EnableHook(targetAddress);
Omnihook::DisableHook(targetAddress);

// Completely remove a hook
Omnihook::RemoveHook(targetAddress);

// Clean up all hooks (recommended on DLL unload)
Omnihook::RemoveAll();
```

---

## Building

Omnihook is designed for **x64 Windows** targets.

1. Open `Omnihook.slnx` or load `Omnihook.vcxproj` in Visual Studio (2026 recommended).
2. Configure your build (Debug/Release, x64).
3. Build the solution. The project compiles to a static library (`.lib`).
