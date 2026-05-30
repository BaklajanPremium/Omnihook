#include <Windows.h>
#include <iostream>
#include "Omnihook.h"

int Add(int a, int b) { return a + b; }

int MyProxy(int a, int b) { return 69; }

int main() {
    Inlinehook hook((uintptr_t)Add, (uintptr_t)MyProxy);


    IHook* p = &hook;
    std::cout << Add(2, 3) << "\n"; // before
    hook.Hook();
    std::cout << Add(2, 3) << "\n"; // proxy should fire
    hook.Unhook();
    std::cout << Add(2, 3) << "\n"; // should be normal again
}