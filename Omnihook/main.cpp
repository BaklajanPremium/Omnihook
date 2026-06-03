#include <iostream>
#include <windows.h>
#include <thread>
#include <vector>
#include "HWBPHook.h" // Your updated Hardware Breakpoint Hook header

// -------------------------------------------------------------------------
// Target Function to Hook
// -------------------------------------------------------------------------
// __declspec(noinline) ensures the compiler doesn't optimize this function out
// by embedding it directly inside the calling loops.
__declspec(noinline) void CriticalFunction(int threadId, int actionCount) {
    std::cout << "    [Original] Executing core logic for Thread " << threadId
        << " (Action #" << actionCount << ")\n";
}

// -------------------------------------------------------------------------
// Hook Proxy & Type Definitions
// -------------------------------------------------------------------------
typedef void(*tCriticalFn)(int, int);
tCriticalFn oCriticalFunction = nullptr;

void hkCriticalFunction(int threadId, int actionCount) {
    // Collect the current thread executing this proxy block
    DWORD currentThreadId = GetCurrentThreadId();

    std::cout << "  [Hooked Proxy] Intercepted call on OS Thread ID: " << currentThreadId << "\n";
    std::cout << "                 Intercepted Arguments -> Thread Ref: " << threadId
        << ", Count: " << actionCount << "\n";

    // Modifying intercepted argument payload to prove data mutation control
    int modifiedCount = actionCount + 1000;

    {
        // Leverage your RAII Scoped Guard to safely arm the TLS bypass flag
        HWBPHook::ScopedBypass guard;

        // Invoke the original function pointer seamlessly
        oCriticalFunction(threadId, modifiedCount);
    }
    // Guard falls out of scope here: m_bypass_flag is guaranteed to reset to false
}

// -------------------------------------------------------------------------
// Multi-Threaded Worker Function
// -------------------------------------------------------------------------
void WorkerLoop(int virtualThreadId, bool& runFlag) {
    int counter = 0;
    while (runFlag) {
        CriticalFunction(virtualThreadId, ++counter);
        std::this_thread::sleep_for(std::chrono::milliseconds(400));
    }
}

// -------------------------------------------------------------------------
// Main Pipeline Execution
// -------------------------------------------------------------------------
int main() {
    std::cout << "==================================================\n";
    std::cout << "       HWBP ENGINE MULTI-THREAD TEST BENCH        \n";
    std::cout << "==================================================\n\n";

    // Set up original pointer fallback reference
    oCriticalFunction = reinterpret_cast<tCriticalFn>(&CriticalFunction);

    std::cout << "[*] Executing original function call naked:\n";
    CriticalFunction(0, 1);
    std::cout << "\n";

    // Initialize your HWBP Hook instance
    uintptr_t targetAddress = reinterpret_cast<uintptr_t>(&CriticalFunction);
    uintptr_t proxyAddress = reinterpret_cast<uintptr_t>(&hkCriticalFunction);

    HWBPHook* hwbp = new HWBPHook(targetAddress, proxyAddress);

    std::cout << "[*] Initializing execution worker threads...\n";
    bool keepRunning = true;

    // Spawn two distinct workers running concurrently on separate OS timelines
    std::thread worker1(WorkerLoop, 1, std::ref(keepRunning));
    std::thread worker2(WorkerLoop, 2, std::ref(keepRunning));

    // Allow them to stream a couple normal runs to the console output window
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    std::cout << "\n[!] Press ENTER inside this console to globally apply the HWBP Hook...\n";
    std::cin.get();

    std::cout << "[*] Committing hardware breakpoint to CPU debug registers...\n";
    if (hwbp->Hook()) {
        std::cout << "  -> Hardware breakpoint successfully initialized process-wide!\n";
        std::cout << "  -> Assigned Slot: DR" << static_cast<int>(hwbp->GetOriginal()) << "\n\n";

        std::cout << "[*] Monitoring concurrent worker execution stream (Look at altered argument counts):\n";
        std::this_thread::sleep_for(std::chrono::seconds(2));

        std::cout << "\n[!] Press ENTER to trigger Unhook routines...\n";
        std::cin.get();

        std::cout << "[*] Restoring thread debug contexts...\n";
        if (hwbp->Unhook()) {
            std::cout << "  -> Hook removed cleanly. All DRx lines wiped.\n\n";

            std::cout << "[*] Monitoring post-unhook execution stream:\n";
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        else {
            std::cout << "  !! Failed to strip HWBP configuration.\n";
        }
    }
    else {
        std::cout << "  !! Failed to apply process-wide hardware breakpoint.\n";
    }

    // Shut down worker background loops gracefully
    std::cout << "\n[*] Terminating worker threads...\n";
    keepRunning = false;

    if (worker1.joinable()) worker1.join();
    if (worker2.joinable()) worker2.join();

    std::cout << "==================================================\n";

    delete hwbp;
    return 0;
}