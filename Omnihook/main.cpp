#include <iostream>
#include <windows.h>
#include <iomanip>

#include "VMTHooks.h" // Your updated VMTHook header

// -------------------------------------------------------------------------
// Multiple Inheritance Base Interfaces
// -------------------------------------------------------------------------
class IBaseRenderable {
public:
    virtual void Draw() = 0;
    virtual void Resize(int width, int height) = 0;
};

class IBaseEntity {
public:
    virtual void Update(float deltaTime) = 0;
    virtual void TakeDamage(int amount) = 0;
};

class IBaseNetworked {
public:
    virtual void Serialize() = 0;
};

// -------------------------------------------------------------------------
// The Target Dummy Class
// This layout produces exactly 3 sequential vtable pointers (vptrs)
// followed by standard primitive member data.
// -------------------------------------------------------------------------
class DummyEntity : public IBaseRenderable, public IBaseEntity, public IBaseNetworked {
public:
    // Simulated class members for ReClass alignment verification
    int m_health = 100;
    int m_shield = 50;
    float m_posX = 142.5f;
    float m_posY = 512.8f;

    // IBaseRenderable Implementations (VTable 0)
    void Draw() override {
        std::cout << "  [Original Draw] Rendering entity model.\n";
    }
    void Resize(int width, int height) override {
        std::cout << "  [Original Resize] Resolution changed to: " << width << "x" << height << "\n";
    }

    // IBaseEntity Implementations (VTable 1 - Offset +0x08)
    void Update(float deltaTime) override {
        std::cout << "  [Original Update] Ticking physics loop with dt: " << deltaTime << "\n";
    }
    void TakeDamage(int amount) override {
        m_health -= amount;
        std::cout << "  [Original TakeDamage] Lost " << amount << " HP. Current Health: " << m_health << "\n";
    }

    // IBaseNetworked Implementations (VTable 2 - Offset +0x10)
    void Serialize() override {
        std::cout << "  [Original Serialize] Compressing net delta updates.\n";
    }
};

// -------------------------------------------------------------------------
// Hook Proxies (Interceptors)
// -------------------------------------------------------------------------
typedef void(__fastcall* tUpdateFn)(void* pThis, float deltaTime);
tUpdateFn oUpdate = nullptr;

void __fastcall hkUpdate(void* pThis, float deltaTime) {
    std::cout << "  [Hooked Update] Intercepted! Boosting deltaTime matrix...\n";

    // Call original through your engine's trampoline tracking
    if (oUpdate) {
        oUpdate(pThis, deltaTime * 2.0f);
    }
}

// -------------------------------------------------------------------------
// Main Testing Pipeline
// -------------------------------------------------------------------------
int main() {
    std::cout << "==================================================\n";
    std::cout << "        VMT MULTIPLE INHERITANCE TEST BENCH       \n";
    std::cout << "==================================================\n\n";

    // Instantiate the dummy object on the heap
    DummyEntity* pEntity = new DummyEntity();

    // Output critical pointers for your ReClass setup
    std::cout << "[ReClass.NET Connection Info]\n";
    std::cout << "  Class Instance Address : 0x" << std::hex << std::uppercase << reinterpret_cast<uintptr_t>(pEntity) << "\n\n";

    std::cout << "[Expected Memory Offsets]\n";
    std::cout << "  +0x00 : vptr -> IBaseRenderable VTable\n";
    std::cout << "  +0x08 : vptr -> IBaseEntity VTable\n";
    std::cout << "  +0x10 : vptr -> IBaseNetworked VTable\n";
    std::cout << "  +0x18 : int  -> m_health (" << std::dec << pEntity->m_health << ")\n";
    std::cout << "  +0x1C : int  -> m_shield (" << pEntity->m_shield << ")\n\n";

    std::cout << "[*] Open ReClass, attach to this process, and map out the offsets.\n";
    std::cout << "[!] Press ENTER inside this console to run the VMTHook test code...\n";
    std::cin.get();

    // -------------------------------------------------------------------------
    // Executing the VMT Hooking Engine Test
    // -------------------------------------------------------------------------
    std::cout << "Executing initial function calls before hook:\n";
    pEntity->Update(0.016f);
    std::cout << "\n";

    // Target the IBaseEntity vptr slot directly (offset +0x08 from object base)
    uintptr_t* pObjectFields = reinterpret_cast<uintptr_t*>(pEntity);
    void* pIBaseEntitySlot = &pObjectFields[1]; // Index 1 = Offset +0x08

    std::cout << "[*] Applying Shadow VMT Hook to IBaseEntity::Update (Index 0)...\n";

    // We pass the explicit pointer to the +0x08 slot as the object instance
    VMTHook* entityHook = new VMTHook(pIBaseEntitySlot, 0, reinterpret_cast<void*>(&hkUpdate), HookType::Default);

    if (entityHook->Hook()) {
        std::cout << "  -> Shadow Hook successfully installed!\n";
        oUpdate = reinterpret_cast<tUpdateFn>(entityHook->GetOriginal());

        std::cout << "  -> Look at ReClass offset +0x08. It now points to your heap allocation!\n\n";

        std::cout << "Executing function call with active hook:\n";
        pEntity->Update(0.016f);
        std::cout << "\n";

        std::cout << "[!] Press ENTER to trigger Unhook routines...\n";
        std::cin.get();

        if (entityHook->Unhook()) {
            std::cout << "  -> Hook removed cleanly. Object table restored.\n\n";

            std::cout << "Executing function call after unhook:\n";
            pEntity->Update(0.016f);
        }
    }
    else {
        std::cout << "  !! Failed to apply VMT Hook.\n";
    }


    std::cout << "\n==================================================\n";
    system("pause");

    // Cleanup allocations
    delete entityHook;
    delete pEntity;

    return 0;
}