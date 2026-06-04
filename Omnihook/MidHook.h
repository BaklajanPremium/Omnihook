#pragma once
#include <unordered_map>
#include "IHook.h"


#pragma pack(push, 1)
struct YMMRegister {
    uint64_t qwords[4];
};


struct RegisterContext {
    YMMRegister ymm0;
    YMMRegister ymm1;
    YMMRegister ymm2;
    YMMRegister ymm3;
    YMMRegister ymm4;
    YMMRegister ymm5;
    YMMRegister ymm6;
    YMMRegister ymm7;
    YMMRegister ymm8;
    YMMRegister ymm9;
    YMMRegister ymm10;
    YMMRegister ymm11;
    YMMRegister ymm12;
    YMMRegister ymm13;
    YMMRegister ymm14;
    YMMRegister ymm15;

    uint64_t r15;
    uint64_t r14;
    uint64_t r13;
    uint64_t r12;
    uint64_t r11;
    uint64_t r10;
    uint64_t r9;
    uint64_t r8;
    uint64_t rbp;
    uint64_t rdi;
    uint64_t rsi;
    uint64_t rbx;
    uint64_t rdx;
    uint64_t rcx;
    uint64_t rax;

	uint64_t rflags;
};
#pragma pack(pop)

class MidHook : public IHook {
public:
	MidHook(uintptr_t target, uintptr_t proxy);
	~MidHook() override;


	bool Hook() override;
	bool Unhook() override;
	bool Ishooked() const override { return m_is_hooked; }
	uintptr_t GetOriginal() const override { return m_trampoline; }


private:
	uintptr_t m_target;
	uintptr_t m_proxy;
	uintptr_t m_trampoline{ 0 };
	std::vector<uint8_t> m_original_bytes;
	size_t m_hook_size{ 0 };
	bool m_is_hooked = false;



};