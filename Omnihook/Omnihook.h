#pragma once
#include <cstdint>

namespace Omnihook {

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

	enum class Status {
		Success,
		AlreadyExists,
		NotFound,
		HookFailed,
		UnhookFailed
	};

	enum class HookType {
		Default = 0,
		Shadow = 1
	};


	Status CreateInlineHook(void* target, void* detour, void** original);
	Status CreateMidHook(void* target, void* detour);
	Status CreateHWBPHook(void* target, void* detour);
	Status CreateVMTHook(void* target, void* detour, int index, HookType hookType = HookType::Default);

	Status EnableHook(void* target);
	Status DisableHook(void* target);
	Status RemoveHook(void* target);

	void RemoveAll();

}
