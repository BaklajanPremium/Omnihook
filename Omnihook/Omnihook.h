#pragma once
#include <cstdint>

namespace Omnihook {

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
