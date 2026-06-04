#include "Omnihook.h"
#include "HookManager.h"
#include "Inlinehook.h"
#include "HWBPHook.h"
#include "VMTHooks.h"
#include "MidHook.h"

static HookManager g_Manager;

namespace Omnihook {

	Status CreateInlineHook(void* target, void* detour, void** original) {
		if (!target || !detour) return Status::HookFailed;

		uintptr_t key = reinterpret_cast<uintptr_t>(target);
		IHook* it = g_Manager.Get(key);
		if (it) {
			return Status::AlreadyExists;
		}

		auto hook = std::make_unique<Inlinehook>(reinterpret_cast<uintptr_t>(target), reinterpret_cast<uintptr_t>(detour), original);

		g_Manager.Add(key, std::move(hook));

		return Status::Success;
	}

	Status CreateMidHook(void* target, void* detour) {
		if (!target || !detour) return Status::HookFailed;

		uintptr_t key = reinterpret_cast<uintptr_t>(target);
		IHook* it = g_Manager.Get(key);
		if (it) {
			return Status::AlreadyExists;
		}

		auto hook = std::make_unique<MidHook>(reinterpret_cast<uintptr_t>(target), reinterpret_cast<uintptr_t>(detour));

		g_Manager.Add(key, std::move(hook));

		return Status::Success;


	}

	Status CreateHWBPHook(void* target, void* detour) {
		if (!target || !detour) return Status::HookFailed;

		uintptr_t key = reinterpret_cast<uintptr_t>(target);
		IHook* it = g_Manager.Get(key);
		if (it) {
			return Status::AlreadyExists;
		}

		auto hook = std::make_unique<HWBPHook>(reinterpret_cast<uintptr_t>(target), reinterpret_cast<uintptr_t>(detour));

		g_Manager.Add(key, std::move(hook));

		return Status::Success;


	}

	Status CreateVMTHook(void* target, void* detour, int index, HookType hookType) {
		if (!target || !detour) return Status::HookFailed;

		uintptr_t key = reinterpret_cast<uintptr_t>(target);
		IHook* it = g_Manager.Get(key);
		if (it) {
			return Status::AlreadyExists;
		}

		auto hook = std::make_unique<VMTHook>(target, index, detour, hookType);

		g_Manager.Add(key, std::move(hook));

		return Status::Success;
	}


	Status EnableHook(void* target) {
		if (!target) return Status::NotFound;

		uintptr_t key = reinterpret_cast<uintptr_t>(target);

		IHook* it = g_Manager.Get(key);

		if (it) {
			if (it->Hook()) {
				return Status::Success;
			}
			else {
				return Status::HookFailed;
			}
		}

		return Status::NotFound;
	}
	Status DisableHook(void* target) {
		if (!target) return Status::NotFound;

		uintptr_t key = reinterpret_cast<uintptr_t>(target);

		IHook* it = g_Manager.Get(key);

		if (it) {
			if (it->Unhook()) {
				return Status::Success;
			}
			else {
				return Status::UnhookFailed;
			}
		}

		return Status::NotFound;


	}
	Status RemoveHook(void* target) {
		if (!target) return Status::NotFound;

		uintptr_t key = reinterpret_cast<uintptr_t>(target);

		DisableHook(target);

		if (g_Manager.Remove(key)) {
			return Status::Success;
		}
		

		return Status::NotFound;
		
	}

	void RemoveAll() {
		g_Manager.RemoveAll();
	}




}
