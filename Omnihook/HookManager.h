#pragma once
#include "IHook.h"
#include <unordered_map>
#include <memory>

class HookManager {

public:

	bool Add(uintptr_t key, std::unique_ptr<IHook> hook);

	bool Remove(uintptr_t key);

	IHook* Get(uintptr_t key) const;

	void RemoveAll();

private:
	std::unordered_map<uintptr_t, std::unique_ptr<IHook>> m_hooks;
};