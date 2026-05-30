#include "HookManager.h"

bool HookManager::Add(uintptr_t key, std::unique_ptr<IHook> hook) {
	m_hooks[key] = std::move(hook);
	return true;
}

bool HookManager::Remove(uintptr_t key) {
	return m_hooks.erase(key) > 0;
}

IHook* HookManager::Get(uintptr_t key) const {

	auto it = m_hooks.find(key);
	if (it == m_hooks.end())
		return nullptr;

	return it->second.get();
}

void HookManager::RemoveAll() {
	m_hooks.clear();
}