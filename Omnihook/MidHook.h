#pragma once
#include <unordered_map>
#include <vector>
#include "IHook.h"


#include "Omnihook.h"

using Omnihook::RegisterContext;
using Omnihook::YMMRegister;

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