#pragma once
#include "IHook.h"
#include <vector>

class Inlinehook : public IHook {
public:
	Inlinehook(uintptr_t target, uintptr_t proxy, void** original);
	~Inlinehook() override;

	bool Hook() override;
	bool Unhook() override;
	bool Ishooked() const override { return m_is_hooked; }
	uintptr_t GetOriginal() const override { return m_trampoline; }



private:

	uintptr_t m_target;
	uintptr_t m_proxy;

	void** m_original_out;

	uintptr_t m_trampoline{ 0 };
	std::vector<uint8_t> m_original_bytes;
	size_t m_hook_size{ 0 };
	bool m_is_hooked = false;



};