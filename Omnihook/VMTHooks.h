#pragma once
#include <vector>
#include "IHook.h"
#include "Omnihook.h"

class VMTHook : public IHook {
public:

	VMTHook(void* p_object_instance, int index, void* proxy, Omnihook::HookType hook_type = Omnihook::HookType::Default);
	~VMTHook() override;


	bool Hook() override;
	bool Unhook() override;
	bool Ishooked() const override { return m_is_hooked; }
	uintptr_t GetOriginal() const override { return m_trampoline; }


private:
	void* m_object_instance{ nullptr };
	int m_index{ 0 };
	uintptr_t m_proxy{ 0 };
	uintptr_t m_trampoline{ 0 };

	void** m_original_vtable{ 0 };
	void** m_shadow_vtable{ 0 };
	void*** m_vptr{ nullptr };
	bool m_is_hooked{ false };
	Omnihook::HookType m_type{ Omnihook::HookType::Default };


};

