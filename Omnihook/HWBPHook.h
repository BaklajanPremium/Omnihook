#pragma once
#include "IHook.h"
#include <vector>
#include <Windows.h>
#include <vector>

class HWBPHook : public IHook {
public:
	HWBPHook(uintptr_t target, uintptr_t proxy);
	~HWBPHook() override;


	bool Hook() override;
	bool Unhook() override;
	bool Ishooked() const override { return m_is_hooked; }
	uintptr_t GetOriginal() const override { return m_trampoline; }

	static LONG PvectoredExceptionHandler(PEXCEPTION_POINTERS ExceptionInfo);
	

	class ScopedBypass {
	public:
		ScopedBypass() { m_bypass_flag = true; }
		~ScopedBypass() { m_bypass_flag = false; }
	};

private:
	uintptr_t m_target;
	uintptr_t m_proxy;
	uintptr_t m_trampoline{ 0 };
	int m_dr_index{ -1 };
	bool m_is_hooked = false;

	static thread_local bool m_bypass_flag;

	static std::vector<HWBPHook*> m_active_hooks;


};