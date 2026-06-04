#include "HWBPHook.h"
#include <windows.h>
#include <TlHelp32.h> 

std::vector<HWBPHook*> HWBPHook::m_active_hooks;
thread_local bool HWBPHook::m_bypass_flag = false;

HWBPHook::HWBPHook(uintptr_t target, uintptr_t proxy)
	: m_target(target),
	m_proxy(proxy),
	m_dr_index(-1),
	m_is_hooked(false)
{

}

HWBPHook::~HWBPHook() {
	if (m_is_hooked) {
		Unhook();
	}
}

LONG HWBPHook::PvectoredExceptionHandler(PEXCEPTION_POINTERS ExceptionInfo) {
	if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP) {
		PVOID exception_addr = ExceptionInfo->ExceptionRecord->ExceptionAddress;
		
		for (HWBPHook* hook : m_active_hooks) {
			if (reinterpret_cast<PVOID>(hook->m_target) == exception_addr) {
				if (m_bypass_flag) {
					ExceptionInfo->ContextRecord->EFlags |= 0x10000; // RF Flag
					m_bypass_flag = false;

				}
				else {
					ExceptionInfo->ContextRecord->Rip = static_cast<DWORD64>(hook->m_proxy);
				}
				return EXCEPTION_CONTINUE_EXECUTION;
			}
		}

	}
	return EXCEPTION_CONTINUE_SEARCH;

};

bool HWBPHook::Hook() {
	if (!m_target || !m_proxy || m_is_hooked) return false;

	static bool veh_registered = false;
	if (!veh_registered) {
		m_exception_handle = AddVectoredExceptionHandler(1, HWBPHook::PvectoredExceptionHandler);
		if (!m_exception_handle) return false;
		veh_registered = true;
	}

	
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (snapshot == INVALID_HANDLE_VALUE) {
		return false;
	}

	THREADENTRY32 te;
	te.dwSize = sizeof(THREADENTRY32);

	bool success = false;
	int negotiated_slot = -1;

	if (Thread32First(snapshot, &te)) {
		do {
			if (te.th32OwnerProcessID == GetCurrentProcessId()) {

				HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, false, te.th32ThreadID);
				if (hThread) {

					bool isCurrentThread = (te.th32ThreadID == GetCurrentThreadId());

					if (!isCurrentThread) {
						SuspendThread(hThread);
					}

					CONTEXT ctx = { 0 };
					ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

					if (GetThreadContext(hThread, &ctx)) {

						if (negotiated_slot == -1) {
							for (int i = 0; i < 4; i++) {
								if ((ctx.Dr7 & (1ULL << (i * 2))) == 0) {
									negotiated_slot = i;
									break;
								}
							}
						}
						// If no slots are open anywhere, or our chosen slot is blocked on this specific thread
						if (negotiated_slot == -1 || (ctx.Dr7 & (1ULL << (negotiated_slot * 2))) != 0) {
							ResumeThread(hThread);
							CloseHandle(hThread);
							success = false;
							break; 
						}

						switch (negotiated_slot) {
						case 0: ctx.Dr0 = m_target; break;
						case 1: ctx.Dr1 = m_target; break;
						case 2: ctx.Dr2 = m_target; break;
						case 3: ctx.Dr3 = m_target; break;
						}

						ctx.Dr7 |= (1ULL << (negotiated_slot * 2));

						ctx.Dr7 &= ~(0xFULL << (16 + (negotiated_slot * 4)));

						if (SetThreadContext(hThread, &ctx)) {
							success = true;
						}
					}

					if (!isCurrentThread) {
						ResumeThread(hThread);
					}
					CloseHandle(hThread);
				}
				
			}
		} while (Thread32Next(snapshot, &te));
	}
	CloseHandle(snapshot);

	if (success) {
		m_dr_index = negotiated_slot;
		m_active_hooks.push_back(this);
		m_is_hooked = true;
		return true;
	}

	return false;

}

bool HWBPHook::Unhook() {
	if (!m_target || !m_proxy || !m_is_hooked) return false;

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (snapshot == INVALID_HANDLE_VALUE) return false;

	THREADENTRY32 te;
	te.dwSize = sizeof(THREADENTRY32);

	if (Thread32First(snapshot, &te)) {
		do {
			if (te.th32OwnerProcessID == GetCurrentProcessId()) {

					HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, false, te.th32ThreadID);
					if (hThread) {

						bool isCurrentThread = (te.th32ThreadID == GetCurrentThreadId());

						if (!isCurrentThread) {
							SuspendThread(hThread);
						}
						CONTEXT ctx = { 0 };
						ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

						if (GetThreadContext(hThread, &ctx)) {
							switch (m_dr_index) {
								case 0: ctx.Dr0 = 0; break;
								case 1: ctx.Dr1 = 0; break;
								case 2: ctx.Dr2 = 0; break;
								case 3: ctx.Dr3 = 0; break;
							}

							ctx.Dr7 &= ~(1ULL << (m_dr_index * 2));

							ctx.Dr7 &= ~(0xFULL << (16 + (m_dr_index * 4)));

							SetThreadContext(hThread, &ctx);
						}

						if (!isCurrentThread) {
							ResumeThread(hThread);
						}
						CloseHandle(hThread);
					}
			}
		} while (Thread32Next(snapshot, &te));
	}

	CloseHandle(snapshot);

	auto it = std::find(m_active_hooks.begin(), m_active_hooks.end(), this);
	if (it != m_active_hooks.end()) {
		m_active_hooks.erase(it);
	}

	RemoveVectoredExceptionHandler(m_exception_handle);

	m_is_hooked = false;
	return true;



}