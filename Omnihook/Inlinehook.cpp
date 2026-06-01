#include <Windows.h>
#include "Omnihook.h"
#include "hde64.h"
#include "HookUtils.h"

using namespace HookUtils;


Inlinehook::Inlinehook(uintptr_t target, uintptr_t proxy) : m_target(target), m_proxy(proxy) {}

Inlinehook::~Inlinehook() {
	if (m_is_hooked) {
		Unhook();
	}
	if (m_trampoline) {
		VirtualFree(reinterpret_cast<void*>(m_trampoline), 0, MEM_RELEASE);
	}
}


bool Inlinehook::Hook() {
	if (!m_target || !m_proxy || m_is_hooked) return false;

	bool use_absolute_jmp = true;

	size_t stolen_size = CalcRequiredSize(m_target, sizeof(AbsoluteJumpx64));

	if (!stolen_size) {
		use_absolute_jmp = false;
		stolen_size = CalcRequiredSize(m_target, sizeof(RelativeJumpx64));
	}

	if (stolen_size < sizeof(RelativeJumpx64))
		return false;

	DWORD oldProt;
	if (!VirtualProtect(reinterpret_cast<void*>(m_target), stolen_size, PAGE_EXECUTE_READWRITE, &oldProt)) {
		return false;
	}

	m_trampoline = AllocateWithin1GBRange(m_target, stolen_size + sizeof(AbsoluteJumpx64) + 128);

	if (!m_trampoline) {
		DWORD temp;
		VirtualProtect(reinterpret_cast<void*>(m_target), stolen_size, oldProt, &temp);
		return false;
	}

	m_original_bytes.resize(stolen_size);
	memcpy(m_original_bytes.data(), reinterpret_cast<void*>(m_target), stolen_size);


	size_t dst_offset = RelocateInstructions(m_target, m_trampoline, stolen_size);

	AbsoluteJumpx64 jmp_back;
	jmp_back.proxy_address = m_target + stolen_size;
	memcpy(reinterpret_cast<void*>(m_trampoline + dst_offset), &jmp_back, sizeof(AbsoluteJumpx64));

	std::vector<uint8_t> patch(stolen_size, 0x90);

	if (use_absolute_jmp) {
	   	AbsoluteJumpx64 detour;
	   	detour.proxy_address = m_proxy;
	   	memcpy(patch.data(), &detour, sizeof(AbsoluteJumpx64));
	   }
	   else {
		AbsoluteJumpx64 far_proxy_relay;
		far_proxy_relay.proxy_address = m_proxy;

		uintptr_t relay_address = m_trampoline + dst_offset + sizeof(AbsoluteJumpx64);
		memcpy(reinterpret_cast<void*>(relay_address), &far_proxy_relay, sizeof(AbsoluteJumpx64));

	   	RelativeJumpx64 detour;
	   	intptr_t rel = (intptr_t)(relay_address - (m_target + 5));
		if (rel < INT32_MIN || rel > INT32_MAX) {
			DWORD temp;
			VirtualProtect(reinterpret_cast<void*>(m_target), stolen_size, oldProt, &temp);
			return false;
		};
	   	detour.displacement = (int32_t)rel;
	   	memcpy(patch.data(), &detour, sizeof(RelativeJumpx64));
	   }
	   
	   memcpy(reinterpret_cast<void*>(m_target), patch.data(), stolen_size);

	DWORD temp;
	VirtualProtect(reinterpret_cast<void*>(m_target), stolen_size, oldProt, &temp);

	m_hook_size = stolen_size;
	m_is_hooked = true;
	return true;
}

bool Inlinehook::Unhook() {
	if (!m_is_hooked) return false;

	DWORD old;
	VirtualProtect(reinterpret_cast<void*>(m_target), m_hook_size, PAGE_EXECUTE_READWRITE, &old);

	memcpy(reinterpret_cast<void*>(m_target), m_original_bytes.data(), m_original_bytes.size());

	DWORD temp;
	VirtualProtect(reinterpret_cast<void*>(m_target), m_hook_size, old, &temp);

	if (m_trampoline) {
		VirtualFree(reinterpret_cast<void*>(m_trampoline), 0, MEM_RELEASE);
		m_trampoline = 0;
	}
	m_original_bytes.clear();
	m_hook_size = 0;
	m_is_hooked = false;

	return true;

}