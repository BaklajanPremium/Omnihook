#include "Omnihook.h"
#include "hde64.h"
#include <Windows.h>


Inlinehook::Inlinehook(uintptr_t target, uintptr_t proxy) : m_target(target), m_proxy(proxy) {}

Inlinehook::~Inlinehook() {
	if (m_is_hooked) {
		Unhook();
	}
}

#pragma pack(push, 1)
struct AbsoluteJumpx64 {
	uint8_t jmp_opcode[2] = { 0xFF, 0x25 };
	uint32_t displacement = 0x00000000;
	uint64_t proxy_address;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct RelativeJumpx64 {
	uint8_t jmp_opcode[1] = { 0xE9 };
	uint32_t displacement = 0x00000000;
};
#pragma pack(pop)

static bool IsTerminal(const hde64s& hs) {
	switch (hs.opcode) {
	case 0xC3:
	case 0xC2:
		return true;

	default:
		return false;
	}
}

size_t CalcRequiredSize(uintptr_t m_target, size_t required_size) {

	uint8_t* p = reinterpret_cast<uint8_t*>(m_target);
	size_t offset = 0;

	while (offset < required_size) {
		hde64s hs;
		uint32_t len = hde64_disasm(p + offset, &hs);

		if (hs.flags & F_ERROR)
			return 0;

		if (IsTerminal(hs) && offset + len < required_size)
			return 0;

		offset += len;
	}

	return offset;

}

bool Inlinehook::Hook() {
	if (!m_target || !m_proxy || m_is_hooked) return false;

	size_t required_bytes = sizeof(AbsoluteJumpx64);


	bool use_absolute_jmp = true;

	size_t stolen_size = CalcRequiredSize(m_target, required_bytes);

	if (!stolen_size) {
		use_absolute_jmp = false;
		required_bytes = sizeof(RelativeJumpx64);
	}

	stolen_size = CalcRequiredSize(m_target, required_bytes);

	if (stolen_size < 5)
		return false;

	DWORD oldProt;
	if (!VirtualProtect(reinterpret_cast<void*>(m_target), stolen_size, PAGE_EXECUTE_READWRITE, &oldProt)) {
		return false;
	}

	m_trampoline = (uintptr_t)VirtualAlloc(NULL, stolen_size + required_bytes, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	if (!m_trampoline) {
		DWORD temp;
		VirtualProtect(reinterpret_cast<void*>(m_target), stolen_size, oldProt, &temp);
		return false;
	}

	m_original_bytes.resize(stolen_size);
	memcpy(m_original_bytes.data(), reinterpret_cast<void*>(m_target), stolen_size);

	if (stolen_size > required_bytes)
		memset(reinterpret_cast<void*>(m_target + required_bytes), 0x90, stolen_size - required_bytes);

	memcpy(reinterpret_cast<void*>(m_trampoline), m_original_bytes.data(), m_original_bytes.size());

	AbsoluteJumpx64 tramp;
	tramp.proxy_address = m_target + stolen_size;

	memcpy(reinterpret_cast<void*>(m_trampoline + sizeof(AbsoluteJumpx64)), &tramp, required_bytes);

	uint8_t* p = reinterpret_cast<uint8_t*>(m_trampoline);
	size_t fix_offset = 0;
	while (fix_offset < stolen_size) {
		hde64s hs;
		uint32_t len = hde64_disasm(p + fix_offset, &hs);

		if ((hs.flags & F_DISP32) && hs.modrm_mod == 0 && hs.modrm_rm == 5) {
			int32_t old_rel = *reinterpret_cast<int32_t*>(m_trampoline + fix_offset + len - 4);
			uintptr_t abs_target = (m_target + fix_offset + len) + old_rel;
			int32_t new_rel = (int32_t)(abs_target - (m_trampoline + fix_offset + len));
			*reinterpret_cast<int32_t*>(m_trampoline + fix_offset + len - 4) = new_rel;
		} 
		fix_offset += len;
	}

	if (use_absolute_jmp) {
		AbsoluteJumpx64 detour;
		detour.proxy_address = m_proxy;
		memcpy(reinterpret_cast<void*>(m_target), &detour, required_bytes);
	}
	else {
		RelativeJumpx64 detour;
		detour.displacement = (int32_t)(m_proxy - (m_target + 5));
		memcpy(reinterpret_cast<void*>(m_target), &detour, required_bytes);
	}
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