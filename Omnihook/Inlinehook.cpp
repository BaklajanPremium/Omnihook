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
	int32_t displacement = 0x00000000;
	uint64_t proxy_address = 0x0;
};

struct RelativeJumpx64 {
	uint8_t jmp_opcode[1] = { 0xE9 };
	int32_t displacement = 0x00000000;
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


bool Inlinehook::VirtualAlloc1GBRange(uintptr_t m_target, size_t size)
{
	int32_t MaxSafeRadius = INT32_MAX / 2; // 1GB

	uintptr_t search_start = m_target > MaxSafeRadius ? m_target - MaxSafeRadius : 0x0;
	SYSTEM_INFO si;
	GetSystemInfo(&si);

	for (uintptr_t addr = search_start; addr < m_target + MaxSafeRadius; addr += si.dwPageSize) {
		m_trampoline = (uintptr_t)VirtualAlloc(reinterpret_cast<void*>(addr), size + 128, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (m_trampoline) {
			return true;
		}
	}
	return false;
}

bool Inlinehook::Hook() {
	if (!m_target || !m_proxy || m_is_hooked) return false;

	size_t required_bytes = sizeof(AbsoluteJumpx64);


	bool use_absolute_jmp = true;

	size_t stolen_size = CalcRequiredSize(m_target, sizeof(AbsoluteJumpx64));

	if (!stolen_size) {
		use_absolute_jmp = false;
		required_bytes = sizeof(RelativeJumpx64);
		stolen_size = CalcRequiredSize(m_target, sizeof(RelativeJumpx64));
	}

	if (stolen_size < sizeof(RelativeJumpx64))
		return false;

	DWORD oldProt;
	if (!VirtualProtect(reinterpret_cast<void*>(m_target), stolen_size, PAGE_EXECUTE_READWRITE, &oldProt)) {
		return false;
	}

	if (!VirtualAlloc1GBRange(m_target, stolen_size + sizeof(AbsoluteJumpx64))) {
		DWORD temp;
		VirtualProtect(reinterpret_cast<void*>(m_target), stolen_size, oldProt, &temp);
		return false;
	}

	m_original_bytes.resize(stolen_size);
	memcpy(m_original_bytes.data(), reinterpret_cast<void*>(m_target), stolen_size);


	size_t src_offset = 0;
	size_t dst_offset = 0;

	while (src_offset < stolen_size) {
		hde64s hs;
		uint32_t len = hde64_disasm(reinterpret_cast<void*>(m_target + src_offset), &hs);

		if (((hs.flags & F_DISP32) && ((hs.modrm_mod == 0 && hs.modrm_rm == 5)) || hs.opcode == 0xE8 || hs.opcode == 0xE9)) { 
				memcpy(reinterpret_cast<void*>(m_trampoline + dst_offset),
					  reinterpret_cast<void*>(m_target + src_offset), len);

				int32_t old_rel = *reinterpret_cast<int32_t*>(m_target + src_offset + len - 4);
				uintptr_t abs_target = (m_target + src_offset + len) + old_rel;
				int32_t new_rel = (int32_t)(abs_target - (m_trampoline + dst_offset + len));
				*reinterpret_cast<int32_t*>(m_trampoline + dst_offset + len - 4) = new_rel;

				src_offset += len;
				dst_offset += len;
			}
		else if (hs.opcode >= 0x70 && hs.opcode <= 0x7F) { //short conditional jump
				int8_t old_rel = *(int8_t*)(m_target + src_offset + 1);
				uintptr_t abs_target = (uintptr_t)(m_target + src_offset + 2) + old_rel;

				int32_t new_rel = (int32_t)(abs_target - (m_trampoline + dst_offset + 6)); // 6 becuase 0x0F 0xYY [disp1] [disp2] [disp3] [disp4]

				*reinterpret_cast<uint8_t*>(m_trampoline + dst_offset) = 0x0F;
				*reinterpret_cast<uint8_t*>(m_trampoline + dst_offset + 1) = (hs.opcode - 0x70) + 0x80;
				*reinterpret_cast<int32_t*>(m_trampoline + dst_offset + 2) = new_rel;


				src_offset += len;
				dst_offset += 6;
			}

		else if (hs.opcode == 0xEB) { //short jump
			int8_t old_rel8 = *(int8_t*)(m_target + src_offset + 1);
			uintptr_t abs_target = (m_target + src_offset + 2) + old_rel8;
			int32_t new_rel = (int32_t)(abs_target - (m_trampoline + dst_offset + 5));

			*(uint8_t*)(m_trampoline + dst_offset)	   = 0xE9;
			*(int32_t*)(m_trampoline + dst_offset + 1) = new_rel;

			src_offset += len;
			dst_offset += 5;
		}
		else {
			memcpy(reinterpret_cast<void*>(m_trampoline + dst_offset),
				   reinterpret_cast<void*>(m_target + src_offset), len);

			src_offset += len;
			dst_offset += len;
			}
		}

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