#include "HookUtils.h"


static bool HookUtils::IsTerminal(const hde64s& hs) {
	switch (hs.opcode) {
	case 0xC3:
	case 0xC2:
	case 0xE9:
		return true;

	default:
		return false;
	}
}

size_t HookUtils::CalcRequiredSize(uintptr_t m_target, size_t required_size) {

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

uintptr_t HookUtils::AllocateWithin1GBRange(uintptr_t m_target, size_t size)
{
	int32_t MaxSafeRadius = INT32_MAX / 2; // 1GB
	uintptr_t trampoline = 0;

	uintptr_t search_start = m_target > MaxSafeRadius ? m_target - MaxSafeRadius : 0x0;

	MEMORY_BASIC_INFORMATION mbi;
	for (uintptr_t addr = search_start; addr < m_target + MaxSafeRadius; ) {
		if (!VirtualQuery(reinterpret_cast<void*>(addr), &mbi, sizeof(mbi))) break;
		if (mbi.State == MEM_FREE) {
			trampoline = (uintptr_t)VirtualAlloc((void*)addr, size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
			if (trampoline) return trampoline;
		}
		addr = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
	}

	return 0;
}

size_t HookUtils::RelocateInstructions(uintptr_t target, uintptr_t trampoline, size_t stolen_size) {
	size_t src_offset = 0;
	size_t dst_offset = 0;

	while (src_offset < stolen_size) {
		hde64s hs;
		uint32_t len = hde64_disasm(reinterpret_cast<void*>(target + src_offset), &hs);

		if (hs.flags & F_ERROR)
			return false;

		if (((hs.flags & F_DISP32) && ((hs.modrm_mod == 0 && hs.modrm_rm == 5)) || hs.opcode == 0xE8 || hs.opcode == 0xE9)) {
			memcpy(reinterpret_cast<void*>(trampoline + dst_offset),
				reinterpret_cast<void*>(target + src_offset), len);

			int32_t old_rel = *reinterpret_cast<int32_t*>(target + src_offset + len - 4);
			uintptr_t abs_target = (target + src_offset + len) + old_rel;
			int32_t new_rel = (int32_t)(abs_target - (trampoline + dst_offset + len));
			*reinterpret_cast<int32_t*>(trampoline + dst_offset + len - 4) = new_rel;

			src_offset += len;
			dst_offset += len;
		}
		else if (hs.opcode >= 0x70 && hs.opcode <= 0x7F) { //short conditional jump
			int8_t old_rel = *(int8_t*)(target + src_offset + 1);
			uintptr_t abs_target = (uintptr_t)(target + src_offset + 2) + old_rel;

			int32_t new_rel = (int32_t)(abs_target - (trampoline + dst_offset + 6)); // 6 becuase 0x0F 0xYY [disp1] [disp2] [disp3] [disp4]

			*reinterpret_cast<uint8_t*>(trampoline + dst_offset) = 0x0F;
			*reinterpret_cast<uint8_t*>(trampoline + dst_offset + 1) = (hs.opcode - 0x70) + 0x80;
			*reinterpret_cast<int32_t*>(trampoline + dst_offset + 2) = new_rel;


			src_offset += len;
			dst_offset += 6;
		}

		else if (hs.opcode == 0xEB) { //short jump
			int8_t old_rel8 = *(int8_t*)(target + src_offset + 1);
			uintptr_t abs_target = (target + src_offset + 2) + old_rel8;
			int32_t new_rel = (int32_t)(abs_target - (trampoline + dst_offset + 5));

			*(uint8_t*)(trampoline + dst_offset) = 0xE9;
			*(int32_t*)(trampoline + dst_offset + 1) = new_rel;

			src_offset += len;
			dst_offset += 5;
		}
		else {
			memcpy(reinterpret_cast<void*>(trampoline + dst_offset),
				reinterpret_cast<void*>(target + src_offset), len);

			src_offset += len;
			dst_offset += len;
		}
	}

	return dst_offset;
}
