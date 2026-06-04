#include "HookUtils.h"

static ZydisDecoder& Decoder() {
	static ZydisDecoder dec = []()
		{
			ZydisDecoder d;
			ZydisDecoderInit(&d, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
			return d;
		}();
	return dec;
}

static bool Decode(const void* ptr, ZydisDecodedInstruction& instr, ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT]) {
	return ZYAN_SUCCESS(ZydisDecoderDecodeFull(&Decoder(), ptr, ZYDIS_MAX_INSTRUCTION_LENGTH, &instr, operands));
}


static bool HookUtils::IsTerminal(const ZydisDecodedInstruction& instr) {
	switch (instr.mnemonic) {
	case ZYDIS_MNEMONIC_RET:
	case ZYDIS_MNEMONIC_JMP:
		return true;

	default:
		return false;
	}
}

size_t HookUtils::CalcRequiredSize(uintptr_t m_target, size_t required_size) {

	uint8_t* p = reinterpret_cast<uint8_t*>(m_target);
	size_t offset = 0;

	while (offset < required_size) {
		ZydisDecodedInstruction instr;
		ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

		if (!Decode(p + offset, instr, operands))
			return 0;

		uint32_t len = instr.length;

		if (IsTerminal(instr) && (offset + len) < required_size)
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

		const uint8_t* src = reinterpret_cast<const uint8_t*>(target + src_offset);
		ZydisDecodedInstruction instr;
		ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

		if (!Decode(src, instr, operands))
			return 0;

		const uint32_t len = instr.length;
		const uint8_t opcode = src[0];

		bool hasRipRelMem = false;
		for (uint8_t i = 0; i < instr.operand_count; i++) {
			if (operands[i].type == ZYDIS_OPERAND_TYPE_MEMORY && operands[i].mem.base == ZYDIS_REGISTER_RIP) {
				hasRipRelMem = true;
				break;
			}

		}

		const bool isNearRelCallOrJmp =
			(instr.mnemonic == ZYDIS_MNEMONIC_CALL ||
				instr.mnemonic == ZYDIS_MNEMONIC_JMP)
			&& instr.operand_count_visible >= 1
			&& operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE
			&& opcode != 0xEB;


		if (hasRipRelMem || isNearRelCallOrJmp) {
			uint8_t* dst = reinterpret_cast<uint8_t*>(trampoline + dst_offset);
			memcpy(dst, src, len);

			int32_t old_rel = *reinterpret_cast<const int32_t*>(src + len - 4);
			uintptr_t abs_target = (target + src_offset + len) + old_rel;
			int32_t new_rel = (int32_t)(abs_target - (trampoline + dst_offset + len));
			*reinterpret_cast<int32_t*>(dst + len - 4) = new_rel;

			src_offset += len;
			dst_offset += len;
		}
		else if (opcode >= 0x70 && opcode <= 0x7F) { //short conditional jump
			int8_t old_rel = *(const int8_t*)(src + 1);
			uintptr_t abs_target = (uintptr_t)(target + src_offset + 2) + old_rel;

			int32_t new_rel = (int32_t)(abs_target - (trampoline + dst_offset + 6)); // 6 becuase 0x0F 0xYY [disp1] [disp2] [disp3] [disp4]

			uint8_t* dst = reinterpret_cast<uint8_t*>(trampoline + dst_offset);

			dst[0] = 0x0F;
			dst[1] = 0x80 + (opcode - 0x70); //J<cc> rel32 opcode
			*reinterpret_cast<int32_t*>(dst + 2) = new_rel;


			src_offset += len;
			dst_offset += 6;
		}

		else if (opcode == 0xEB) { //short jump
			int8_t old_rel8 = *(int8_t*)(src + 1);
			uintptr_t abs_target = (target + src_offset + 2) + old_rel8;
			int32_t new_rel = (int32_t)(abs_target - (trampoline + dst_offset + 5));

			uint8_t* dst = reinterpret_cast<uint8_t*>(trampoline + dst_offset);
			dst[0] = 0xE9;
			*(int32_t*)(dst + 1) = new_rel;

			src_offset += len;
			dst_offset += 5;
		}
		else {
			memcpy(reinterpret_cast<void*>(trampoline + dst_offset), src, len);

			src_offset += len;
			dst_offset += len;
		}
	}

	return dst_offset;
}
