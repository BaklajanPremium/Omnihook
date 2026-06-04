#pragma once
#include <cstdint>
#include <vector>
#include "hde64.h"
#include "Zydis/Zydis.h"


//#ifdef _DEBUG
//#pragma comment(lib, "Zydis_D.lib")
//#else 
//#pragma comment(lib, "Zydis.lib")
//#endif


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


namespace HookUtils {
	bool IsTerminal(const ZydisDecodedInstruction& instr);
	size_t CalcRequiredSize(uintptr_t target, size_t required_size);
	uintptr_t AllocateWithin1GBRange(uintptr_t target, size_t size);

	size_t RelocateInstructions(uintptr_t target, uintptr_t trampoline, size_t stolen_size);

}