#include "MidHook.h"
#include "HookUtils.h"

using namespace HookUtils;

struct MidHookData {
	uintptr_t user_callback;
	uintptr_t trampoline_address;
};

static std::unordered_map<uintptr_t, MidHookData> g_mid_hooks;

extern "C" void SharedMidHookStub();

extern "C" uintptr_t MasterDispatcher(uintptr_t hookId, RegisterContext* regs) {
	uintptr_t returnAddress = 0xDEADBEEF;
	auto it = g_mid_hooks.find(hookId);

	if (it != g_mid_hooks.end()) {
		auto& hook = it->second;

		if (hook.user_callback) {
			auto callback = reinterpret_cast<void(*)(RegisterContext*)>(hook.user_callback);
			callback(regs);
		}

		returnAddress = hook.trampoline_address;
	}
	//Maybe better to log and kill thread if hook not found?
	
	return returnAddress;
}


MidHook::MidHook(uintptr_t target, uintptr_t proxy) : m_target(target), m_proxy(proxy) {}

MidHook::~MidHook() {
	if (m_is_hooked) {
		Unhook();
	}
	if (m_trampoline) {
		VirtualFree(reinterpret_cast<void*>(m_trampoline), 0, MEM_RELEASE);
	}
}

bool MidHook::Hook() {
	if (!m_target || !m_proxy || m_is_hooked) return false;

	size_t stolen_size = CalcRequiredSize(m_target, sizeof(RelativeJumpx64));
	if (stolen_size < sizeof(RelativeJumpx64)) return false;

	DWORD old;
	if (!VirtualProtect(reinterpret_cast<void*>(m_target), stolen_size, PAGE_EXECUTE_READWRITE, &old))
		return false;

	m_trampoline = AllocateWithin1GBRange(m_target, stolen_size + sizeof(AbsoluteJumpx64) + 128);
	if (!m_trampoline) {
		DWORD temp;
		VirtualProtect(reinterpret_cast<void*>(m_target), stolen_size, old, &temp);
		return false;
	}

	m_original_bytes.resize(stolen_size);
	memcpy(m_original_bytes.data(), reinterpret_cast<void*>(m_target), stolen_size);

	size_t dst_offset = RelocateInstructions(m_target, m_trampoline, stolen_size);

	AbsoluteJumpx64 jmp_back;
	jmp_back.proxy_address = m_target + stolen_size;
	memcpy(reinterpret_cast<void*>(m_trampoline + dst_offset), &jmp_back, sizeof(AbsoluteJumpx64));

	uintptr_t return_address = m_target + 5;

	MidHookData data{ 0 };
	data.user_callback = m_proxy;
	data.trampoline_address = m_trampoline;

	g_mid_hooks[return_address] = data;


	std::vector<uint8_t> patch(stolen_size, 0x90);

	AbsoluteJumpx64 far_proxy_relay;
	far_proxy_relay.proxy_address = reinterpret_cast<uintptr_t>(&SharedMidHookStub);

	uintptr_t relay_address = m_trampoline + dst_offset + sizeof(AbsoluteJumpx64);
	memcpy(reinterpret_cast<void*>(relay_address), &far_proxy_relay, sizeof(AbsoluteJumpx64));

	intptr_t rel = (intptr_t)(relay_address - (m_target + 5));
	if (rel < INT32_MIN || rel > INT32_MAX) {
		DWORD temp;
		VirtualProtect(reinterpret_cast<void*>(m_target), stolen_size, old, &temp);
		return false;
	};
	RelativeJumpx64 detour;
	detour.jmp_opcode[0] = 0xE8;
	detour.displacement = (int32_t)rel;
	memcpy(patch.data(), &detour, sizeof(RelativeJumpx64));

	memcpy(reinterpret_cast<void*>(m_target), patch.data(), stolen_size);

	DWORD temp;
	VirtualProtect(reinterpret_cast<void*>(m_target), stolen_size, old, &temp);

	m_hook_size = stolen_size;
	m_is_hooked = true;
	return true;
}

bool MidHook::Unhook() {
	if (!m_is_hooked) return false;

	DWORD old;
	VirtualProtect(reinterpret_cast<void*>(m_target), m_hook_size, PAGE_EXECUTE_READWRITE, &old);

	memcpy(reinterpret_cast<void*>(m_target), m_original_bytes.data(), m_hook_size);

	DWORD temp;
	VirtualProtect(reinterpret_cast<void*>(m_target), m_hook_size, old, &temp);

	g_mid_hooks.erase(m_target + 5);

	if (m_trampoline) {
		VirtualFree(reinterpret_cast<void*>(m_trampoline), 0, MEM_RELEASE);
		m_trampoline = 0;
	}

	m_hook_size = 0;
	m_original_bytes.clear();
	m_is_hooked = false;

	return true;

}
