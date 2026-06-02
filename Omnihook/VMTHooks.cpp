#include "VMTHooks.h"
#include "HookUtils.h"


VMTHook::VMTHook(void* p_object_instance, int index, void* proxy, HookType hook_type)
	: m_object_instance(p_object_instance), m_index(index),
	m_proxy(reinterpret_cast<uintptr_t>(proxy)), m_type(hook_type)
{
	if (m_object_instance) {
		m_vptr = reinterpret_cast<void***>(m_object_instance);
		m_original_vtable = *m_vptr;
	}
}

VMTHook::~VMTHook() {
	if (m_is_hooked) {
		Unhook();
	}
}

bool VMTHook::Hook() {
	if (m_is_hooked || !m_vptr || !m_original_vtable) return false;

	m_trampoline = reinterpret_cast<uintptr_t>(m_original_vtable[m_index]);

	if (m_type == HookType::Default) {
		DWORD old;
		if (!VirtualProtect(&m_original_vtable[m_index], sizeof(void*), PAGE_READWRITE, &old))
			return false;

		m_original_vtable[m_index] = reinterpret_cast<void*>(m_proxy);
		VirtualProtect(&m_original_vtable[m_index], sizeof(void*), old, &old);

	}
	else if (m_type == HookType::Shadow) {
		size_t vtable_size = 128;

		m_shadow_vtable = new void* [vtable_size];
		memcpy(m_shadow_vtable, m_original_vtable, vtable_size * sizeof(void*));

		m_shadow_vtable[m_index] = reinterpret_cast<void*>(m_proxy);

		*m_vptr = m_shadow_vtable;


	}

	m_is_hooked = true;
	return true;

}

bool VMTHook::Unhook() {
	if (m_type == HookType::Default) {
		DWORD old;
		VirtualProtect(&m_original_vtable[m_index], sizeof(void*), PAGE_READWRITE, &old);

		m_original_vtable[m_index] = reinterpret_cast<void*>(m_trampoline);

		VirtualProtect(&m_original_vtable[m_index], sizeof(void*), old, &old);

	}
	else if (m_type == HookType::Shadow) {
		*m_vptr = m_original_vtable;

		delete[] m_shadow_vtable;
		m_shadow_vtable = nullptr;
	}

	m_is_hooked = false;
	return true;

}