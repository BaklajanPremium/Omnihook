#pragma once
#include <cstdint>

class IHook {
public:

	virtual ~IHook() = default;

	virtual bool Hook() = 0;
	virtual bool Unhook() = 0;
	virtual bool Ishooked() const = 0;


	virtual uintptr_t GetOriginal() const = 0;
};