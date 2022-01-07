#pragma once

// ReSharper disable once CppUnusedIncludeDirective
#include "hde.h"

#if defined(_M_X64) || defined(__x86_64__)
#include "hde64.h"
#else
#include "hde32.h"
#endif

namespace dhooks::hde
{
#if defined(_M_X64) || defined(__x86_64__)
	_INLINE_VAR constexpr auto _HDE_disasm = hde64_disasm;
	using HDE_data = hde64s;
	//constexpr auto TRAMPOLINE_MAX_SIZE = MEMORY_SLOT_SIZE - sizeof(JMP_ABS);
#else
	_INLINE_VAR	constexpr auto _HDE_disasm = hde::hde32_disasm;
	using HDE_data = hde32s;
	//constexpr auto TRAMPOLINE_MAX_SIZE = MEMORY_SLOT_SIZE;
#endif
}
