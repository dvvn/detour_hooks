#pragma once

#include <memory>

// ReSharper disable CppInconsistentNaming
using UINT8 = unsigned char;
using UINT32 = unsigned int;
using UINT64 = unsigned __int64;
using UINT = unsigned int;
using LPVOID = void*;
// ReSharper restore CppInconsistentNaming

namespace dhooks::detail
{
#pragma pack(push, 1)
	// ReSharper disable CppInconsistentNaming

	// Structs for writing x86/x64 instructions.

	// 8-bit relative jump.
	struct JMP_REL_SHORT
	{
		UINT8 opcode; // EB xx: JMP +2+xx
		UINT8 operand;
	};

	// 32-bit direct relative jump/call.
	struct JMP_REL
	{
		UINT8  opcode;  // E9/E8 xxxxxxxx: JMP/CALL +5+xxxxxxxx
		UINT32 operand; // Relative destination address
	};

	using CALL_REL = JMP_REL;
	// 64-bit indirect absolute jump.

	struct JMP_ABS
	{
		UINT8  opcode0; // FF25 00000000: JMP [+6]
		UINT8  opcode1;
		UINT32 dummy;
		UINT64 address; // Absolute destination address
	};

	// 64-bit indirect absolute call.
	struct CALL_ABS
	{
		UINT8  opcode0; // FF15 00000002: CALL [+6]
		UINT8  opcode1;
		UINT32 dummy0;
		UINT8  dummy1; // EB 08:         JMP +10
		UINT8  dummy2;
		UINT64 address; // Absolute destination address
	};

	// 32-bit direct relative conditional jumps.
	struct JCC_REL
	{
		UINT8  opcode0; // 0F8* xxxxxxxx: J** +6+xxxxxxxx
		UINT8  opcode1;
		UINT32 operand; // Relative destination address
	};

	// 64bit indirect absolute conditional jumps that x64 lacks.
	struct JCC_ABS
	{
		UINT8  opcode; // 7* 0E:         J** +16
		UINT8  dummy0;
		UINT8  dummy1; // FF25 00000000: JMP [+6]
		UINT8  dummy2;
		UINT32 dummy3;
		UINT64 address; // Absolute destination address
	};

	// ReSharper restore CppInconsistentNaming
#pragma pack(pop)

	class trampoline2
	{
	public:
		trampoline2( );
		~trampoline2( );

		trampoline2(trampoline2&&) noexcept;
		trampoline2& operator=(trampoline2&&) noexcept;

		bool fix_page_protection( );
		bool create(LPVOID target, LPVOID detour);

		bool patch_above( ) const;

		LPVOID target( ) const;
		LPVOID detour( ) const;

		UINT8* trampoline( ) const;

	private:
		struct impl;
		std::unique_ptr<impl> impl_;
	};
}
