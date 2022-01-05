module;

#include <windows.h>
#include <vector>

export module dhooks:trampoline;
import nstd.mem;

export namespace dhooks
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
		UINT8 opcode;   // E9/E8 xxxxxxxx: JMP/CALL +5+xxxxxxxx
		UINT32 operand; // Relative destination address
	};

	using CALL_REL = JMP_REL;
	// 64-bit indirect absolute jump.

	struct JMP_ABS
	{
		UINT8 opcode0; // FF25 00000000: JMP [+6]
		UINT8 opcode1;
		UINT32 dummy;
		UINT64 address; // Absolute destination address
	};

	// 64-bit indirect absolute call.
	struct CALL_ABS
	{
		UINT8 opcode0; // FF15 00000002: CALL [+6]
		UINT8 opcode1;
		UINT32 dummy0;
		UINT8 dummy1; // EB 08:         JMP +10
		UINT8 dummy2;
		UINT64 address; // Absolute destination address
	};

	// 32-bit direct relative conditional jumps.
	struct JCC_REL
	{
		UINT8 opcode0; // 0F8* xxxxxxxx: J** +6+xxxxxxxx
		UINT8 opcode1;
		UINT32 operand; // Relative destination address
	};

	// 64bit indirect absolute conditional jumps that x64 lacks.
	struct JCC_ABS
	{
		UINT8 opcode; // 7* 0E:         J** +16
		UINT8 dummy0;
		UINT8 dummy1; // FF25 00000000: JMP [+6]
		UINT8 dummy2;
		UINT32 dummy3;
		UINT64 address; // Absolute destination address
	};

	// ReSharper restore CppInconsistentNaming
#pragma pack(pop)

	class trampoline2
	{
	public:
		trampoline2( );
		virtual ~trampoline2( );

		trampoline2(trampoline2&&) noexcept;
		trampoline2& operator=(trampoline2&&) noexcept;

		bool fix_page_protection( );
		bool create(LPVOID target, LPVOID detour);

		bool patch_above( ) const;

		LPVOID target( ) const;
		LPVOID detour( ) const;

		UINT8* trampoline( ) const;

	private:
		LPVOID target_ = nullptr;
		LPVOID detour_ = nullptr; // [In] Address of the detour function.
#if defined(_M_X64) || defined(__x86_64__)
		LPVOID pRelay_ = nullptr; // [Out] Address of the relay function.
#endif
		std::vector<uint8_t> trampoline_;

		bool patch_above_ = false; // [Out] Should use the hot patch area?
		//uint32_t ips_count   = 0;     // [Out] Number of the instruction boundaries.

		std::vector<uint8_t> old_ips_; // [Out] Instruction boundaries of the target function.
		std::vector<uint8_t> new_ips_; // [Out] Instruction boundaries of the trampoline function.

		nstd::mem::protect old_protection_;
	};
}
