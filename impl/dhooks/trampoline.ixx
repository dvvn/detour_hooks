module;

#include <vector>

export module dhooks:trampoline;
import nstd.mem.protect;

export namespace dhooks
{
	// Structs for writing x86/x64 instructions.

#pragma pack(push, 1)

	// 8-bit relative jump.
	struct  JMP_REL_SHORT
	{
		uint8_t opcode; // EB xx: JMP +2+xx
		uint8_t operand;
	};
	static_assert(sizeof(JMP_REL_SHORT) == (sizeof(uint8_t) * 2));

	// 32-bit direct relative jump/call.
	struct  JMP_REL
	{
		uint8_t opcode;   // E9/E8 xxxxxxxx: JMP/CALL +5+xxxxxxxx
		uint32_t operand; // Relative destination address
	};
	static_assert(sizeof(JMP_REL) == (sizeof(uint8_t) + sizeof(uint32_t)));

	using CALL_REL = JMP_REL;
	// 64-bit indirect absolute jump.

	struct JMP_ABS
	{
		uint8_t opcode0; // FF25 00000000: JMP [+6]
		uint8_t opcode1;
		uint32_t dummy;
		uint64_t address; // Absolute destination address
	};
	static_assert(sizeof(JMP_ABS) == (sizeof(uint8_t) * 2 + sizeof(uint32_t) + sizeof(uint64_t)));

	// 64-bit indirect absolute call.
	struct CALL_ABS
	{
		uint8_t opcode0; // FF15 00000002: CALL [+6]
		uint8_t opcode1;
		uint32_t dummy0;
		uint8_t dummy1; // EB 08:         JMP +10
		uint8_t dummy2;
		uint64_t address; // Absolute destination address
	};
	static_assert(sizeof(CALL_ABS) == (sizeof(uint8_t) * 4 + sizeof(uint32_t) + sizeof(uint64_t)));

	// 32-bit direct relative conditional jumps.
	struct JCC_REL
	{
		uint8_t opcode0; // 0F8* xxxxxxxx: J** +6+xxxxxxxx
		uint8_t opcode1;
		uint32_t operand; // Relative destination address
	};
	static_assert(sizeof(JCC_REL) == (sizeof(uint8_t) * 2 + sizeof(uint32_t)));

	// 64bit indirect absolute conditional jumps that x64 lacks.
	struct JCC_ABS
	{
		uint8_t opcode; // 7* 0E:         J** +16
		uint8_t dummy0;
		uint8_t dummy1; // FF25 00000000: JMP [+6]
		uint8_t dummy2;
		uint32_t dummy3;
		uint64_t address; // Absolute destination address
	};
	static_assert(sizeof(JCC_ABS) == (sizeof(uint8_t) * 4 + sizeof(uint32_t) + sizeof(uint64_t)));

#pragma pack(push, 1)

	struct trampoline2
	{
		using trampoline_type = std::vector<uint8_t>;

		trampoline2( );
		virtual ~trampoline2( );

		trampoline2(trampoline2&&) noexcept;
		trampoline2& operator=(trampoline2&&) noexcept;

		bool fix_page_protection( );
		virtual bool create( );
		bool created( )const;
		void* get_original_method( )const;

		void* target = nullptr;
		void* detour = nullptr; // [In] Address of the detour function.
#if defined(_M_X64) || defined(__x86_64__)
		void* pRelay = nullptr; // [Out] Address of the relay function.
#endif
		bool patch_above = false; // [Out] Should use the hot patch area?
		//uint32_t_t ips_count   = 0;     // [Out] Number of the instruction boundaries.

	private:
		std::vector<uint8_t> old_ips_; // [Out] Instruction boundaries of the target function.
		std::vector<uint8_t> new_ips_; // [Out] Instruction boundaries of the trampoline function.

		trampoline_type trampoline_;
		nstd::mem::protect old_protection_;
	};
}
