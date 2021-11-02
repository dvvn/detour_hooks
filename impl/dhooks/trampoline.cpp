#include "trampoline.h"

#include "hde/include.h"

#include <nstd/memory block.h>
#include <nstd/memory protect.h>
#include <nstd/runtime_assert_fwd.h>

#include <Windows.h>

#include <vector>

using namespace dhooks::detail;
using namespace dhooks;
//bool dhooks::detail::_Is_code_padding(LPBYTE pInst, UINT size)
//{
//	
//}
//
//bool dhooks::detail::_Is_address_readable(LPVOID addr, size_t mem_size)
//{
//	return memory_block(addr, mem_size).readable_ex( );
//}
//
//bool dhooks::detail::_Is_address_executable(LPVOID addr, size_t mem_size)
//{
//	return memory_block(addr, mem_size).executable( );
//}

struct trampoline2::impl
{
	LPVOID target = nullptr;
	LPVOID detour = nullptr; // [In] Address of the detour function.
#if defined(_M_X64) || defined(__x86_64__)
		LPVOID pRelay=nullptr; // [Out] Address of the relay function.
#endif
	std::vector<uint8_t> trampoline;

	bool patch_above = false; // [Out] Should use the hot patch area?
	//uint32_t ips_count   = 0;     // [Out] Number of the instruction boundaries.

	std::vector<uint8_t> old_ips; // [Out] Instruction boundaries of the target function.
	std::vector<uint8_t> new_ips; // [Out] Instruction boundaries of the trampoline function.

	nstd::memory_protect old_protection;
};

trampoline2::trampoline2( )
{
	impl_ = std::make_unique<impl>( );
}

trampoline2::~trampoline2( )                                = default;
trampoline2::trampoline2(trampoline2&&) noexcept            = default;
trampoline2& trampoline2::operator=(trampoline2&&) noexcept = default;

bool trampoline2::fix_page_protection( )
{
	runtime_assert(!impl_->old_protection.has_value());

	const auto buff      = impl_->trampoline.data( );
	const auto buff_size = impl_->trampoline.size( );

	if (!nstd::memory_block(buff, buff_size).executable( ))
	{
		try
		{
			impl_->old_protection = {buff, buff_size, PAGE_EXECUTE_READWRITE};
		}
		catch (const std::exception&)
		{
			return false;
		}
	}

	return true;
}

bool trampoline2::create(LPVOID target, LPVOID detour)
{
	auto& ct = *this->impl_;

	ct.target = target;
	ct.detour = detour;

#if defined(_M_X64) || defined(__x86_64__)
    CALL_ABS call = {
        0xFF, 0x15, 0x00000002, // FF15 00000002: CALL [RIP+8]
        0xEB, 0x08,             // EB 08:         JMP +10
        0x0000000000000000ULL   // Absolute destination address
    };
    JMP_ABS jmp = {
        0xFF, 0x25, 0x00000000, // FF25 00000000: JMP [RIP+6]
        0x0000000000000000ULL   // Absolute destination address
    };
    JCC_ABS jcc = {
        0x70, 0x0E,             // 7* 0E:         J** +16
        0xFF, 0x25, 0x00000000, // FF25 00000000: JMP [RIP+6]
        0x0000000000000000ULL   // Absolute destination address
    };
#else
	CALL_REL call = {
			0xE8,      // E8 xxxxxxxx: CALL +5+xxxxxxxx
			0x00000000 // Relative destination address
	};
	JMP_REL jmp = {
			0xE9,      // E9 xxxxxxxx: JMP +5+xxxxxxxx
			0x00000000 // Relative destination address
	};
	JCC_REL jcc = {
			0x0F, 0x80, // 0F8* xxxxxxxx: J** +6+xxxxxxxx
			0x00000000  // Relative destination address
	};
#endif

	UINT8 old_pos      = 0;
	UINT8 new_pos      = 0;
	ULONG_PTR jmp_dest = 0;     // Destination address of an internal jump.
	bool finished      = false; // Is the function completed?
#if defined(_M_X64) || defined(__x86_64__)
    UINT8 instBuf[16];
#endif

	//ct.patch_above = false;
	//ct.ips_count   = 0;

	do
	{
		HDE_data hs;
		uint8_t copy_size = 0;
		ULONG_PTR new_inst;
		const auto old_inst = reinterpret_cast<ULONG_PTR>(ct.target) + old_pos;

		// ReSharper disable once CppInconsistentNaming
		const auto _Set_copy_size = [&](uint8_t size)
		{
			if (copy_size < size)
			{
				auto& tr = ct.trampoline;

				const auto size_diff = size - copy_size;
				/*const auto pad       = [&]( )-> size_t
				{
					const auto     estimate_size = tr.size( ) + size_diff;
					constexpr auto delim         = sizeof(ULONG_PTR);
					if (estimate_size < delim)
						return delim - estimate_size;
					if (estimate_size > delim)
						return estimate_size % delim;
					return 0;
				}( );*/
				tr.insert(std::next(tr.begin( ), new_pos + copy_size), size_diff /*+ pad*/, -1);

				new_inst = reinterpret_cast<ULONG_PTR>(tr.data( )) + new_pos;
			}
			copy_size = size;
		};

		_Set_copy_size(_HDE_disasm(reinterpret_cast<LPVOID>(old_inst), &hs));
		if (hs.flags & hde::F_ERROR)
			return false;

		auto copy_src = reinterpret_cast<LPVOID>(old_inst);
		if (old_pos >= sizeof(JMP_REL))
		{
			copy_src = &jmp;
			_Set_copy_size(sizeof(decltype(jmp)));

			// The trampoline function is long enough.
			// Complete the function with the jump to the target function.
#if defined(_M_X64) || defined(__x86_64__)
            jmp.address = old_inst;
#else
			jmp.operand = static_cast<UINT32>(old_inst - (new_inst + copy_size));
#endif

			finished = true;
		}
#if defined(_M_X64) || defined(__x86_64__)
        else if ((hs.modrm & 0xC7) == 0x05)
        {
            // Instructions using RIP relative addressing. (ModR/M = 00???101B)

            // Modify the RIP relative address.
            PUINT32 pRelAddr;

            // Avoid using memcpy to reduce the footprint.
            std::memcpy(instBuf, (LPBYTE)old_inst, copy_size);

            copy_src = instBuf;

            // Relative address is stored at (instruction length - immediate value length - 4).
            pRelAddr  = (PUINT32)(instBuf + hs.len - ((hs.flags & 0x3C) >> 2) - 4);
            *pRelAddr = static_cast<UINT32>(old_inst + hs.len + static_cast<INT32>(hs.disp.disp32) - (new_inst + hs.len));

            // Complete the function if JMP (FF /4).
            if (hs.opcode == 0xFF && hs.modrm_reg == 4)
                finished = true;
        }
#endif
		else if (hs.opcode == 0xE8)
		{
			copy_src = &call;
			_Set_copy_size(sizeof(decltype(call)));

			// Direct relative CALL
			const auto dest = old_inst + hs.len + static_cast<INT32>(hs.imm.imm32);
#if defined(_M_X64) || defined(__x86_64__)
            call.address = dest;
#else
			call.operand = static_cast<UINT32>(dest - (new_inst + copy_size));
#endif
		}
		else if ((hs.opcode & 0xFD) == 0xE9)
		{
			// Direct relative JMP (EB or E9)
			auto dest = old_inst + hs.len;

			if (hs.opcode == 0xEB) // isShort jmp
				dest += static_cast<INT8>(hs.imm.imm8);
			else
				dest += static_cast<INT32>(hs.imm.imm32);

			// Simply copy an internal jump.
			if (reinterpret_cast<ULONG_PTR>(ct.target) <= dest && dest < reinterpret_cast<ULONG_PTR>(ct.target) + sizeof(JMP_REL))
			{
				if (jmp_dest < dest)
					jmp_dest = dest;
			}
			else
			{
				copy_src = &jmp;
				_Set_copy_size(sizeof(decltype(jmp)));

#if defined(_M_X64) || defined(__x86_64__)
                jmp.address = dest;
#else
				jmp.operand = static_cast<UINT32>(dest - (new_inst + copy_size));
#endif

				// Exit the function If it is not in the branch
				finished = old_inst >= jmp_dest;
			}
		}
		else if ((hs.opcode & 0xF0) == 0x70 || (hs.opcode & 0xFC) == 0xE0 || (hs.opcode2 & 0xF0) == 0x80)
		{
			// Direct relative Jcc
			auto dest = old_inst + hs.len;

			if ( // Jcc
				(hs.opcode & 0xF0) == 0x70 ||
				// LOOPNZ/LOOPZ/LOOP/JECXZ
				(hs.opcode & 0xFC) == 0xE0)
				dest += static_cast<INT8>(hs.imm.imm8);
			else
				dest += static_cast<INT32>(hs.imm.imm32);

			// Simply copy an internal jump.
			if (reinterpret_cast<ULONG_PTR>(ct.target) <= dest && dest < reinterpret_cast<ULONG_PTR>(ct.target) + sizeof(JMP_REL))
			{
				if (jmp_dest < dest)
					jmp_dest = dest;
			}
			else if ((hs.opcode & 0xFC) == 0xE0)
			{
				// LOOPNZ/LOOPZ/LOOP/JCXZ/JECXZ to the outside are not supported.
				return false;
			}
			else
			{
				copy_src = &jcc;
				_Set_copy_size(sizeof(decltype(jcc)));

				const UINT8 cond = (hs.opcode != 0x0F ? hs.opcode : hs.opcode2) & 0x0F;
#if defined(_M_X64) || defined(__x86_64__)
                // Invert the condition in x64 mode to simplify the conditional jump logic.
                jcc.opcode  = 0x71 ^ cond;
                jcc.address = dest;
#else
				jcc.opcode1 = 0x80 | cond;
				jcc.operand = static_cast<UINT32>(dest - (new_inst + copy_size));
#endif
			}
		}
		else if ((hs.opcode & 0xFE) == 0xC2)
		{
			// RET (C2 or C3)

			// Complete the function if not in a branch.
			finished = old_inst >= jmp_dest;
		}

		// Can't alter the instruction length in a branch.
		if (old_inst < jmp_dest && copy_size != hs.len)
			return false;

#if 0
		// Trampoline function is too large.
		if (new_pos + copy_size > this->buffer_size( ))
			return false;

		// Trampoline function has too many instructions.
		if (ct.ips_count >= /*ct.old_ips.size( )*/sizeof(ips_type))
			return false;
#endif

		ct.old_ips.push_back(old_pos);
		ct.new_ips.push_back(new_pos);

		std::memcpy(reinterpret_cast<LPVOID>(new_inst), copy_src, copy_size);

		new_pos += copy_size;
		old_pos += hs.len;
	}
	while (!finished);

	using namespace nstd;

	// Is there enough place for a long jump?
	if (old_pos < sizeof(JMP_REL) && !memory_block(address(ct.target) + old_pos, sizeof(JMP_REL) - old_pos).code_padding( ))
	{
		// Is there enough place for a short jump?
		if (old_pos < sizeof(JMP_REL_SHORT) && !memory_block(address(ct.target) + old_pos, sizeof(JMP_REL_SHORT) - old_pos).code_padding( ))
			return false;

		// Can we place the long jump above the function?
		if (!memory_block(address(ct.target) - sizeof(JMP_REL)).executable( ))
			return false;
		if (!memory_block(address(ct.target) - sizeof(JMP_REL), sizeof(JMP_REL)).code_padding( ))
			return false;

		ct.patch_above = true;
	}

#if defined(_M_X64) || defined(__x86_64__)
    // Create a relay function.
    jmp.address = reinterpret_cast<ULONG_PTR>(ct.pDetour);

    ct.pRelay = static_cast<LPBYTE>(ct.pTrampoline.get( )) + new_pos;
    
    std::memcpy(ct.pRelay, &jmp, sizeof jmp);
#endif

	return true;
}

bool trampoline2::patch_above( ) const
{
	return impl_->patch_above;
}

LPVOID trampoline2::target( ) const
{
	return impl_->target;
}

LPVOID trampoline2::detour( ) const
{
	return impl_->detour;
}

UINT8* trampoline2::trampoline( ) const
{
	auto& tr = impl_->trampoline;
	// ReSharper disable once CppRedundantCastExpression
	const auto begin = reinterpret_cast<uint8_t*>(tr._Unchecked_begin( ));
	//return {begin, tr.size( ) * sizeof(decltype(impl::trampoline)::value_type)};
	return begin;
}
