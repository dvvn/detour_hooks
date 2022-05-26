module;

#define NOMINMAX

#ifdef DHOOKS_X64
#include <hde64.h>
#else
#include <hde32.h>
#endif

#include <nstd/runtime_assert.h>

#include <Windows.h>

#include <vector>

module dhooks.entry;
import nstd.mem.block;

using namespace dhooks;

#if 1
#define VALIDATE_SIZE(...)
#else
template <typename... Ts>
constexpr size_t _Get_size()
{
	return (sizeof(Ts) + ...);
}
#define VALIDATE_SIZE(_NAME_,...) static_assert(sizeof(_NAME_) == _Get_size<__VA_ARGS__>( ))
#endif
#pragma pack(push, 1)

// 8-bit relative jump.
struct JMP_REL_SHORT
{
	uint8_t opcode; // EB xx: JMP +2+xx
	uint8_t operand;
};
VALIDATE_SIZE(JMP_REL_SHORT, uint8_t[2]);

// 32-bit direct relative jump/call.
struct JMP_REL
{
	uint8_t opcode;   // E9/E8 xxxxxxxx: JMP/CALL +5+xxxxxxxx
	uint32_t operand; // Relative destination address
};
VALIDATE_SIZE(JMP_REL, uint8_t, uint32_t);

using CALL_REL = JMP_REL;

// 64-bit indirect absolute jump.
struct JMP_ABS
{
	uint8_t opcode0; // FF25 00000000: JMP [+6]
	uint8_t opcode1;
	uint32_t dummy;
	uint64_t address; // Absolute destination address
};
VALIDATE_SIZE(JMP_ABS, uint8_t[2], uint32_t, uint64_t);

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
VALIDATE_SIZE(CALL_ABS, uint8_t[4], uint32_t, uint64_t);

// 32-bit direct relative conditional jumps.
struct JCC_REL
{
	uint8_t opcode0; // 0F8* xxxxxxxx: J** +6+xxxxxxxx
	uint8_t opcode1;
	uint32_t operand; // Relative destination address
};
VALIDATE_SIZE(JCC_REL, uint8_t[2], uint32_t);

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
VALIDATE_SIZE(JCC_ABS, uint8_t[4], uint32_t, uint64_t);

#pragma pack(pop)

//----------------------

hook_entry::hook_entry() = default;

hook_entry::~hook_entry()
{
	disable();
}

hook_entry::hook_entry(hook_entry&& other) = default;
hook_entry& hook_entry::operator=(hook_entry&& other) = default;

template <typename T>
static nstd::mem::block _To_mem_block(T* ptr)
{
	return { reinterpret_cast<uint8_t*>(ptr), std::max(sizeof(uintptr_t), sizeof(T)) };
}

static nstd::mem::block _To_mem_block(void* ptr)
{
	return { reinterpret_cast<uint8_t*>(ptr), sizeof(uintptr_t) };
}

template <typename T>
static nstd::mem::block _To_mem_block(T& rng)
{
	return { reinterpret_cast<uint8_t*>(rng.data()), rng.size() * sizeof(T::value_type) };
}

//template<class T>
//static bool _Have_flags(T && obj, DWORD flags)
//{
//	return _To_mem_block(obj).have_flags(flags);
//}

bool hook_entry::create()
{
	if (created())
		return 0;
	if (!target_)
		return 0;
	if (!detour_)
		return 0;
	if (target_ == detour_)
		return /*hook_status::ERROR_UNSUPPORTED_FUNCTION*/0;

	if (!_To_mem_block(target_).executable())
		return /*hook_status::ERROR_NOT_EXECUTABLE*/0;
	if (!_To_mem_block(detour_).executable())
		return /*hook_status::ERROR_NOT_EXECUTABLE*/0;

#ifdef DHOOKS_X64
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

	uint8_t old_pos = 0;
	uint8_t new_pos = 0;
	ULONG_PTR jmp_dest = 0;     // Destination address of an internal jump.
	bool finished = false; // Is the function completed?
#ifdef DHOOKS_X64
	uint8_t instBuf[16];
#endif

	do
	{
#ifdef DHOOKS_X64
		hde64s hs;
#else
		hde32s hs;
#endif
		uint8_t copy_size = 0;
		ULONG_PTR new_inst;
		const auto old_inst = reinterpret_cast<ULONG_PTR>(target_) + old_pos;
		//const address old_inst = old_pos ? address(target_) + old_pos : target_;

		// ReSharper disable once CppInconsistentNaming
		const auto _Set_copy_size = [&](uint8_t size)
		{
			if (copy_size < size)
			{
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
				trampoline_.insert(std::next(trampoline_.begin(), new_pos + copy_size), size_diff /*+ pad*/, -1);

				new_inst = reinterpret_cast<ULONG_PTR>(trampoline_.data()) + new_pos;
			}
			copy_size = size;
		};

#ifdef DHOOKS_X64
		_Set_copy_size(hde64_disasm(reinterpret_cast<void*>(old_inst), &hs));
#else
		_Set_copy_size(hde32_disasm(reinterpret_cast<void*>(old_inst), &hs));
#endif

		if (hs.flags & F_ERROR)
			return false;

		auto copy_src = reinterpret_cast<void*>(old_inst);
		if (old_pos >= sizeof(JMP_REL))
		{
			copy_src = &jmp;
			_Set_copy_size(sizeof(decltype(jmp)));

			// The trampoline function is long enough.
			// Complete the function with the jump to the target_ function.
#ifdef DHOOKS_X64
			jmp.address = old_inst;
#else
			jmp.operand = static_cast<uint32_t>(old_inst - (new_inst + copy_size));
#endif

			finished = true;
		}
#ifdef DHOOKS_X64
		else if ((hs.modrm & 0xC7) == 0x05)
		{
			// Instructions using RIP relative addressing. (ModR/M = 00???101B)

			// Modify the RIP relative address.
			uint32_t* pRelAddr;

			std::memcpy(instBuf, (LPBYTE)old_inst, copy_size);

			copy_src = instBuf;

			// Relative address is stored at (instruction length - immediate value length - 4).
			pRelAddr = (uint32_t*)(instBuf + hs.len - ((hs.flags & 0x3C) >> 2) - 4);
			*pRelAddr = static_cast<uint32_t>(old_inst + hs.len + static_cast<INT32>(hs.disp.disp32) - (new_inst + hs.len));

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
#ifdef DHOOKS_X64
			call.address = dest;
#else
			call.operand = static_cast<uint32_t>(dest - (new_inst + copy_size));
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
			if (reinterpret_cast<ULONG_PTR>(target_) <= dest && dest < reinterpret_cast<ULONG_PTR>(target_) + sizeof(JMP_REL))
			{
				if (jmp_dest < dest)
					jmp_dest = dest;
			}
			else
			{
				copy_src = &jmp;
				_Set_copy_size(sizeof(decltype(jmp)));

#ifdef DHOOKS_X64
				jmp.address = dest;
#else
				jmp.operand = static_cast<uint32_t>(dest - (new_inst + copy_size));
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
			if (reinterpret_cast<ULONG_PTR>(target_) <= dest && dest < reinterpret_cast<ULONG_PTR>(target_) + sizeof(JMP_REL))
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

				const uint8_t cond = (hs.opcode != 0x0F ? hs.opcode : hs.opcode2) & 0x0F;
#ifdef DHOOKS_X64
				// Invert the condition in x64 mode to simplify the conditional jump logic.
				jcc.opcode = 0x71 ^ cond;
				jcc.address = dest;
#else
				jcc.opcode1 = 0x80 | cond;
				jcc.operand = static_cast<uint32_t>(dest - (new_inst + copy_size));
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
		if (new_pos + copy_size > buffer_size())
			return false;

		// Trampoline function has too many instructions.
		if (ct.ips_count >= /*ct.old_ips.size( )*/sizeof(ips_type))
			return false;
#endif

#ifdef DHOOKS_ENTRY_STORE_IPS
		old_ips_.push_back(old_pos);
		new_ips_.push_back(new_pos);
#endif

		std::copy_n(static_cast<uint8_t*>(copy_src), copy_size, reinterpret_cast<uint8_t*>(new_inst));
		//std::memcpy(reinterpret_cast<void*>(new_inst), copy_src, copy_size);

		new_pos += copy_size;
		old_pos += hs.len;
} while (!finished);

const auto target_ptr = static_cast<uint8_t*>(target_);

// Is there enough place for a long jump?
if (old_pos < sizeof(JMP_REL) && !nstd::mem::block(target_ptr + old_pos, sizeof(JMP_REL) - old_pos).code_padding())
{
	// Is there enough place for a short jump?
	if (old_pos < sizeof(JMP_REL_SHORT) && !nstd::mem::block(target_ptr + old_pos, sizeof(JMP_REL_SHORT) - old_pos).code_padding())
		return false;

	const nstd::mem::block target_rel = { target_ptr - sizeof(JMP_REL), sizeof(JMP_REL) };

	// Can we place the long jump above the function?
	if (!target_rel.executable())
		return false;
	if (!target_rel.code_padding())
		return false;

	patch_above_ = true;
}

#ifdef DHOOKS_X64
// Create a relay function.
jmp.address = reinterpret_cast<ULONG_PTR>(ct.pDetour);

ct.pRelay = static_cast<LPBYTE>(trampoline_.data()) + new_pos;
WIP
std::memcpy(ct.pRelay, &jmp, sizeof jmp);

detour_ = ct.pRelay;
#endif

//correct trampoline memory access
if (!nstd::mem::block(trampoline_.data(), trampoline_.size()).have_flags(PAGE_EXECUTE_READWRITE))
{
	runtime_assert(!trampoline_protection_.has_value(), "Trampoline memory protection already fixed");
	trampoline_protection_ = { trampoline_.data(), trampoline_.size(), PAGE_EXECUTE_READWRITE };
	runtime_assert(trampoline_protection_.has_value(), "Unable to fix trampoline memory protection");
}

// Back up the target function.
runtime_assert(target_backup_.empty());
if (patch_above_)
target_backup_.assign(target_ptr - sizeof(JMP_REL), target_ptr /*- sizeof(JMP_REL) + sizeof(JMP_REL)*/ + sizeof(JMP_REL_SHORT));
else
target_backup_.assign(target_ptr, target_ptr + sizeof(JMP_REL));

return true;
}

bool hook_entry::created() const
{
	return !trampoline_.empty();
}

bool hook_entry::enabled() const
{
	return enabled_;
}

struct prepared_memory
{
	prepared_memory() = default;
	~prepared_memory()
	{
		if (block.empty())
			return;

		protect.restore();
		FlushInstructionCache(GetCurrentProcess(), block.data(), block.size());
	}

    prepared_memory(const prepared_memory&) = delete;

    prepared_memory(prepared_memory&& other)
    {
		using std::swap;
		swap(block, other.block);
		swap(protect, other.protect);
	}

	nstd::mem::block block;
	nstd::mem::protect protect;
};

static prepared_memory _Prepare_memory(void* target, bool patch_above)
{
	runtime_assert(target != nullptr);

	auto target_ptr = static_cast<uint8_t*>(target);
	auto target_ptr_size = sizeof(JMP_REL);

	if (patch_above)
	{
		target_ptr -= sizeof(JMP_REL);
		target_ptr_size += sizeof(JMP_REL_SHORT);
	}

	prepared_memory mem;
	mem.block = { target_ptr, target_ptr_size };

	//todo: wait if not readable
	//-----

	if (!mem.block.have_flags(PAGE_EXECUTE_READWRITE))
	{
		mem.protect = { target_ptr,target_ptr_size,PAGE_EXECUTE_READWRITE };
		runtime_assert(mem.protect.has_value());
	}

	return mem;
}

bool hook_entry::enable()
{
	if (enabled_)
		return false;
	const auto mem = _Prepare_memory(target_, patch_above_);
	if (mem.block.empty())
		return false;

	const auto jmp_rel = reinterpret_cast<JMP_REL*>(mem.block.data());
	jmp_rel->opcode = 0xE9;
	jmp_rel->operand = static_cast<UINT32>(static_cast<LPBYTE>(detour_) - (mem.block.data() + sizeof(JMP_REL)));
	if (patch_above_)
	{
		const auto short_jmp = static_cast<JMP_REL_SHORT*>(target_);
		short_jmp->opcode = 0xEB;
		short_jmp->operand = static_cast<UINT8>(0 - (sizeof(JMP_REL_SHORT) + sizeof(JMP_REL)));
	}

	enabled_ = true;
	return true;
}

bool hook_entry::disable()
{
	if (!enabled_)
		return false;
	const auto mem = _Prepare_memory(target_, patch_above_);
	if (mem.block.empty())
		return false;

	std::copy(target_backup_.begin(), target_backup_.end(), mem.block.data());
	enabled_ = false;
	return true;
}

void* hook_entry::get_original_method() const
{
	runtime_assert(created());
	auto ptr = trampoline_.data();
	return (void*)ptr;
}

void* hook_entry::get_target_method() const
{
	return target_;
}

void* hook_entry::get_replace_method() const
{
	return detour_;
}

void hook_entry::set_target_method(void* getter)
{
	runtime_assert(target_ == nullptr);
	runtime_assert(getter != nullptr);
	target_ = getter;
}

void hook_entry::set_replace_method(void* getter)
{
	runtime_assert(detour_ == nullptr);
	runtime_assert(getter != nullptr);
	detour_ = getter;
}
