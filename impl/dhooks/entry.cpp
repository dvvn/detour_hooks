module;

#include <nstd/runtime_assert.h>
#include <nstd/mem/block_includes.h>

#include <Windows.h>

#include <vector>

module dhooks:entry;
import nstd.mem;

using namespace dhooks;

hook_entry::hook_entry( ) = default;

hook_entry::~hook_entry( )
{
	runtime_assert(enabled == false, "Unable to destroy enabled hook entry!");
}

hook_entry::hook_entry(hook_entry && other) noexcept
{
	*this = std::move(other);
}

hook_entry& hook_entry::operator=(hook_entry && other) noexcept
{
	*static_cast<trampoline2*>(this) = static_cast<trampoline2&&>(other);
	enabled = other.enabled;
	other.enabled = false;
	backup_ = std::move(other.backup_);
	return *this;
}

hook_status hook_entry::set_state(bool enable)
{
	if (this->enabled == enable)
		return enable ? hook_status::ERROR_ENABLED : hook_status::ERROR_DISABLED;

	auto patch_target = static_cast<LPBYTE>(this->target);
	SIZE_T patch_size = sizeof(JMP_REL);

	if (patch_above)
	{
		patch_target -= sizeof(JMP_REL);
		patch_size += sizeof(JMP_REL_SHORT);
	}

	DWORD old_protect;
	if (!VirtualProtect(patch_target, patch_size, PAGE_EXECUTE_READWRITE, &old_protect))
		return hook_status::ERROR_MEMORY_PROTECT;

	if (enable)
	{
		auto again = false;
		(void)again;
	_TRY_AGAIN:
		__try
		{
			const auto jmp_rel = reinterpret_cast<JMP_REL*>(patch_target);
			jmp_rel->opcode = 0xE9;
			jmp_rel->operand = static_cast<UINT32>(static_cast<LPBYTE>(this->detour) - (patch_target + sizeof(JMP_REL)));
			if (patch_above)
			{
				const auto short_jmp = static_cast<JMP_REL_SHORT*>(this->target);
				short_jmp->opcode = 0xEB;
				short_jmp->operand = static_cast<UINT8>(0 - (sizeof(JMP_REL_SHORT) + sizeof(JMP_REL)));
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			DWORD dummy;
			if (again || !VirtualProtect(patch_target, patch_size, PAGE_EXECUTE_READWRITE, &dummy))
			{
				VirtualProtect(patch_target, patch_size, old_protect, &dummy);
				return hook_status::ERROR_MEMORY_PROTECT;
			}
			again = true;
			goto _TRY_AGAIN;
		}
	}
	else
	{
		const auto backup = backup_.data( );
		if (patch_above)
			std::memcpy(patch_target, backup, sizeof(JMP_REL) + sizeof(JMP_REL_SHORT));
		else
			std::memcpy(patch_target, backup, sizeof(JMP_REL));
	}

	VirtualProtect(patch_target, patch_size, old_protect, &old_protect);

	// Just-in-case measure.
	FlushInstructionCache(GetCurrentProcess( ), patch_target, patch_size);

	enabled = enable;

	return hook_status::OK;
}

void hook_entry::init_backup(void* from, size_t bytes_count)
{
	runtime_assert(backup_.empty( ));
	auto rng = nstd::mem::block(from, bytes_count);
	backup_.assign(rng.begin( ), rng.end( ));
}
