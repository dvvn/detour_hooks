module;

#include <nstd/runtime_assert.h>
#include <nstd/mem/block_includes.h>

#include <Windows.h>

#include <vector>

module dhooks:entry;

using namespace dhooks;

hook_entry::hook_entry( ) = default;

hook_entry::~hook_entry( )
{
	this->disable( );
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

bool hook_entry::create()
{
	

#if 0
	const auto check_ptr_helper = [&](void* checked)
	{
		return checked == target || checked == detour;
	};
	for (const auto& value : storage_)
	{
		if (check_ptr_helper(value->target) || check_ptr_helper(value->detour))
			return /*hook_status::ERROR_ALREADY_CREATED*/0;
	}
#endif

	if (!trampoline2::create())
		return /*hook_status::ERROR_UNSUPPORTED_FUNCTION*/0;
	if (!this->fix_page_protection( ))
		return /*hook_status::ERROR_MEMORY_PROTECT*/0;

#if defined(_M_X64) || defined(__x86_64__)
	this->detour = ct.pRelay;
#endif
	// Back up the target function.

	if (this->patch_above)
		this->init_backup(static_cast<LPBYTE>(target) - sizeof(JMP_REL), sizeof(JMP_REL) + sizeof(JMP_REL_SHORT));
	else
		this->init_backup(target, sizeof(JMP_REL));

	return 1;
	//storage_.push_back(new_hook);
	//return {hook_status::OK,std::move(new_hook)};
}

bool hook_entry::enable( )
{
	const auto status = this->set_state(true);
	return status == hook_status::OK;
}

bool hook_entry::disable( )
{
	const auto status = this->set_state(false);
	return status == hook_status::OK;
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
		std::memcpy(patch_target, backup_.data( ), backup_.size( ));
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
	auto begin = (uint8_t*)from;
	backup_.assign(begin, begin + bytes_count);
}
