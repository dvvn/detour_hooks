#include "entry.h"

#include <nstd/runtime_assert.h>

#include <Windows.h>

#include <vector>

import nstd.mem.block;

using namespace dhooks;
using namespace dhooks::detail;

struct hook_entry::impl
{
    bool enabled = false;
    std::vector<uint8_t> backup;

    ~impl( )
    {
        runtime_assert(enabled == false, "Unable to destroy enabled hook entry!");
    }
};

hook_entry::hook_entry( )
{
    impl_ = std::make_unique<impl>( );
}

hook_entry::~hook_entry( )                               = default;
hook_entry::hook_entry(hook_entry&&) noexcept            = default;
hook_entry& hook_entry::operator=(hook_entry&&) noexcept = default;

hook_status hook_entry::set_state(bool enable)
{
    if (this->enabled( ) == enable)
        return enable ? hook_status::ERROR_ENABLED : hook_status::ERROR_DISABLED;

    auto patch_target = static_cast<LPBYTE>(this->target( ));
    SIZE_T patch_size = sizeof(JMP_REL);

    const auto patch_above = this->patch_above( );

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
            jmp_rel->opcode    = 0xE9;
            jmp_rel->operand   = static_cast<UINT32>(static_cast<LPBYTE>(this->detour( )) - (patch_target + sizeof(JMP_REL)));
            if (patch_above)
            {
                const auto short_jmp = static_cast<JMP_REL_SHORT*>(this->target( ));
                short_jmp->opcode    = 0xEB;
                short_jmp->operand   = static_cast<UINT8>(0 - (sizeof(JMP_REL_SHORT) + sizeof(JMP_REL)));
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
        const auto backup = impl_->backup.data( );
        if (patch_above)
            memcpy(patch_target, backup, sizeof(JMP_REL) + sizeof(JMP_REL_SHORT));
        else
            memcpy(patch_target, backup, sizeof(JMP_REL));
    }

    VirtualProtect(patch_target, patch_size, old_protect, &old_protect);

    // Just-in-case measure.
    FlushInstructionCache(GetCurrentProcess( ), patch_target, patch_size);

    impl_->enabled = enable;

    return hook_status::OK;
}

bool hook_entry::enabled( ) const
{
    return impl_->enabled;
}

void hook_entry::init_backup(LPVOID from, size_t bytes_count)
{
    auto& b = impl_->backup;
    runtime_assert(b.empty());

    auto rng = nstd::mem::block(from, bytes_count);
    b.assign(rng.begin( ), rng.end( ));
}

void hook_entry::mark_disabled( )
{
    impl_->enabled = false;
}
