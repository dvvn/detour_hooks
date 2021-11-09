#pragma once

#include "trampoline.h"
#include "status.h"

#include "context.h"

namespace dhooks
{
    class hook_entry final : public detail::trampoline2
    {
    public:
        hook_entry( );
        ~hook_entry( ) override;

        hook_entry(hook_entry&&) noexcept;
        hook_entry& operator=(hook_entry&&) noexcept;

        hook_status set_state(bool enable);

        bool enabled( ) const;
        void init_backup(LPVOID from, size_t bytes_count);
        void mark_disabled( );
    private:
        struct impl;
        std::unique_ptr<impl> impl_;
    };
}
