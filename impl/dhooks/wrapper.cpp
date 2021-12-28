#include "wrapper.h"
#include "entry.h"

#include <nstd/runtime_assert.h>

#include <mutex>

using namespace dhooks;

struct hook_holder_data::impl
{
    mutable std::mutex mtx;
    std::atomic_bool active = false;
    std::weak_ptr<basic_context> wctx;

    std::shared_ptr<basic_context> get_ctx( ) const
    {
#ifdef _DEBUG
        return std::shared_ptr(wctx);
#else
        return wctx.lock( );
#endif
    }

    struct
    {
        std::atomic_bool unhook  = false;
        std::atomic_bool disable = false;

        void reset( )
        {
            unhook = disable = false;
        }
    } after_call;

    void* target  = nullptr;
    void* replace = nullptr;

    void* hook(void* target_fn, void* replace_fn)
    {
        const auto lock = std::scoped_lock(mtx);
        runtime_assert(!active);
        active = true;
        runtime_assert(!target);
        target = target_fn;
        runtime_assert(!replace);
        replace = replace_fn;

        const auto ctx    = this->get_ctx( );
        const auto result = ctx->create_hook(target, replace);

        if (result.status != hook_status::OK)
        {
            runtime_assert(std::format("Unable to hook function: {}",hook_status_to_string(result.status)).c_str());
            return nullptr;
        }

        return result.entry->trampoline( )/*._Unchecked_begin( )*/;
    }

    bool unhook( )
    {
        const auto _false = [&]
        {
            after_call.unhook = false;
            return false;
        };

        if (!active)
            return _false( );

        const auto lock    = std::scoped_lock(mtx);
        const auto expired = wctx.expired( );

        if (!expired)
        {
            const auto ctx = this->get_ctx( );
            if (ctx->remove_hook(target, true) != hook_status::OK)
                return _false( );
        }

        active = false;
        after_call.reset( );
        replace = target = nullptr;

        return !expired;
    }

    void unhook_after_call( )
    {
        after_call.unhook = true;
    }

    // ReSharper disable once CppMemberFunctionMayBeConst
    bool enable( )
    {
        if (!active)
            return false;

        const auto lock = std::scoped_lock(mtx);
        const auto ctx  = this->get_ctx( );

        return ctx->enable_hook(target) == hook_status::OK;
    }

    bool disable( )
    {
        if (!active)
        {
            after_call.disable = false;
            return false;
        }

        const auto lock = std::scoped_lock(mtx);
        const auto ctx  = this->get_ctx( );
        const auto ret  = ctx->disable_hook(target) == hook_status::OK;

        after_call.disable = false;
        return ret;
    }

    void disable_after_call( )
    {
        after_call.disable = true;
    }

    bool hooked( ) const
    {
        if (!active)
            return false;

        const auto lock = std::scoped_lock(mtx);
        const auto ctx  = this->get_ctx( );

        return ctx->find_hook(target).status == hook_status::OK;
    }

    bool enabled( ) const
    {
        if (!active)
            return false;

        const auto lock = std::scoped_lock(mtx);
        const auto ctx  = this->get_ctx( );
        const auto hook = ctx->find_hook(target);

        if (hook.status != hook_status::OK)
            return false;
        return hook.entry->enabled( );
    }

    impl( )
    {
        const auto& sctx = current_context::get( );
        runtime_assert(sctx != nullptr, "Context isn't set!");
        wctx = sctx;
    }

    bool unhook_after_call_if_wanted( )
    {
        return after_call.unhook && this->unhook( );
    }

    bool disable_after_call_if_wanted( )
    {
        return after_call.disable && this->disable( );
    }
};

hook_holder_data::hook_holder_data( )
{
}

bool hook_holder_data::hook( )
{
    if (!impl_)
        impl_ = std::make_unique<impl>( );
    const auto original = impl_->hook(this->get_target_method( ), this->get_replace_method( ));
    if (!original)
        return false;
    this->set_original_func(original);
    return true;
}

bool hook_holder_data::unhook( )
{
    if (!impl_)
        return false;
    return impl_->unhook( );
}

void hook_holder_data::unhook_after_call( )
{
    impl_->unhook_after_call( );
}

bool hook_holder_data::enable( )
{
    return impl_->enable( );
}

bool hook_holder_data::disable( )
{
    return impl_->disable( );
}

void hook_holder_data::disable_after_call( )
{
    impl_->disable_after_call( );
}

bool hook_holder_data::hooked( ) const
{
    return impl_->hooked( );
}

bool hook_holder_data::enabled( ) const
{
    return impl_->enabled( );
}

hook_holder_data::~hook_holder_data( )
{
    unhook( );
}

hook_holder_data::hook_holder_data(hook_holder_data&&) noexcept            = default;
hook_holder_data& hook_holder_data::operator=(hook_holder_data&&) noexcept = default;

// ReSharper disable once CppMemberFunctionMayBeConst
bool hook_holder_data::unhook_after_call_if_wanted( )
{
    return impl_->unhook_after_call_if_wanted( );
}

// ReSharper disable once CppMemberFunctionMayBeConst
void hook_holder_data::disable_after_call_if_wanted( )
{
    impl_->disable_after_call_if_wanted( );
}

//---

