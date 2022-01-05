module;

#include <nstd/runtime_assert.h>

#include "includes.h"

module dhooks;
using namespace dhooks;

hook_holder_data::hook_holder_data( )
{
	const auto& sctx = current_context::share( );
	runtime_assert(sctx != nullptr, "Context isn't set!");
	wctx = sctx;
} 

hook_holder_data::~hook_holder_data( )
{
	unhook( );
}

hook_holder_data::hook_holder_data(hook_holder_data&&) noexcept = default;
hook_holder_data& hook_holder_data::operator=(hook_holder_data&&) noexcept = default;

bool hook_holder_data::hook( )
{
	/*if (!impl_)
		impl_ = std::make_unique<impl>( );
	const auto original = impl_->hook(this->get_target_method( ), this->get_replace_method( ));
	if (!original)
		return false;
	this->set_original_func(original);
	return true;*/

	const auto lock = std::scoped_lock(mtx);
	runtime_assert(!active);
	active = true;
	runtime_assert(!target);
	target = this->get_target_method( );
	runtime_assert(!replace);
	replace = this->get_replace_method( );

	const auto ctx = this->get_ctx( );
	const auto result = ctx->create_hook(target, replace);

	if (result.status != hook_status::OK)
	{
		runtime_assert(std::format("Unable to hook function: {}", hook_status_to_string(result.status)).c_str( ));
		return nullptr;
	}

	const auto original = result.entry->trampoline( )/*._Unchecked_begin( )*/;
	if (!original)
		return false;
	this->set_original_func(original);
	return true;
}

bool hook_holder_data::unhook( )
{
	/*if (!impl_)
		return false;
	return impl_->unhook( );*/

	const auto _false = [&]
	{
		after_call.unhook = false;
		return false;
	};

	if (!active)
		return _false( );

	const auto lock = std::scoped_lock(mtx);
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

void hook_holder_data::unhook_after_call( )
{
	after_call.unhook = true;
}

bool hook_holder_data::enable( )
{
	if (!active)
		return false;

	const auto lock = std::scoped_lock(mtx);
	const auto ctx = this->get_ctx( );

	return ctx->enable_hook(target) == hook_status::OK;
}

bool hook_holder_data::disable( )
{
	if (!active)
	{
		after_call.disable = false;
		return false;
	}

	const auto lock = std::scoped_lock(mtx);
	const auto ctx = this->get_ctx( );
	const auto ret = ctx->disable_hook(target) == hook_status::OK;

	after_call.disable = false;
	return ret;
}

void hook_holder_data::disable_after_call( )
{
	after_call.disable = true;
}

bool hook_holder_data::hooked( ) const
{
	if (!active)
		return false;

	const auto lock = std::scoped_lock(mtx);
	const auto ctx = this->get_ctx( );

	return ctx->find_hook(target).status == hook_status::OK;
}

bool hook_holder_data::enabled( ) const
{
	if (!active)
		return false;

	const auto lock = std::scoped_lock(mtx);
	const auto ctx = this->get_ctx( );
	const auto hook = ctx->find_hook(target);

	if (hook.status != hook_status::OK)
		return false;
	return hook.entry->enabled( );
}

bool hook_holder_data::unhook_after_call_if_wanted( )
{
	return after_call.unhook && this->unhook( );
}

bool hook_holder_data::disable_after_call_if_wanted( )
{
	return after_call.disable && this->disable( );
}




