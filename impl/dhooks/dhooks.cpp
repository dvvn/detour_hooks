module;

#include <nstd/runtime_assert.h>

#include "includes.h"

module dhooks;

using namespace dhooks;

hook_holder_data::hook_holder_data( ) = default;

hook_holder_data::~hook_holder_data( )
{
	this->unhook( );
}

//hook_holder_data::hook_holder_data(hook_holder_data&&) noexcept = default;
//hook_holder_data& hook_holder_data::operator=(hook_holder_data&&) noexcept = default;

bool hook_holder_data::hook( )
{
	const auto lock = std::scoped_lock(mtx);
	runtime_assert(!this->hooked( ), "Hook already set!");
	const auto ctx = current_context::share( );
	runtime_assert(ctx != nullptr, "Context isn't set!");
	runtime_assert(!target);
	target = this->get_target_method( );
	runtime_assert(!replace);
	replace = this->get_replace_method( );

	auto result = ctx->create_hook(target, replace);
	if (result.status != hook_status::OK)
	{
		runtime_assert(std::string("Unable to hook function: ").append(hook_status_to_string(result.status)).c_str( ));
		return false;
	}

	const auto original = result.entry->trampoline.data( );
	if (!original)
		return false;
	this->set_original_func(original);
	entry = std::move(result.entry);
	return true;
}

bool hook_holder_data::unhook( )
{
	if (!this->hooked( ))
		return false;

	const auto lock = std::scoped_lock(mtx);
	const auto ctx = current_context::share( );

	bool result;

	//remove from context
	if (ctx && ctx->find_hook(target).entry == entry)
		result = ctx->remove_hook(target, true) == hook_status::OK;
	else
		result = entry->set_state(false) == hook_status::OK;

	entry.reset( );
	after_call.reset( );
	replace = target = nullptr;

	return result;
}

void hook_holder_data::unhook_after_call( )
{
	//runtime_assert(this->hooked( ));
	after_call.unhook = true;
}

bool hook_holder_data::enable( )
{
	if (!this->hooked( ))
		return false;

	const auto lock = std::scoped_lock(mtx);
	return entry->set_state(true) == hook_status::OK;
}

bool hook_holder_data::disable( )
{
	bool result;
	if (!this->hooked( ))
	{
		result = false;
	}
	else
	{
		const auto lock = std::scoped_lock(mtx);
		result = entry->set_state(false) == hook_status::OK;
	}

	after_call.disable = false;
	return result;
}
 
void hook_holder_data::disable_after_call( )
{
	//runtime_assert(this->hooked( ));
	after_call.disable = true;
}

bool hook_holder_data::hooked( ) const
{
	return entry != nullptr;
}

bool hook_holder_data::enabled( ) const
{
	return this->hooked( ) && entry->enabled;
}

bool hook_holder_data::unhook_after_call_if_wanted( )
{
	return after_call.unhook && this->unhook( );
}

bool hook_holder_data::disable_after_call_if_wanted( )
{
	return after_call.disable && this->disable( );
}
