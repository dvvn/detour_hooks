module;

#include <nstd/runtime_assert.h>

#include "includes.h"

module dhooks;

using namespace dhooks;
bool hook_holder_data::hook( )
{
	const auto lock = std::scoped_lock(mtx);
	runtime_assert(!this->hooked( ), "Hook already set!");
	runtime_assert(!target);
	target = this->get_target_method( );
	runtime_assert(!replace);
	replace = this->get_replace_method( );

	auto result = entry.create(target, replace);
	if (/*result.status != hook_status::OK*/!result)
	{
		runtime_assert("Unable to hook function!");
		return false;
	}

	const auto original = entry.trampoline.data( );
	this->set_original_func(original);
	return true;
}

bool hook_holder_data::unhook( )
{
	if (!this->hooked( ))
		return false;

	const auto lock = std::scoped_lock(mtx);

	after_call.reset( );
	replace = target = nullptr;

	return entry.disable( );
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
	return entry.enable( );
}

bool hook_holder_data::disable( )
{
	if (!this->hooked( ))
		return 0;

	after_call.disable = false;
	return entry.disable( );
}

void hook_holder_data::disable_after_call( )
{
	//runtime_assert(this->hooked( ));
	after_call.disable = true;
}

bool hook_holder_data::hooked( ) const
{
	return replace && target;
}

bool hook_holder_data::enabled( ) const
{
	return this->hooked( ) && entry.enabled;
}

bool hook_holder_data::unhook_after_call_if_wanted( )
{
	return after_call.unhook && this->unhook( );
}

bool hook_holder_data::disable_after_call_if_wanted( )
{
	return after_call.disable && this->disable( );
}
