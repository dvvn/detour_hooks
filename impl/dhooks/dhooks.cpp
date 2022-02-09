module;

#include <nstd/runtime_assert.h>

#include "includes.h"

module dhooks;

using namespace dhooks;

hook_holder_data::hook_holder_data( ) = default;

hook_holder_data::hook_holder_data(hook_holder_data && other)noexcept
{
	*this = std::move(other);
}

hook_holder_data& hook_holder_data::operator=(hook_holder_data && other)noexcept
{
	using std::swap;
	swap(entry_, other.entry_);
	swap(disable_after_call_, other.disable_after_call_);
	return *this;
}

bool hook_holder_data::hook( )
{
	const auto lock = std::scoped_lock(mtx_);
	auto result = entry_.create( );
	if (/*result.status != hook_status::OK*/!result)
	{
		runtime_assert("Unable to hook function!");
		return false;
	}

	const auto original = entry_.get_original_method( );
	this->set_original_method(original);
	return true;
}

bool hook_holder_data::enable( )
{
	if (!this->hooked( ))
		return false;

	const auto lock = std::scoped_lock(mtx_);
	return entry_.enable( );
}

bool hook_holder_data::disable( )
{
	if (!this->hooked( ))
		return false;

	const auto lock = std::scoped_lock(mtx_);
	disable_after_call_ = false;
	return entry_.disable( );
}

void hook_holder_data::request_disable( )
{
	//runtime_assert(this->hooked( ));
	disable_after_call_ = true;
}

bool hook_holder_data::hooked( ) const
{
	return entry_.created( );
}

bool hook_holder_data::enabled( ) const
{
	return this->hooked( ) && entry_.enabled;
}

void hook_holder_data::set_target_method(void* fn)
{
	runtime_assert(!entry_.target || !entry_.enabled);
	entry_.target = fn;
}

void hook_holder_data::set_replace_method(void* fn)
{
	runtime_assert(!entry_.detour || !entry_.enabled);
	entry_.detour = fn;
}

bool hook_holder_data::process_disable_request( )
{
	return disable_after_call_ && this->disable( );
}
