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
	swap(entry, other.entry);
	swap(disable_after_call_, other.disable_after_call_);
	return *this;
}

bool hook_holder_data::hook( )
{
	const auto lock = std::scoped_lock(mtx);
	auto result = entry.create( );
	if (/*result.status != hook_status::OK*/!result)
	{
		runtime_assert("Unable to hook function!");
		return false;
	}

	const auto original = entry.get_original_method( );
	this->set_original_method(original);
	return true;
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
		return false;

	const auto lock = std::scoped_lock(mtx);
	disable_after_call_ = false;
	return entry.disable( );
}

void hook_holder_data::disable_after_call( )
{
	//runtime_assert(this->hooked( ));
	disable_after_call_ = true;
}

bool hook_holder_data::hooked( ) const
{
	return entry.created( );
}

bool hook_holder_data::enabled( ) const
{
	return this->hooked( ) && entry.enabled;
}

void hook_holder_data::set_target_method(void* fn)
{
	runtime_assert(!entry.target || !entry.enabled);
	entry.target = fn;
}

void hook_holder_data::set_replace_method(void* fn)
{
	runtime_assert(!entry.detour || !entry.enabled);
	entry.detour = fn;
}

bool hook_holder_data::try_disable_after_call( )
{
	return disable_after_call_ && this->disable( );
}
