#include "hook_utils.h"

#ifdef _DEBUG
#include <intrin.h>
#endif

using namespace dhooks;
using namespace dhooks::detail;

nstd::address method_info::get_target_method( )
{
	if (target_method_ == nullptr)
		target_method_ = this->get_target_method_impl( );

	return target_method_;
}

nstd::address method_info::get_target_method( ) const
{
	runtime_assert(target_method_ != nullptr);
	return target_method_;
}

void detail::_Call_fn_trap(call_conversion original, call_conversion called)
{
#ifdef _DEBUG
	[[maybe_unused]] const auto a = _ReturnAddress( );
	[[maybe_unused]] const auto b = _AddressOfReturnAddress( );
	constexpr auto              _ = 0;
#endif // _DEBUG
}

void detail::_Call_fn_trap(call_conversion original)
{
	_Call_fn_trap(original, original);
}
