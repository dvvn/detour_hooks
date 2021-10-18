#include "status.h"

#include <nstd/runtime_assert_fwd.h>

#include <array>
#include <ranges>

using namespace dhooks;

static constexpr auto _Status_to_string_cache = []
{
	using hook_status_raw = std::underlying_type_t<hook_status>;

#define STATUS_STR(x) data[static_cast<hook_status_raw>(hook_status::x)].first = /*CRYPT_STR*/(#x);

	auto data = std::array<std::pair<std::string_view, hook_status>, static_cast<hook_status_raw>(hook_status::COUNT)>( );
	for (size_t i = 0; i < data.size( ); ++i)
	{
		data[i].second = static_cast<hook_status>(i);
	}

	STATUS_STR(UNKNOWN)
	STATUS_STR(OK)
	//STATUS_STR(ERROR_ALREADY_INITIALIZED)
	//STATUS_STR(ERROR_NOT_INITIALIZED)
	STATUS_STR(ERROR_ALREADY_CREATED)
	STATUS_STR(ERROR_NOT_CREATED)
	STATUS_STR(ERROR_ENABLED)
	STATUS_STR(ERROR_DISABLED)
	STATUS_STR(ERROR_NOT_EXECUTABLE)
	STATUS_STR(ERROR_UNSUPPORTED_FUNCTION)
	STATUS_STR(ERROR_MEMORY_ALLOC)
	STATUS_STR(ERROR_MEMORY_PROTECT)
	STATUS_STR(ERROR_MODULE_NOT_FOUND)
	STATUS_STR(ERROR_FUNCTION_NOT_FOUND)
	STATUS_STR(ERROR_VTABLE_NOT_FOUND)
	STATUS_STR(ERROR_NOT_READABLE)

#undef STATUS_STR

#ifdef _DEBUG
	for (const auto& key : data | std::ranges::views::keys)
	{
		if (key == std::remove_cvref_t<decltype(key)>( ))
		{
			if (std::is_constant_evaluated( ))
				throw std::exception("Element isn't set!");
				// ReSharper disable once CppRedundantElseKeywordInsideCompoundStatement
			else
				// ReSharper disable once CppUnreachableCode
				runtime_assert("Element isn't set!");
		}
	}
#endif

	return data;
}( );

std::string_view dhooks::hook_status_to_string(hook_status status)
{
	try
	{
		return _Status_to_string_cache[static_cast<std::underlying_type_t<hook_status>>(status)].first;
	}
	catch (...)
	{
		return /*CRYPT_STR*/"Unsupported status";
	}
}
