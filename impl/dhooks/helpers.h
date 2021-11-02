#pragma once

#include <type_traits>

using LPVOID = void*;

namespace dhooks
{
	template <typename C>
	LPVOID* _Pointer_to_virtual_class_table(C* instance)
	{
		return *(LPVOID**)instance;
	}

	enum class call_conversion
	{
		// ReSharper disable CppInconsistentNaming
		thiscall__
	  , cdecl__
	  , stdcall__
	  , vectorcall__
	  , fastcall__
		// ReSharper restore CppInconsistentNaming
	};

	namespace detail
	{
		template <typename Fn>
		LPVOID _Ptr_to_fn(Fn fn)
		{
			const auto ptr = reinterpret_cast<void*&>(fn);
			return ptr;
		}
	}

	template <typename Ret, typename C, typename ...Args>
	LPVOID _Pointer_to_class_method(Ret (__thiscall C::*fn)(Args ...))
	{
		return detail::_Ptr_to_fn(fn);
	}

	template <typename Ret, typename C, typename ...Args>
	LPVOID _Pointer_to_class_method(Ret (__thiscall C::*fn)(Args ...) const)
	{
		return detail::_Ptr_to_fn(fn);
	}

	template <typename Ret, typename C, typename ...Args>
	LPVOID _Pointer_to_class_method(Ret (__fastcall C::*fn)(Args ...))
	{
		return detail::_Ptr_to_fn(fn);
	}

	template <typename Ret, typename C, typename ...Args>
	LPVOID _Pointer_to_class_method(Ret (__fastcall C::*fn)(Args ...) const)
	{
		return detail::_Ptr_to_fn(fn);
	}

	template <typename Ret, typename C, typename ...Args>
	LPVOID _Pointer_to_class_method(Ret (__stdcall C::*fn)(Args ...))
	{
		return detail::_Ptr_to_fn(fn);
	}

	template <typename Ret, typename C, typename ...Args>
	LPVOID _Pointer_to_class_method(Ret (__stdcall C::*fn)(Args ...) const)
	{
		return detail::_Ptr_to_fn(fn);
	}

	template <typename Ret, typename C, typename ...Args>
	LPVOID _Pointer_to_class_method(Ret (__cdecl C::*fn)(Args ...))
	{
		return detail::_Ptr_to_fn(fn);
	}

	template <typename Ret, typename C, typename ...Args>
	LPVOID _Pointer_to_class_method(Ret (__cdecl C::*fn)(Args ...) const)
	{
		return detail::_Ptr_to_fn(fn);
	}

	//--

	namespace detail
	{
		void _Call_fn_trap(call_conversion original, call_conversion called);
		void _Call_fn_trap(call_conversion original);

		template <typename Fn_as, typename Fn_old, typename ...Args>
		decltype(auto) _Call_fn_as(Fn_old func_ptr, Args&& ...args)
		{
			Fn_as callable;
			reinterpret_cast<void*&>(callable) = reinterpret_cast<void*&>(func_ptr);
			return std::invoke(callable, std::forward<Args>(args)...);
		}
	}

	/**
	 * \brief thiscall -> fastcall
	 */
	template <typename Ret, typename C, typename ...Args>
	Ret _Call_function(Ret (__thiscall C::*fn)(Args ...), C* instance, std::type_identity_t<Args> ...args)
	{
		detail::_Call_fn_trap(call_conversion::thiscall__, call_conversion::fastcall__);
		using fn_t = Ret(__fastcall*)(C*, void*, Args ...);
		return detail::_Call_fn_as<fn_t>(fn, instance, nullptr, args...);
	}

	/**
	 * \brief thiscall -> fastcall CONST
	 */
	template <typename Ret, typename C, typename ...Args>
	Ret _Call_function(Ret (__thiscall C::*fn)(Args ...) const, const C* instance, std::type_identity_t<Args> ...args)
	{
		detail::_Call_fn_trap(call_conversion::thiscall__, call_conversion::fastcall__);
		using fn_t = Ret(__fastcall*)(const C*, void*, Args ...);
		return detail::_Call_fn_as<fn_t>(fn, instance, nullptr, args...);
	}

	/**
	 * \brief fastcall
	 */
	template <typename Ret, typename C, typename ...Args>
	Ret _Call_function(Ret (__fastcall C::*fn)(Args ...), C* instance, std::type_identity_t<Args> ...args)
	{
		detail::_Call_fn_trap(call_conversion::fastcall__);
		using fn_t = Ret(__fastcall*)(C*, void*, Args ...);
		return detail::_Call_fn_as<fn_t>(fn, instance, nullptr, args...);
	}

	/**
	 * \brief fastcall CONST
	 */
	template <typename Ret, typename C, typename ...Args>
	Ret _Call_function(Ret (__fastcall C::*fn)(Args ...) const, const C* instance, std::type_identity_t<Args> ...args)
	{
		detail::_Call_fn_trap(call_conversion::fastcall__);
		using fn_t = Ret(__fastcall*)(const C*, void*, Args ...);
		return detail::_Call_fn_as<fn_t>(fn, instance, nullptr, args...);
	}

	/**
	 * \brief stdcall
	 */
	template <typename Ret, typename C, typename ...Args>
	Ret _Call_function(Ret (__stdcall C::*fn)(Args ...), C* instance, std::type_identity_t<Args> ...args)
	{
		//3
		detail::_Call_fn_trap(call_conversion::stdcall__);
		using fn_t = Ret(__stdcall*)(C*, Args ...);
		return detail::_Call_fn_as<fn_t>(fn, instance, args...);
	}

	/**
	 * \brief stdcall CONST
	 */
	template <typename Ret, typename C, typename ...Args>
	Ret _Call_function(Ret (__stdcall C::*fn)(Args ...) const, const C* instance, std::type_identity_t<Args> ...args)
	{
		detail::_Call_fn_trap(call_conversion::stdcall__);
		using fn_t = Ret(__stdcall*)(const C*, Args ...);
		return detail::_Call_fn_as<fn_t>(fn, instance, args...);
	}

	/**
	 * \brief cdecl
	 */
	template <typename Ret, typename C, typename ...Args>
	Ret _Call_function(Ret (__cdecl C::*fn)(Args ...), C* instance, std::type_identity_t<Args> ...args)
	{
		detail::_Call_fn_trap(call_conversion::cdecl__);
		using fn_t = Ret(__cdecl*)(C*, Args ...);
		return detail::_Call_fn_as<fn_t>(fn, instance, args...);
	}

	/**
	 * \brief cdecl CONST
	 */
	template <typename Ret, typename C, typename ...Args>
	Ret _Call_function(Ret (__cdecl C::*fn)(Args ...) const, const C* instance, std::type_identity_t<Args> ...args)
	{
		detail::_Call_fn_trap(call_conversion::cdecl__);
		using fn_t = Ret(__cdecl*)(const C*, Args ...);
		return detail::_Call_fn_as<fn_t>(fn, instance, args...);
	}

	namespace detail
	{
		template <typename Fn, typename C, typename ...Args>
		decltype(auto) _Call_virtual_fn(Fn fn, C* instance, size_t index, Args&& ...args)
		{
			auto vtable                  = _Pointer_to_virtual_class_table(instance);
			reinterpret_cast<void*&>(fn) = vtable[index];
			return _Call_function(fn, instance, std::forward<Args>(args)...);
		}
	}

	template <typename Ret, typename C, typename ...Args>
	Ret _Call_function(Ret (__thiscall C::*fn_sample)(Args ...), C* instance, size_t index, std::type_identity_t<Args> ...args)
	{
		return detail::_Call_virtual_fn(fn_sample, instance, index, std::forward<Args>(args)...);
	}

	template <typename Ret, typename C, typename ...Args>
	Ret _Call_function(Ret (__thiscall C::*fn_sample)(Args ...) const, const C* instance, size_t index, std::type_identity_t<Args> ...args)
	{
		return detail::_Call_virtual_fn(fn_sample, instance, index, std::forward<Args>(args)...);
	}

	template <typename Ret, typename C, typename ...Args>
	Ret _Call_function(Ret (__fastcall C::*fn_sample)(Args ...), C* instance, size_t index, std::type_identity_t<Args> ...args)
	{
		return detail::_Call_virtual_fn(fn_sample, instance, index, std::forward<Args>(args)...);
	}

	template <typename Ret, typename C, typename ...Args>
	Ret _Call_function(Ret (__fastcall C::*fn_sample)(Args ...) const, const C* instance, size_t index, std::type_identity_t<Args> ...args)
	{
		return detail::_Call_virtual_fn(fn_sample, instance, index, std::forward<Args>(args)...);
	}

	template <typename Ret, typename C, typename ...Args>
	Ret _Call_function(Ret (__stdcall C::*fn_sample)(Args ...), C* instance, size_t index, std::type_identity_t<Args> ...args)
	{
		return detail::_Call_virtual_fn(fn_sample, instance, index, std::forward<Args>(args)...);
	}

	template <typename Ret, typename C, typename ...Args>
	Ret _Call_function(Ret (__stdcall C::*fn_sample)(Args ...) const, const C* instance, size_t index, std::type_identity_t<Args> ...args)
	{
		return detail::_Call_virtual_fn(fn_sample, instance, index, std::forward<Args>(args)...);
	}

	template <typename Ret, typename C, typename ...Args>
	Ret _Call_function(Ret (__cdecl C::*fn_sample)(Args ...), C* instance, size_t index, std::type_identity_t<Args> ...args)
	{
		return detail::_Call_virtual_fn(fn_sample, instance, index, std::forward<Args>(args)...);
	}

	template <typename Ret, typename C, typename ...Args>
	Ret _Call_function(Ret (__cdecl C::*fn_sample)(Args ...) const, const C* instance, size_t index, std::type_identity_t<Args> ...args)
	{
		return detail::_Call_virtual_fn(fn_sample, instance, index, std::forward<Args>(args)...);
	}

	/**
	 * \brief fastcall STATIC
	 */
	template <typename Ret, typename ...Args>
	Ret _Call_function(Ret (__fastcall*fn)(Args ...), std::type_identity_t<Args> ...args) = delete;

	/**
	 * \brief stdcall STATIC
	 */
	template <typename Ret, typename ...Args>
	Ret _Call_function(Ret (__stdcall*fn)(Args ...), std::type_identity_t<Args> ...args)
	{
		detail::_Call_fn_trap(call_conversion::stdcall__);
		return std::invoke(fn, args...);
	}

	/**
	 * \brief cdecl STATIC
	 */
	template <typename Ret, typename ...Args>
	Ret _Call_function(Ret (__cdecl*fn)(Args ...), std::type_identity_t<Args> ...args)
	{
		detail::_Call_fn_trap(call_conversion::cdecl__);
		return std::invoke(fn, args...);
	}
}
