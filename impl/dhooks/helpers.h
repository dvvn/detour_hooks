#pragma once

#include <type_traits>

#define DHOOKS_CALL_CVS_HELPER(_MACRO_)\
		_MACRO_(thiscall)\
		_MACRO_(cdecl)\
		_MACRO_(stdcall)\
		_MACRO_(vectorcall)\
		_MACRO_(fastcall)

namespace dhooks
{
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
        void* _Ptr_to_fn(Fn fn)
        {
            const auto ptr = reinterpret_cast<void*&>(fn);
            return ptr;
        }

#if 0
        template <typename C>
        void** _Ptr_to_vtable(C* instance)
        {
            // ReSharper disable once CppCStyleCast
            return *(void***)(instance);
        }
#endif
    }

#define DHOOKS_POINTER_TO_CLASS_METHOD0(_CALL_CVS_,CONST) \
    template <typename Ret, typename C, typename ...Args>\
    void* _Pointer_to_class_method(Ret (__##_CALL_CVS_ C::*fn)(Args ...) CONST)\
    {\
        return detail::_Ptr_to_fn(fn);\
    }

#define DHOOKS_POINTER_TO_CLASS_METHOD(_CALL_CVS_) \
    DHOOKS_POINTER_TO_CLASS_METHOD0(_CALL_CVS_, )\
    DHOOKS_POINTER_TO_CLASS_METHOD0(_CALL_CVS_,const)

    DHOOKS_CALL_CVS_HELPER(DHOOKS_POINTER_TO_CLASS_METHOD)

    namespace detail
    {
        template <typename Fn_as, typename Arg2, typename Arg1, typename ...Args>
        decltype(auto) _Call_fn_as_fastcall(Fn_as callable, Arg2 arg2, Arg1 arg1, Args&& ...args)
        {
            return std::invoke(callable, arg1, arg2, std::forward<Args>(args)...);
        }

        template <typename Fn_as, typename Fn_old, typename ...Args>
        decltype(auto) _Call_fn_as(Fn_old func_ptr, Args&& ...args)
        {
            Fn_as callable;
            reinterpret_cast<void*&>(callable) = reinterpret_cast<void*&>(func_ptr);
            if constexpr (std::is_invocable_v<Fn_as, Args...>)
                return std::invoke(callable, std::forward<Args>(args)...);
            else if constexpr (std::is_member_function_pointer_v<Fn_old>)
                return _Call_fn_as_fastcall(callable, nullptr, std::forward<Args>(args)...);
        }
    }

#define DHOOKS_CALL_CLASS_FN0(_CALL_CVS_IN_,_CALL_CVS_OUT_,_CONST_,...) \
    template <typename Ret, typename C, typename ...Args>\
    Ret _Call_function(Ret (__##_CALL_CVS_IN_ C::*fn)(Args ...) _CONST_, _CONST_ C* instance, std::type_identity_t<Args> ...args)\
    {\
        using fn_t = Ret(__##_CALL_CVS_OUT_*)(_CONST_ C*,##__VA_ARGS__, Args ...);\
        return detail::_Call_fn_as<fn_t>(fn, instance, args...);\
    }

#define DHOOKS_CALL_CLASS_FN_EX(_CALL_CVS_) \
        DHOOKS_CALL_CLASS_FN0(_CALL_CVS_,fastcall,const,void*)\
        DHOOKS_CALL_CLASS_FN0(_CALL_CVS_,fastcall,_EMPTY_ARGUMENT,void*)

#define DHOOKS_CALL_CLASS_FN(_CALL_CVS_) \
        DHOOKS_CALL_CLASS_FN0(_CALL_CVS_,_CALL_CVS_,const)\
        DHOOKS_CALL_CLASS_FN0(_CALL_CVS_,_CALL_CVS_,_EMPTY_ARGUMENT)

    DHOOKS_CALL_CLASS_FN_EX(thiscall)
    DHOOKS_CALL_CLASS_FN_EX(fastcall)
    DHOOKS_CALL_CLASS_FN(stdcall)
    DHOOKS_CALL_CLASS_FN(cdecl)

    namespace detail
    {
        template <typename Fn, typename C, typename ...Args>
        decltype(auto) _Call_virtual_fn(Fn fn, C* instance, size_t index, Args&& ...args)
        {
            //auto vtable                  = _Ptr_to_vtable(instance);
            auto vtable0 = *(void**)instance;
            auto vtable  = (void**)vtable0;
            auto real_fn = vtable[index];

            reinterpret_cast<void*&>(fn) = real_fn;
            return _Call_function(fn, instance, std::forward<Args>(args)...);
        }
    }

#define DHOOKS_CALL_VIRTUAL_FN(_CALL_CVS_) \
    template <typename Ret, typename C, typename ...Args>\
    Ret _Call_function(Ret (__##_CALL_CVS_ C::*fn_sample)(Args ...), C* instance, size_t index, std::type_identity_t<Args> ...args)\
    {\
        return detail::_Call_virtual_fn(fn_sample, instance, index, std::forward<Args>(args)...);\
    }\
    template <typename Ret, typename C, typename ...Args>\
    Ret _Call_function(Ret (__##_CALL_CVS_ C::*fn_sample)(Args ...) const,const C* instance, size_t index, std::type_identity_t<Args> ...args)\
    {\
        return detail::_Call_virtual_fn(fn_sample, instance, index, std::forward<Args>(args)...);\
    }

    DHOOKS_CALL_CVS_HELPER(DHOOKS_CALL_VIRTUAL_FN)

#define DHOOKS_CALL_STATIC_FN(_CALL_CVS_) \
    template <typename Ret, typename ...Args>\
    Ret _Call_function(Ret (__##_CALL_CVS_*fn)(Args ...), std::type_identity_t<Args> ...args)\
    {\
        return std::invoke(fn, std::forward<Args>(args)...);\
    }

    DHOOKS_CALL_CVS_HELPER(DHOOKS_CALL_STATIC_FN)
}
