#pragma once

#include "helpers.h"
#include "wrapper_fwd.h"

#include <memory>

namespace dhooks
{
	template <typename T>
	struct hiddent_type
	{
		uintptr_t value;

		hiddent_type( ) = default;

		hiddent_type(void* ptr)
			: value(reinterpret_cast<uintptr_t>(ptr))
		{
		}

		template <typename T1>
		hiddent_type<T1> change_type( ) const
		{
			hiddent_type<T1> ret;
			ret.value = value;
			return ret;
		}

		decltype(auto) unhide( )
		{
			if constexpr (std::is_pointer_v<T>)
				return reinterpret_cast<T>(value);
			else if constexpr (!std::is_reference_v<T>)
				return reinterpret_cast<T&>(value);
			else
				return std::forward<T>(*reinterpret_cast<std::remove_reference_t<T>*>(value));
		}
	};

	template <typename Ret, call_conversion CallCvs, typename ...Args2>
	class original_function0;

	template <typename C>
	class object_instance_holder
	{
		C* instance_ = nullptr;
	public:
		void set_object_instance(void* ptr)
		{
			reinterpret_cast<void*&>(instance_) = ptr;
		}

		C* get_object_instance( ) const
		{
			return instance_;
		}
	};

	template < >
	class object_instance_holder<void>
	{
	};

#define DHOOKS_HOOK_ORIGINAL_FN(_CALL_CVS_)\
	template <typename Ret, typename C, typename ...Args>\
	class original_function0<Ret, call_conversion::_CALL_CVS_##__, C, Args...>:public object_instance_holder<C>, protected virtual original_func_setter\
	{\
		Ret (__##_CALL_CVS_ C::*original_fn)(Args ...) = nullptr;\
    public:\
		Ret call_original(Args ...args){ return _Call_function(original_fn, this->get_object_instance( ), args...); }\
        void set_original_func(void* fn) final { reinterpret_cast<void*&>(original_fn) = fn; }\
	};\
	template <typename Ret, typename ...Args>\
	class original_function0<Ret, call_conversion::_CALL_CVS_##__,void, Args...>: protected virtual original_func_setter\
	{\
		Ret (__##_CALL_CVS_ *original_fn)(Args ...) = nullptr;\
    public:\
		Ret call_original(Args ...args) { return _Call_function(original_fn, args...); }\
        void set_original_func(void* fn) final { reinterpret_cast<void*&>(original_fn) = fn; }\
	};

	DHOOKS_CALL_CVS_HELPER(DHOOKS_HOOK_ORIGINAL_FN)

	template <class Ret>
	class return_value_holder
	{
		Ret value_;
		bool set_ = false;

	public:
		return_value_holder( ) = default;

		static_assert(std::is_default_constructible_v<Ret>);

		void store_return_value(Ret&& val)
		{
			value_ = std::move(val);
			set_   = true;
		}

		void store_return_value(const Ret& val)
		{
			value_ = val;
			set_   = true;
		}

		void reset_return_value( )
		{
			set_ = false;
		}

		bool have_return_value( ) const
		{
			return set_;
		}

		Ret&& get_return_value( ) &&
		{
			set_ = false;
			return static_cast<Ret&&>(value_);
		}

		Ret get_return_value( ) &
		{
			if constexpr (std::is_copy_constructible_v<Ret>)
				return value_;
			else
				return std::move(*this).get( );
		}
	};

	template < >
	class return_value_holder<void>
	{
		bool called_ = false;

	public:
		void store_return_value(bool called = true)
		{
			called_ = called;
		}

		void reset_return_value( )
		{
			called_ = false;
		}

		bool have_return_value( ) const
		{
			return called_;
		}

		void get_return_value( ) &
		{
			(void)this;
		}

		void get_return_value( ) &&
		{
			called_ = false;
		}
	};

	template <typename Ret, call_conversion CallCvs, typename Arg1, typename ...Args>
	struct original_function : original_function0<Ret, CallCvs, Arg1, Args...>, return_value_holder<Ret>
	{
		// ReSharper disable once CppNotAllPathsReturnValue
		Ret call_original_and_store_result(Args ...args)
		{
			if constexpr (!std::is_void_v<Ret>)
			{
				auto ret = this->call_original(args...);
				this->store_return_value(ret);
				return ret;
			}
			else
			{
				this->call_original(args...);
				this->store_return_value( );
			}
		}
	};

	class __declspec(novtable) hook_holder_data : public hook_holder_base, protected virtual original_func_setter
	{
	protected:
		~hook_holder_data( ) override;
		hook_holder_data( );
	public:
		bool hook( ) final;
		bool unhook( ) final;
		void unhook_after_call( ) final;
		bool enable( ) final;
		bool disable( ) final;
		void disable_after_call( ) final;
		bool hooked( ) const final;
		bool enabled( ) const final;

		virtual void* get_target_method( ) const =0;
		virtual void* get_replace_method( ) =0;

		hook_holder_data(hook_holder_data&&) noexcept;
		hook_holder_data& operator=(hook_holder_data&&) noexcept;

	protected:
		bool unhook_after_call_if_wanted( );
		void disable_after_call_if_wanted( );

	private:
		struct impl;
		std::unique_ptr<impl> impl_;
	};

	class return_address_getter
	{
#ifdef __INTRIN_H_
        void* addr1_ = nullptr; //_ReturnAddress
        void* addr2_ = nullptr; //_AddressOfReturnAddress
#endif
	public:
#ifdef __INTRIN_H_
        using return_address_t=void*;
#else
		using return_address_t = void;
#endif

		return_address_t return_address( ) const
		{
#ifdef __INTRIN_H_
#ifdef _DEBUG
            if (addr1_)
#endif
                return addr1_;
#else
			(void)this;
#endif
			std::_Xruntime_error("_ReturnAddress not set");
		}

		return_address_t address_of_return_address( ) const
		{
#ifdef __INTRIN_H_
#ifdef _DEBUG
            if (addr2_)
#endif
                return addr2_;
#else
			(void)this;
#endif
			std::_Xruntime_error("_AddressOfReturnAddress not set");
		}

#ifdef __INTRIN_H_
        void set_return_address(void* addr1, void* addr2)
        {
            addr1_ = addr1;
            addr2_ = addr2;
        }
#endif
	};

#ifdef __INTRIN_H_
#define DHOOKS_SET_RETURN_ADDRESS(_THIS_) (_THIS_)->set_return_address(_ReturnAddress(),_AddressOfReturnAddress())
#else
#define DHOOKS_SET_RETURN_ADDRESS(_THIS_) (void)0
#endif

	template <typename Ret, call_conversion CallCvs, typename Arg1, typename ...Args>
	class hook_holder_impl : public return_address_getter
						   , public original_function<Ret, CallCvs, Arg1, Args...>
						   , public hook_holder_data
						   , public hook_callback<Ret, Args...>
	{
	protected:
		static hook_holder_impl*& instance( )
		{
			static hook_holder_impl* obj = nullptr;
			return obj;
		}

	public:
		hook_holder_impl( )
			: hook_holder_data( )
		{
			auto& ref = instance( );
#ifdef _DEBUG
            if (ref != nullptr)
                std::_Xout_of_range(__FUNCSIG__": instance already created!");
#endif
			ref = this;
		}

		~hook_holder_impl( ) override
		{
			instance( ) = nullptr;
		}

	protected:
		Ret callback_impl(Args ...args)
		{
			//this->reset_return_value( ); //done by reset_return_value
			this->callback(args...);

			if (!this->have_return_value( ))
				this->call_original_and_store_result(args...);

			if (!this->unhook_after_call_if_wanted( ))
				this->disable_after_call_if_wanted( );

			return std::move(*this).get_return_value( );
		}
	};

	template <typename Ret, call_conversion CallCvs, typename Arg1, typename ...Args>
	struct hook_holder;

	namespace detail
	{
		template <typename T, size_t ...I>
		auto shift_left_impl(T& tpl, std::index_sequence<I...>)
		{
			return std::forward_as_tuple(reinterpret_cast<std::tuple_element_t<I + 1, T>&>(std::get<I>(tpl)).unhide( )...);
		}

		template <typename ...T>
		auto shift_left(std::tuple<hiddent_type<T>...>&& tpl)
		{
			return shift_left_impl(tpl, std::make_index_sequence<sizeof...(T) - 1>( ));
		}
	}

#define CHEAT_HOOK_HOLDER_IMPL(_CALL_CVS_)\
	template < typename Ret, typename Arg1, typename ...Args>\
	struct hook_holder<Ret, call_conversion::_CALL_CVS_##__, Arg1, Args...>: hook_holder_impl<Ret, call_conversion::_CALL_CVS_##__, Arg1, Args...>\
	{\
		__declspec(noinline) Ret __##_CALL_CVS_ callback_proxy(hiddent_type<Args> ...args)\
		{\
			auto _Instance = this->instance( );\
			DHOOKS_SET_RETURN_ADDRESS(_Instance);\
			if constexpr (std::is_class_v<Arg1>)\
			{\
				_Instance->set_object_instance(this);\
				return std::invoke(\
								   &hook_holder::callback_impl,\
								   _Instance, args.unhide( )...\
								  );\
			}\
			else\
			{\
                hiddent_type<void*> fake_this_ptr = this;\
				return std::apply(\
								  &hook_holder::callback_impl,\
								  std::tuple_cat(std::tuple(_Instance), detail::shift_left(std::tuple(fake_this_ptr, args...)))\
								 );\
			}\
		}\
		void* get_replace_method( ) final\
		{\
			return _Pointer_to_class_method(&hook_holder::callback_proxy);\
		}\
	};

	DHOOKS_CALL_CVS_HELPER(CHEAT_HOOK_HOLDER_IMPL)

#define CHEAT_HOOK_HOLDER_DETECTOR(_CALL_CVS_)\
	template <typename Ret, typename C, typename ...Args>\
    auto _Detect_hook_holder(Ret (__##_CALL_CVS_ C::*fn)(Args ...)) ->\
    hook_holder<Ret, call_conversion::_CALL_CVS_##__, C, /*false,*/ Args...>\
    { return {}; }\
    template <typename Ret, typename C, typename ...Args>\
    auto _Detect_hook_holder(Ret (__##_CALL_CVS_ C::*fn)(Args ...) const) ->\
    hook_holder<Ret, call_conversion::_CALL_CVS_##__, C, /*true,*/ Args...>\
    { return {}; }\
    template <typename Ret, typename ...Args>\
    auto _Detect_hook_holder(Ret (__##_CALL_CVS_    *fn)(Args ...)) ->\
	hook_holder<Ret, call_conversion::_CALL_CVS_##__, void,/* false,*/ Args...>\
    { return {}; }

	DHOOKS_CALL_CVS_HELPER(CHEAT_HOOK_HOLDER_DETECTOR)

	template <size_t Idx, typename Fn>
	using _Detect_hook_holder_t = decltype(_Detect_hook_holder(std::declval<Fn>( )));
}
