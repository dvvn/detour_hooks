module;

#include <intrin.h>

#include <memory>
#include <mutex>

export module dhooks;
export import :context;

#define DHOOKS_CALL_CVS_HELPER_STATIC(_MACRO_)\
		_MACRO_(cdecl)\
		_MACRO_(stdcall)\
		_MACRO_(vectorcall)\
		_MACRO_(fastcall)

#define DHOOKS_CALL_CVS_HELPER_MEMBER(_MACRO_)\
		_MACRO_(thiscall)

#define DHOOKS_CALL_CVS_HELPER_ALL(_MACRO_)\
		DHOOKS_CALL_CVS_HELPER_STATIC(_MACRO_)\
		DHOOKS_CALL_CVS_HELPER_MEMBER(_MACRO_)

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

#define DHOOKS_POINTER_TO_CLASS_METHOD0(_CALL_CVS_,CONST) \
    template <typename Ret, typename C, typename ...Args>\
    void* _Pointer_to_class_method(Ret (__##_CALL_CVS_ C::*fn)(Args ...) CONST)\
    {\
        return _Ptr_to_fn(fn);\
    }

#define DHOOKS_POINTER_TO_CLASS_METHOD(_CALL_CVS_) \
    DHOOKS_POINTER_TO_CLASS_METHOD0(_CALL_CVS_, )\
    DHOOKS_POINTER_TO_CLASS_METHOD0(_CALL_CVS_,const)

export namespace dhooks
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

	DHOOKS_CALL_CVS_HELPER_ALL(DHOOKS_POINTER_TO_CLASS_METHOD);
}

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

#define DHOOKS_CALL_CLASS_FN0(_CALL_CVS_IN_,_CALL_CVS_OUT_,_CONST_,...) \
    template <typename Ret, typename C, typename ...Args>\
    Ret _Call_function(Ret (__##_CALL_CVS_IN_ C::*fn)(Args ...) _CONST_, _CONST_ C* instance, std::type_identity_t<Args> ...args)\
    {\
        using fn_t = Ret(__##_CALL_CVS_OUT_*)(_CONST_ C*,##__VA_ARGS__, Args ...);\
        return _Call_fn_as<fn_t>(fn, instance, args...);\
    }

#define DHOOKS_CALL_CLASS_FN_EX(_CALL_CVS_) \
	DHOOKS_CALL_CLASS_FN0(_CALL_CVS_,fastcall,const,void*)\
	DHOOKS_CALL_CLASS_FN0(_CALL_CVS_,fastcall,_EMPTY_ARGUMENT,void*)

#define DHOOKS_CALL_CLASS_FN(_CALL_CVS_) \
	DHOOKS_CALL_CLASS_FN0(_CALL_CVS_,_CALL_CVS_,const)\
	DHOOKS_CALL_CLASS_FN0(_CALL_CVS_,_CALL_CVS_,_EMPTY_ARGUMENT)

export namespace dhooks
{
	DHOOKS_CALL_CLASS_FN_EX(thiscall);
	DHOOKS_CALL_CLASS_FN_EX(fastcall);
	DHOOKS_CALL_CLASS_FN(stdcall);
	DHOOKS_CALL_CLASS_FN(cdecl);
}

template <typename Fn, typename C, typename ...Args>
decltype(auto) _Call_virtual_fn(Fn fn, C* instance, size_t index, Args&& ...args)
{
	//auto vtable                  = _Ptr_to_vtable(instance);
	auto vtable0 = *(void**)instance;
	auto vtable = (void**)vtable0;
	auto real_fn = vtable[index];

	reinterpret_cast<void*&>(fn) = real_fn;
	return _Call_function(fn, instance, std::forward<Args>(args)...);
}

#define DHOOKS_CALL_VIRTUAL_FN(_CALL_CVS_) \
    template <typename Ret, typename C, typename ...Args>\
    Ret _Call_function(Ret (__##_CALL_CVS_ C::*fn_sample)(Args ...), C* instance, size_t index, std::type_identity_t<Args> ...args)\
    {\
        return _Call_virtual_fn(fn_sample, instance, index, std::forward<Args>(args)...);\
    }\
    template <typename Ret, typename C, typename ...Args>\
    Ret _Call_function(Ret (__##_CALL_CVS_ C::*fn_sample)(Args ...) const,const C* instance, size_t index, std::type_identity_t<Args> ...args)\
    {\
        return _Call_virtual_fn(fn_sample, instance, index, std::forward<Args>(args)...);\
    }

#define DHOOKS_CALL_STATIC_FN(_CALL_CVS_) \
    template <typename Ret, typename ...Args>\
    Ret _Call_function(Ret (__##_CALL_CVS_*fn)(Args ...), std::type_identity_t<Args> ...args)\
    {\
        return std::invoke(fn, std::forward<Args>(args)...);\
    }

export namespace dhooks
{
	DHOOKS_CALL_CVS_HELPER_ALL(DHOOKS_CALL_VIRTUAL_FN);
	DHOOKS_CALL_CVS_HELPER_STATIC(DHOOKS_CALL_STATIC_FN);
}

export namespace dhooks
{
	struct __declspec(novtable) original_func_setter
	{
		virtual ~original_func_setter( ) = default;
		virtual void set_original_func(void* fn) = 0;
	};

	template <typename Ret, /*typename Arg1,*/ typename ...Args>
	struct __declspec(novtable) hook_callback
	{
		virtual ~hook_callback( ) = default;
		virtual void callback(Args ...) = 0;
	};

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

}

#define DHOOKS_HOOK_ORIGINAL_FN_MEMBER(_CALL_CVS_)\
	template <typename Ret, typename C, typename ...Args>\
	class original_function0<Ret, call_conversion::_CALL_CVS_##__, C, Args...>:public object_instance_holder<C>, protected virtual original_func_setter\
	{\
		Ret (__##_CALL_CVS_ C::*original_fn)(Args ...) = nullptr;\
    public:\
		Ret call_original(Args ...args){ return _Call_function(original_fn, this->get_object_instance( ), args...); }\
        void set_original_func(void* fn) final { reinterpret_cast<void*&>(original_fn) = fn; }\
	};


#define DHOOKS_HOOK_ORIGINAL_FN_STATIC(_CALL_CVS_)\
	template <typename Ret, typename ...Args>\
	class original_function0<Ret, call_conversion::_CALL_CVS_##__,void, Args...>: protected virtual original_func_setter\
	{\
		Ret (__##_CALL_CVS_ *original_fn)(Args ...) = nullptr;\
    public:\
		Ret call_original(Args ...args) { return _Call_function(original_fn, args...); }\
        void set_original_func(void* fn) final { reinterpret_cast<void*&>(original_fn) = fn; }\
	};

export namespace dhooks
{
	DHOOKS_CALL_CVS_HELPER_ALL(DHOOKS_HOOK_ORIGINAL_FN_MEMBER);
	DHOOKS_CALL_CVS_HELPER_STATIC(DHOOKS_HOOK_ORIGINAL_FN_STATIC);

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
			set_ = true;
		}

		void store_return_value(const Ret& val)
		{
			value_ = val;
			set_ = true;
		}

		void reset_return_value( )
		{
			set_ = false;
		}

		bool have_return_value( ) const
		{
			return set_;
		}

		Ret&& get_return_value( )&&
		{
			set_ = false;
			return static_cast<Ret&&>(value_);
		}

		Ret get_return_value( )&
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

		void get_return_value( )&
		{
			(void)this;
		}

		void get_return_value( )&&
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

	class __declspec(novtable) hook_holder_data : protected virtual original_func_setter
	{
		mutable std::mutex mtx;
		std::atomic_bool active = false;
		std::weak_ptr<basic_context> wctx;

		std::shared_ptr<basic_context> get_ctx( )const
		{
#ifdef _DEBUG
			return std::shared_ptr(wctx);
#else
			return wctx.lock( );
#endif
		}

		struct
		{
			std::atomic_bool unhook = false;
			std::atomic_bool disable = false;

			void reset( )
			{
				unhook = disable = false;
			}
		} after_call;

		void* target = nullptr;
		void* replace = nullptr;

	protected:
		hook_holder_data( );
		~hook_holder_data( ) override;

	public:
		hook_holder_data(hook_holder_data&&) noexcept;
		hook_holder_data& operator=(hook_holder_data&&) noexcept;

		bool hook( );
		bool unhook( );
		void unhook_after_call( );

		bool enable( );
		bool disable( );
		void disable_after_call( );

		bool hooked( ) const;
		bool enabled( ) const;

		virtual void* get_target_method( ) const = 0;
		virtual void* get_replace_method( ) = 0;
	protected:
		bool unhook_after_call_if_wanted( );
		bool disable_after_call_if_wanted( );
	};

	struct return_address_getter
	{
		using addr_watcher = std::optional<void*>;
		addr_watcher addr1; //_ReturnAddress
		addr_watcher addr2; //_AddressOfReturnAddress

		return_address_getter* _Rt_addr_getter( )
		{
			return this;
		}

	};

	template <typename Ret, call_conversion CallCvs, typename Arg1, typename ...Args>
	struct hook_holder_impl : return_address_getter
		, original_function<Ret, CallCvs, Arg1, Args...>
		, hook_holder_data
		, hook_callback<Ret, Args...>
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
}

#define DHOOKS_SET_RETURN_ADDRESS0(_THIS_,_ADDR_,_FN_) \
	if(_THIS_->_Rt_addr_getter()->_ADDR_.has_value())\
		_THIS_->_Rt_addr_getter()->_ADDR_.emplace(_FN_);

#define DHOOKS_SET_RETURN_ADDRESS(_THIS_) \
	DHOOKS_SET_RETURN_ADDRESS0(_THIS_,addr1,_ReturnAddress())\
	DHOOKS_SET_RETURN_ADDRESS0(_THIS_,addr2,_AddressOfReturnAddress())

template <typename T, size_t ...I>
auto shift_left_impl(T& tpl, std::index_sequence<I...>)
{
	return std::forward_as_tuple(reinterpret_cast<std::tuple_element_t<I + 1, T>&>(std::get<I>(tpl)).unhide( )...);
}

template <typename ...T>
auto shift_left(std::tuple<dhooks::hiddent_type<T>...>&& tpl)
{
	return shift_left_impl(tpl, std::make_index_sequence<sizeof...(T) - 1>( ));
}

export namespace dhooks
{
#if 0
#define DHOOKS_HOOK_HOLDER_HEAD(_CALL_CVS_)\
	template < typename Ret, typename Arg1, typename ...Args>\
	struct hook_holder<Ret, call_conversion::_CALL_CVS_##__, Arg1, Args...>: hook_holder_impl<Ret, call_conversion::_CALL_CVS_##__, Arg1, Args...>\
	{\
		__declspec(noinline) Ret __##_CALL_CVS_ callback_proxy(hiddent_type<Args> ...args)\
		{\
			auto _Instance = this->instance( );\
			DHOOKS_SET_RETURN_ADDRESS(_Instance);

#define DHOOKS_HOOK_HOLDER_MEMBER_IMPL\
				_Instance->set_object_instance(this);\
				return std::invoke(\
								   &hook_holder::callback_impl,\
								   _Instance, args.unhide( )...\
								  );
#define DHOOKS_HOOK_HOLDER_STATIC_IMPL\
				hiddent_type<void*> fake_this_ptr = this;\
				return std::apply(\
								  &hook_holder::callback_impl,\
								  std::tuple_cat(std::tuple(_Instance), detail::shift_left(std::tuple(fake_this_ptr, args...)))\
								 );

#define DHOOKS_HOOK_HOLDER_TAIL\
		}\
		void* get_replace_method( ) final\
		{\
			return _Pointer_to_class_method(&hook_holder::callback_proxy);\
		}\
	};

#define DHOOKS_HOOK_HOLDER_MEMBER(_CALL_CVS_)\
DHOOKS_HOOK_HOLDER_HEAD(_CALL_CVS_)\
DHOOKS_HOOK_HOLDER_MEMBER_IMPL\
DHOOKS_HOOK_HOLDER_TAIL

#define DHOOKS_HOOK_HOLDER_STATIC(_CALL_CVS_)\
DHOOKS_HOOK_HOLDER_HEAD(_CALL_CVS_)\
DHOOKS_HOOK_HOLDER_STATIC_IMPL\
DHOOKS_HOOK_HOLDER_TAIL

	DHOOKS_CALL_CVS_HELPER_ALL(DHOOKS_HOOK_HOLDER_MEMBER);
	DHOOKS_CALL_CVS_HELPER_STATIC(DHOOKS_HOOK_HOLDER_STATIC);
#else

#define DHOOKS_HOOK_HOLDER_IMPL(_CALL_CVS_)\
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
									  std::tuple_cat(std::tuple(_Instance), shift_left(std::tuple(fake_this_ptr, args...)))\
									 );\
				}\
			}\
			void* get_replace_method( ) final\
			{\
				return _Pointer_to_class_method(&hook_holder::callback_proxy);\
			}\
		};
	DHOOKS_CALL_CVS_HELPER_ALL(DHOOKS_HOOK_HOLDER_IMPL);
#endif

#define CHEAT_HOOK_HOLDER_DETECTOR_MEMBER(_CALL_CVS_)\
	template <typename Ret, typename C, typename ...Args>\
    auto _Detect_hook_holder(Ret (__##_CALL_CVS_ C::*fn)(Args ...)) ->\
    hook_holder<Ret, call_conversion::_CALL_CVS_##__, C, /*false,*/ Args...>\
    { return {}; }\
    template <typename Ret, typename C, typename ...Args>\
    auto _Detect_hook_holder(Ret (__##_CALL_CVS_ C::*fn)(Args ...) const) ->\
    hook_holder<Ret, call_conversion::_CALL_CVS_##__, C, /*true,*/ Args...>\
    { return {}; }

#define CHEAT_HOOK_HOLDER_DETECTOR_STATIC(_CALL_CVS_)\
    template <typename Ret, typename ...Args>\
    auto _Detect_hook_holder(Ret (__##_CALL_CVS_    *fn)(Args ...)) ->\
	hook_holder<Ret, call_conversion::_CALL_CVS_##__, void,/* false,*/ Args...>\
    { return {}; }

	DHOOKS_CALL_CVS_HELPER_ALL(CHEAT_HOOK_HOLDER_DETECTOR_MEMBER);
	DHOOKS_CALL_CVS_HELPER_STATIC(CHEAT_HOOK_HOLDER_DETECTOR_STATIC);

#if 0
	template <size_t Idx, typename Fn>
	using _Detect_hook_holder_t = decltype(_Detect_hook_holder(std::declval<Fn>( )));
#endif
	template<typename Fn>
	using select_hook_holder = decltype(_Detect_hook_holder(std::declval<Fn>( )));
}
