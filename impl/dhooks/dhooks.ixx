module;

#include <intrin.h>

#include <memory>
#include <mutex>

export module dhooks;
//export import :context;
export import :entry;

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

namespace dhooks
{
	template<typename Out, typename In>
	Out force_cast(In in)
	{
		Out out;
		reinterpret_cast<void*&>(out) = reinterpret_cast<void*&>(in);
		return out;
	}

	template<typename Out, typename In, typename ...Args>
	decltype(auto) force_cast_and_call(In in, Args&&...args)
	{
		auto out = force_cast<Out>(in);
		return std::invoke(out, std::forward<Args>(args)...);
	}

#define DHOOKS_CALL_MEMBER_FN_HEAD(_CALL_CVS_,_CONST_)\
	export template<typename Ret, typename C, typename ...Args>\
	Ret call_function(Ret(__##_CALL_CVS_ C::* fn)(Args ...) _CONST_, _CONST_ C* instance, Args ...args)

#define DHOOKS_CALL_MEMBER_FN_BODY(_CALL_CVS_)\
	force_cast_and_call<Ret(__##_CALL_CVS_*)(decltype(instance), Args...)>(fn, instance, std::forward<Args>(args)...);

#define DHOOKS_CALL_MEMBER_FN_SIMPLE(_CALL_CVS_)\
	DHOOKS_CALL_MEMBER_FN_HEAD(_CALL_CVS_,) { return DHOOKS_CALL_MEMBER_FN_BODY(_CALL_CVS_);}\
	DHOOKS_CALL_MEMBER_FN_HEAD(_CALL_CVS_,const) { return DHOOKS_CALL_MEMBER_FN_BODY(_CALL_CVS_);}

#define DHOOKS_CALL_MEMBER_FN_BODY_EX(_CALL_CVS_)\
	force_cast_and_call<Ret(__##_CALL_CVS_*)(decltype(instance), void*, Args...)>(fn, instance, nullptr, std::forward<Args>(args)...);

#define DHOOKS_CALL_MEMBER_FN_FASTCALL(_CALL_CVS_)\
	DHOOKS_CALL_MEMBER_FN_HEAD(_CALL_CVS_,) { return DHOOKS_CALL_MEMBER_FN_BODY_EX(_CALL_CVS_);}\
	DHOOKS_CALL_MEMBER_FN_HEAD(_CALL_CVS_,const) { return DHOOKS_CALL_MEMBER_FN_BODY_EX(_CALL_CVS_);}

	DHOOKS_CALL_MEMBER_FN_SIMPLE(cdecl);
	DHOOKS_CALL_MEMBER_FN_SIMPLE(stdcall);
	DHOOKS_CALL_MEMBER_FN_SIMPLE(vectorcall);//not sure
	DHOOKS_CALL_MEMBER_FN_FASTCALL(thiscall);
	DHOOKS_CALL_MEMBER_FN_FASTCALL(fastcall);

	export template<typename T, typename ...Args>
		requires(!std::is_member_function_pointer_v<T>)
	decltype(auto) call_function(T fn, Args&&...args)
	{
		return std::invoke(fn, std::forward<Args>(args)...);
	}

	struct visible_vtable
	{
		using table_type = void*;
		table_type* vtable;

		void* operator[](size_t index)const
		{
			return vtable[index];
		}
	};

	export template<typename T, typename C, typename ...Args>
		requires(std::is_member_function_pointer_v<T>)
	decltype(auto) call_function(T fn, C* instance, size_t index, Args&&...args)
	{
		auto vtable = *reinterpret_cast<const visible_vtable*>(instance);
		auto real_fn = vtable[index];
		return call_function(force_cast<T>(real_fn), instance, std::forward<Args>(args)...);
	}


}

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

namespace dhooks
{
#define DHOOKS_GENERATE_FUNC(_CALL_CVS_)\
	if constexpr(CallCvs == call_conversion::_CALL_CVS_##__)\
	{\
		if constexpr(std::is_class_v<C>)\
		{\
			Ret (__##_CALL_CVS_ C::*fn)(Args ...) = nullptr;\
			return fn;\
		}\
		else\
		{\
			Ret (__##_CALL_CVS_ *fn)(Args ...) = nullptr;\
			return fn;\
		}\
	}

	template <typename Ret, call_conversion CallCvs, typename C, typename ...Args>
	auto generate_function_type( )
	{
		DHOOKS_GENERATE_FUNC(cdecl)
	else
	DHOOKS_GENERATE_FUNC(stdcall)
		else
		DHOOKS_GENERATE_FUNC(vectorcall)
		else
		DHOOKS_GENERATE_FUNC(fastcall)
		else
		DHOOKS_GENERATE_FUNC(thiscall);
	}
}

export namespace dhooks
{
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

	template <typename Ret, call_conversion CallCvs, typename C, typename ...Args>
	class original_function :public object_instance_holder<C>, protected virtual original_func_setter, public return_value_holder<Ret>
	{
	protected:
		using func_type = decltype(generate_function_type<Ret, CallCvs, C, Args...>( ));
		func_type original_func = nullptr;
	public:
		Ret call_original(Args ...args)
		{
			if constexpr (std::is_class_v<C>)
				return call_function<Ret, C, Args...>(original_func, this->get_object_instance( ), args...);//todo: made it works without template args specified
			else
				return call_function(original_func, args...);
		}

		void set_original_func(void* fn) final
		{
			reinterpret_cast<void*&>(original_func) = fn;
		}

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

	struct hook_holder_data_after_call
	{
		std::atomic<bool> unhook;
		std::atomic<bool> disable;

		hook_holder_data_after_call( );
		hook_holder_data_after_call(const hook_holder_data_after_call& other);
		hook_holder_data_after_call& operator=(const hook_holder_data_after_call& other);

		void reset( );
	};

	class __declspec(novtable) hook_holder_data : protected virtual original_func_setter
	{
		mutable std::mutex mtx;
		hook_entry entry;
		hook_holder_data_after_call after_call;
		void* target = nullptr;
		void* replace = nullptr;

	protected:
		hook_holder_data( );

	public:

		hook_holder_data(hook_holder_data&& other)noexcept;
		hook_holder_data& operator=(hook_holder_data&& other)noexcept;

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

#define DHOOKS_SET_RETURN_ADDRESS_IMPL(_THIS_,_ADDR_,_FN_) \
	if(_THIS_->_Rt_addr_getter()->_ADDR_.has_value())\
		_THIS_->_Rt_addr_getter()->_ADDR_.emplace(_FN_);

#define DHOOKS_SET_RETURN_ADDRESS(_THIS_) \
	DHOOKS_SET_RETURN_ADDRESS_IMPL(_THIS_,addr1,_ReturnAddress())\
	DHOOKS_SET_RETURN_ADDRESS_IMPL(_THIS_,addr2,_AddressOfReturnAddress())

namespace dhooks
{
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

	export template<typename T>
		requires(std::is_member_function_pointer_v<T>)
	void* pointer_to_class_method(T fn)
	{
		const auto ptr = reinterpret_cast<void*&>(fn);
		return ptr;
	}

	template<typename T, typename Fn, typename Ret, call_conversion CallCvs, typename C, typename ...Args>
	Ret callback_proxy_impl(T* thisptr, Fn callback, hook_holder_impl<Ret, CallCvs, C, Args...>* instance, hiddent_type<Args> ...args)
	{
		if constexpr (std::is_class_v<C>)
		{
			instance->set_object_instance(thisptr);
			return std::invoke(
				callback,
				instance, args.unhide( )...
			);
		}
		else
		{
			hiddent_type<void*> fake_thisptr = thisptr;
			return std::apply(
				callback,
				std::tuple_cat(std::tuple(instance), shift_left(std::tuple(fake_thisptr, args...)))
			);
		}
	}

#define DHOOKS_HOOK_HOLDER_IMPL(_CALL_CVS_)\
	export template <typename Ret, typename Arg1, typename ...Args>\
	struct hook_holder<Ret, call_conversion::_CALL_CVS_##__, Arg1, Args...>: hook_holder_impl<Ret, call_conversion::_CALL_CVS_##__, Arg1, Args...>\
	{\
		Ret __##_CALL_CVS_ callback_proxy(hiddent_type<Args> ...args)\
		{\
			auto inst = this->instance( );\
			DHOOKS_SET_RETURN_ADDRESS(inst);\
			return callback_proxy_impl(this,&hook_holder::callback_impl,inst,args...);\
		}\
		void* get_replace_method( ) final\
		{\
			return pointer_to_class_method(&hook_holder::callback_proxy); \
		}\
	};

	DHOOKS_CALL_CVS_HELPER_ALL(DHOOKS_HOOK_HOLDER_IMPL);

#define DHOOKS_HOOK_HOLDER_MEMBER_IMPL(_CALL_CVS_,_CONST_)\
	template <typename Ret, typename C, typename ...Args>\
	hook_holder<Ret, call_conversion::_CALL_CVS_##__, C, Args...>\
	select_hook_holder_impl(Ret (__##_CALL_CVS_ C::*fn)(Args ...) _CONST_) { return {}; }

#define DHOOKS_HOOK_HOLDER_MEMBER(_CALL_CVS_)\
	DHOOKS_HOOK_HOLDER_MEMBER_IMPL(_CALL_CVS_,)\
	DHOOKS_HOOK_HOLDER_MEMBER_IMPL(_CALL_CVS_,const)

	DHOOKS_CALL_CVS_HELPER_ALL(DHOOKS_HOOK_HOLDER_MEMBER);

#define DHOOKS_HOOK_HOLDER_STATIC(_CALL_CVS_)\
	template <typename Ret, typename ...Args>\
	hook_holder<Ret, call_conversion::_CALL_CVS_##__, void, Args...>\
	select_hook_holder_impl(Ret (__##_CALL_CVS_ *fn)(Args ...)) { return {}; }

	DHOOKS_CALL_CVS_HELPER_STATIC(DHOOKS_HOOK_HOLDER_STATIC);

	export template<typename Fn>
		using select_hook_holder = decltype(select_hook_holder_impl(std::declval<Fn>( )));
}
