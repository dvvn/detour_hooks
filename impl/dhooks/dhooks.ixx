module;

#include <intrin.h>

#include <memory>
#include <mutex>
#include <array>
#include <cassert>

export module dhooks;
import :entry;

#ifndef assertm
#define assertm(exp, msg) assert(((void)msg, exp))
#endif

#define DHOOKS_CALL_CVS_HELPER_GLOBAL(_MACRO_)\
		_MACRO_(cdecl)\
		_MACRO_(stdcall)\
		_MACRO_(vectorcall)\
		_MACRO_(fastcall)

#define DHOOKS_CALL_CVS_HELPER_MEMBER(_MACRO_)\
		_MACRO_(thiscall)

#define DHOOKS_CALL_CVS_HELPER_ALL(_MACRO_)\
		DHOOKS_CALL_CVS_HELPER_GLOBAL(_MACRO_)\
		DHOOKS_CALL_CVS_HELPER_MEMBER(_MACRO_)


template<typename Out, typename In>
Out force_cast(In in)
{
	Out out;
	reinterpret_cast<void*&>(out) = reinterpret_cast<void*&>(in);
	return out;
}

//#define DHOOKS_INVOKE(_FN_,...) std::invoke(_FN_,__VA_ARGS__)
#define DHOOKS_INVOKE(_FN_,...) _FN_(__VA_ARGS__)

#define DHOOKS_INVOKE_FORCE(_OUT_TYPE_, _FN_, ...)\
	DHOOKS_INVOKE(force_cast<_OUT_TYPE_>(_FN_),__VA_ARGS__)
#define DHOOKS_INVOKE_GLOBAL(_FN_)\
	DHOOKS_INVOKE(_FN_, std::forward<Args>(args)...)

/*template<typename Out, typename In, typename ...Args>
decltype(auto) force_cast_and_call(In in, Args&&...args)
{
	auto out = force_cast<Out>(in);
	return out(std::forward<Args>(args)...);
}*/

struct visible_vtable
{
	using table_type = void*;
	table_type* vtable;

	void* operator[](size_t index)const
	{
		return vtable[index];
	}
};

template<typename C>
auto get_func_from_vtable(C* instance, size_t index)
{
	auto vtable = *reinterpret_cast<const visible_vtable*>(instance);
	return vtable[index];
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

export namespace dhooks
{
#define DHOOKS_CALL_MEMBER_FN_HEAD(_CALL_CVS_,_CONST_,...)\
	template<typename Ret, typename C, typename ...Args>\
	Ret call_function(Ret(__##_CALL_CVS_ C::* fn)(Args ...) _CONST_, _CONST_ C* instance,##__VA_ARGS__, Args ...args)
#define DHOOKS_CALL_FN_HEAD(_CALL_CVS_)\
	template<typename Ret, typename ...Args>\
	Ret call_function(Ret(__##_CALL_CVS_ *fn)(Args ...), Args ...args)

#define DHOOKS_CALL_MEMBER_FN_BODY(_CALL_CVS_)\
	DHOOKS_INVOKE_FORCE(Ret(__##_CALL_CVS_*)(decltype(instance), Args...), fn, instance, std::forward<Args>(args)...);

#define DHOOKS_CALL_MEMBER(_CALL_CVS_)\
	DHOOKS_CALL_MEMBER_FN_HEAD(_CALL_CVS_, )\
	{\
		return DHOOKS_INVOKE_MEMBER_##_CALL_CVS_(fn);\
	}\
	DHOOKS_CALL_MEMBER_FN_HEAD(_CALL_CVS_, const)\
	{\
		return DHOOKS_INVOKE_MEMBER_##_CALL_CVS_(fn);\
	}\
	DHOOKS_CALL_MEMBER_FN_HEAD(_CALL_CVS_, , size_t index)\
	{\
		return DHOOKS_INVOKE_MEMBER_##_CALL_CVS_(get_func_from_vtable(instance,index));\
	}\
	DHOOKS_CALL_MEMBER_FN_HEAD(_CALL_CVS_, const, size_t index)\
	{\
		return DHOOKS_INVOKE_MEMBER_##_CALL_CVS_(get_func_from_vtable(instance,index));\
	}

#define DHOOKS_INVOKE_MEMBER_any(_CALL_CVS_,_FN_)\
	DHOOKS_INVOKE_FORCE(Ret(__##_CALL_CVS_*)(decltype(instance), Args...), _FN_, instance, std::forward<Args>(args)...);
#define DHOOKS_INVOKE_MEMBER_thiscall(_FN_)\
	DHOOKS_INVOKE_FORCE(Ret(__fastcall*)(decltype(instance),void*, Args...), _FN_, instance, nullptr, std::forward<Args>(args)...);
#define DHOOKS_INVOKE_MEMBER_fastcall(_FN_) DHOOKS_INVOKE_MEMBER_any(fastcall,_FN_)
#define DHOOKS_INVOKE_MEMBER_stdcall(_FN_) DHOOKS_INVOKE_MEMBER_any(stdcall,_FN_)
#define DHOOKS_INVOKE_MEMBER_cdecl(_FN_) DHOOKS_INVOKE_MEMBER_any(cdecl,_FN_)
#define DHOOKS_INVOKE_MEMBER_vectorcall(_FN_) DHOOKS_INVOKE_MEMBER_any(vectorcall,_FN_)

	DHOOKS_CALL_CVS_HELPER_ALL(DHOOKS_CALL_MEMBER);

	template<typename T, typename ...Args>
		requires(!std::is_member_function_pointer_v<T>)
	decltype(auto) call_function(T fn, Args&&...args)
	{
		return DHOOKS_INVOKE_GLOBAL(fn);
	}
}

struct __declspec(novtable) original_func_setter
{
	virtual ~original_func_setter( ) = default;
	virtual void set_original_method(void* fn) = 0;
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

#define DHOOKS_GENERATE_FUNC(_CALL_CVS_)\
 constexpr(CallCvs == call_conversion::_CALL_CVS_##__)\
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
	if DHOOKS_GENERATE_FUNC(cdecl)
	else if	DHOOKS_GENERATE_FUNC(stdcall)
	else if	DHOOKS_GENERATE_FUNC(vectorcall)
	else if	DHOOKS_GENERATE_FUNC(fastcall)
	else if constexpr (CallCvs == call_conversion::thiscall__)
	{
		Ret(__thiscall C:: * fn)(Args ...) = nullptr;
		return fn;
	}
}

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
public:
	using func_type = decltype(generate_function_type<Ret, CallCvs, C, Args...>( ));

protected:
	union
	{
		func_type original_func_;
		void* original_func_void_;
	};

public:
	original_function( )
	{
		original_func_void_ = nullptr;
	}

	func_type get_original( )const
	{
		return original_func_;
	}

	Ret call_original(Args ...args)
	{
		/*if constexpr (!std::is_class_v<C>)
		{
			return DHOOKS_INVOKE_GLOBAL(original_func_);
		}
		else
		{
#define DHOOKS_ORIGINAL_FN_CLASS_CALL(_CALL_CVS_)\
				constexpr (CallCvs == call_conversion::_CALL_CVS_##__)\
					{return DHOOKS_INVOKE_MEMBER_##_CALL_CVS_(original_func_);}

				auto instance = this->get_object_instance( );
				assertm(instance != nullptr, "Object instance not set!");
				if DHOOKS_ORIGINAL_FN_CLASS_CALL(cdecl)
				else if DHOOKS_ORIGINAL_FN_CLASS_CALL(stdcall)
				else if DHOOKS_ORIGINAL_FN_CLASS_CALL(vectorcall)
				else if DHOOKS_ORIGINAL_FN_CLASS_CALL(fastcall)
				else if DHOOKS_ORIGINAL_FN_CLASS_CALL(thiscall)
#undef DHOOKS_ORIGINAL_FN_CLASS_CALL
			}*/
		if constexpr (std::is_class_v<C>)
			return call_function<Ret, C, Args...>(original_func_, this->get_object_instance( ), std::forward<Args>(args)...);
		else
			return call_function(original_func_, std::forward<Args>(args)...);
	}

	void set_original_method(void* fn) final
	{
		original_func_void_ = fn;
	}

	Ret call_original_and_store_result(Args ...args)
	{
		if constexpr (!std::is_void_v<Ret>)
		{
			decltype(auto) ret = this->call_original(std::forward<Args>(args)...);
			this->store_return_value(ret);
			return ret;
		}
		else
		{
			this->call_original(std::forward<Args>(args)...);
			this->store_return_value( );
		}
	}
};

export namespace dhooks
{
	struct hook_enabler
	{
		virtual ~hook_enabler( ) = default;
		virtual bool enable( ) = 0;
	};

	struct hook_disabler
	{
		virtual ~hook_disabler( ) = default;
		virtual bool disable( ) = 0;
	};

	struct hook_disabler_lazy
	{
		virtual ~hook_disabler_lazy( ) = default;
		virtual void request_disable( ) = 0;
	};

	class hook_holder_data : protected virtual original_func_setter, public hook_enabler, public hook_disabler, public hook_disabler_lazy
	{
		mutable std::mutex mtx_;
		hook_entry entry_;
		bool disable_after_call_ = false;

	protected:
		hook_holder_data( );

	public:

		hook_holder_data(hook_holder_data&& other)noexcept;
		hook_holder_data& operator=(hook_holder_data&& other)noexcept;

		bool hook( );

		bool enable( ) final;
		bool disable( ) final;
		void request_disable( ) final;

		bool hooked( ) const;
		bool enabled( ) const;

	protected:
		void set_target_method(void* fn);
		void set_replace_method(void* fn);

		bool process_disable_request( );
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

#define DHOOKS_HOOK_HOLDER_HEAD_TEMPLATE_ARGS\
	size_t UniqueIdx, typename Ret
#define DHOOKS_HOOK_HOLDER_HEAD_ARGS\
	UniqueIdx, Ret

#define DHOOKS_SET_RETURN_ADDRESS_IMPL(_THIS_,_ADDR_,_FN_) \
	if(_THIS_->_Rt_addr_getter()->_ADDR_.has_value())\
		_THIS_->_Rt_addr_getter()->_ADDR_.emplace(_FN_);

#define DHOOKS_SET_RETURN_ADDRESS(_THIS_) \
	DHOOKS_SET_RETURN_ADDRESS_IMPL(_THIS_,addr1,_ReturnAddress())\
	DHOOKS_SET_RETURN_ADDRESS_IMPL(_THIS_,addr2,_AddressOfReturnAddress())

	template<typename T>
		requires(std::is_member_function_pointer_v<T>)
	void* pointer_to_class_method(T fn)
	{
		const auto ptr = reinterpret_cast<void*&>(fn);
		return ptr;
	}

#define DHOOKS_EMPTY_ARG

#define DHOOKS_HOOK_HOLDER_TYPE_IMPL(_NAME_,_CALL_CVS_,_CLASS_) _NAME_<DHOOKS_HOOK_HOLDER_HEAD_ARGS, call_conversion::_CALL_CVS_##__, _CLASS_, Args...>
#define DHOOKS_HOOK_HOLDER_BASE_TYPE(_CALL_CVS_,_CLASS_) DHOOKS_HOOK_HOLDER_TYPE_IMPL(hook_holder_base,_CALL_CVS_,_CLASS_)
#define DHOOKS_HOOK_HOLDER_TYPE(_CALL_CVS_,_CLASS_)	DHOOKS_HOOK_HOLDER_TYPE_IMPL(hook_holder,_CALL_CVS_,_CLASS_)

	template<DHOOKS_HOOK_HOLDER_HEAD_TEMPLATE_ARGS, call_conversion CallCvs, typename ClassT, typename ...Args>
	struct hook_holder;

	template<DHOOKS_HOOK_HOLDER_HEAD_TEMPLATE_ARGS, call_conversion CallCvs, typename ClassT, typename ...Args>
	class hook_holder_base : public return_address_getter
		, public original_function<Ret, CallCvs, ClassT, Args...>
		, public hook_holder_data
	{
	protected:
		static auto& instance( )
		{
			static hook_holder_base* obj = nullptr;
			return obj;
		}

		virtual void callback(Args ...) = 0; 

	public:
		Ret callback_proxy(Args ...args)
		{
			assertm(instance( ) == this, "instance not set!");
			this->callback(std::forward<Args>(args)...);
			if (!this->have_return_value( ))
				this->call_original_and_store_result(std::forward<Args>(args)...);
			this->process_disable_request( );
			return std::move(*this).get_return_value( );
		}

		hook_holder_base( )
		{
			auto& inst = instance( );
			assertm(inst == nullptr, "instance already created!");
			inst = this;
		}

		~hook_holder_base( )
		{
			auto& inst = instance( );
			if (inst == this)
				inst = nullptr;
		}
	};

#define DHOOKS_HOOK_HOLDER_MEMBER(_CALL_CVS_)\
	template<DHOOKS_HOOK_HOLDER_HEAD_TEMPLATE_ARGS, typename ClassT, typename ...Args>\
	struct DHOOKS_HOOK_HOLDER_TYPE(_CALL_CVS_, ClassT) : DHOOKS_HOOK_HOLDER_BASE_TYPE(_CALL_CVS_,ClassT)\
	{\
		using hook_base = DHOOKS_HOOK_HOLDER_BASE_TYPE(_CALL_CVS_,ClassT);\
		hook_holder( )\
		{\
			this->set_replace_method(pointer_to_class_method(&hook_holder::replace_method));\
		}\
	private:\
		Ret __##_CALL_CVS_ replace_method(Args...args)\
		{\
			hook_base::instance( )->set_object_instance(this);\
			return hook_base::instance( )->callback_proxy(std::forward<Args>(args)...);\
		}\
	};

#define DHOOKS_HOOK_HOLDER_GLOBAL(_CALL_CVS_)\
	template<size_t UniqueIdx, typename Ret, typename ...Args>\
	struct DHOOKS_HOOK_HOLDER_TYPE(_CALL_CVS_, void) : DHOOKS_HOOK_HOLDER_BASE_TYPE(_CALL_CVS_,void)\
	{\
		using hook_base = DHOOKS_HOOK_HOLDER_BASE_TYPE(_CALL_CVS_,void);\
		hook_holder( )\
		{\
			this->set_replace_method(&hook_holder::replace_method);\
		}\
	private:\
		static Ret __##_CALL_CVS_ replace_method(Args...args)\
		{\
			return hook_base::instance( )->callback_proxy(std::forward<Args>(args)...);\
		}\
	};

	DHOOKS_CALL_CVS_HELPER_ALL(DHOOKS_HOOK_HOLDER_MEMBER);
	DHOOKS_CALL_CVS_HELPER_GLOBAL(DHOOKS_HOOK_HOLDER_GLOBAL);

#define DHOOKS_HOOK_HOLDER_SELECTOR_MEMBER_IMPL(_CALL_CVS_,_CONST_)\
	template <DHOOKS_HOOK_HOLDER_HEAD_TEMPLATE_ARGS, typename ClassT, typename ...Args>\
	DHOOKS_HOOK_HOLDER_TYPE(_CALL_CVS_,ClassT)\
	select_hook_holder_impl(Ret (__##_CALL_CVS_ ClassT::*fn)(Args ...) _CONST_) { return {}; }

#define DHOOKS_HOOK_HOLDER_SELECTOR_MEMBER(_CALL_CVS_)\
	DHOOKS_HOOK_HOLDER_SELECTOR_MEMBER_IMPL(_CALL_CVS_,DHOOKS_EMPTY_ARG)\
	DHOOKS_HOOK_HOLDER_SELECTOR_MEMBER_IMPL(_CALL_CVS_,const)

#define DHOOKS_HOOK_HOLDER_SELECTOR_GLOBAL(_CALL_CVS_)\
	template <DHOOKS_HOOK_HOLDER_HEAD_TEMPLATE_ARGS, typename ...Args>\
	hook_holder<DHOOKS_HOOK_HOLDER_HEAD_ARGS, call_conversion::_CALL_CVS_##__, void, Args...>\
	select_hook_holder_impl(Ret (__##_CALL_CVS_ *fn)(Args ...)) { return {}; }

	DHOOKS_CALL_CVS_HELPER_ALL(DHOOKS_HOOK_HOLDER_SELECTOR_MEMBER);
	DHOOKS_CALL_CVS_HELPER_GLOBAL(DHOOKS_HOOK_HOLDER_SELECTOR_GLOBAL);

	template<typename Fn, size_t UniqueIdx = 0>
	using select_hook_holder = decltype(select_hook_holder_impl<UniqueIdx>(std::declval<Fn>( )));

	template<typename Fn, size_t UniqueIdx = 0>
	using select_hook_holder_base = select_hook_holder<Fn, UniqueIdx>::hook_base;
}

