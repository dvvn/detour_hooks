module;

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

struct visible_vtable
{
	using table_type = void*;
	table_type* vtable;

	void* operator[](size_t index)const
	{
		return vtable[index];
	}
};

template<typename ClassT>
auto get_func_from_vtable(ClassT* instance, size_t index)
{
	auto vtable = *reinterpret_cast<const visible_vtable*>(instance);
	return vtable[index];
}

template<typename Out, typename In>
Out force_cast(In in)
{
	Out out;
	reinterpret_cast<void*&>(out) = reinterpret_cast<void*&>(in);
	return out;
}

#define DHOOKS_INVOKE_MEMBER_HEAD(_CALL_CVS_,_CONST_)\
template<typename Ret, typename ClassT, typename ...Args>\
Ret invoke_member(Ret(__##_CALL_CVS_ ClassT::* fn)(Args ...) _CONST_, _CONST_ ClassT* instance, std::type_identity_t<Args> ...args)

#define DHOOKS_INVOKE_MEMBER_BODY(_CALL_CVS_)\
std::invoke(force_cast<Ret(__##_CALL_CVS_*)(decltype(instance), Args...)>(fn),instance,static_cast<Args>(args)...)

#define DHOOKS_INVOKE_MEMBER_BODY_thiscall \
std::invoke(force_cast<Ret(__fastcall*)(decltype(instance), void*, Args...)>(fn),instance,nullptr,static_cast<Args>(args)...)
#define DHOOKS_INVOKE_MEMBER_BODY_fastcall \
DHOOKS_INVOKE_MEMBER_BODY(fastcall)
#define DHOOKS_INVOKE_MEMBER_BODY_stdcall \
DHOOKS_INVOKE_MEMBER_BODY(stdcall)
#define DHOOKS_INVOKE_MEMBER_BODY_cdecl \
DHOOKS_INVOKE_MEMBER_BODY(cdecl)
#define DHOOKS_INVOKE_MEMBER_BODY_vectorcall \
DHOOKS_INVOKE_MEMBER_BODY(vectorcall)

#define DHOOKS_INVOKE_MEMBER(_CALL_CVS_)\
DHOOKS_INVOKE_MEMBER_HEAD(_CALL_CVS_,)\
{\
	return DHOOKS_INVOKE_MEMBER_BODY_##_CALL_CVS_;\
}\
DHOOKS_INVOKE_MEMBER_HEAD(_CALL_CVS_,const)\
{\
	return DHOOKS_INVOKE_MEMBER_BODY_##_CALL_CVS_;\
}\

DHOOKS_CALL_CVS_HELPER_ALL(DHOOKS_INVOKE_MEMBER);

template<typename T, typename ...Args>
decltype(auto) invoke_global(T fn, Args&&...args)
{
	return std::invoke(fn, std::forward<Args>(args)...);
}

export namespace dhooks
{
	template<typename T, typename ...Args>
		requires(!std::is_member_function_pointer_v<T>)
	decltype(auto) invoke(T fn, Args&&...args)
	{
		return invoke_global(fn, std::forward<Args>(args)...);
	}

	template<typename T, typename ...Args>
		requires(std::is_member_function_pointer_v<T>)
	decltype(auto) invoke(T fn, Args&&...args)
	{
		return invoke_member(fn, std::forward<Args>(args)...);
	}

	template<typename T, typename ClassT, typename ...Args>
		requires(std::is_member_function_pointer_v<T>)
	decltype(auto) invoke([[maybe_unused]] T fn, const size_t index, ClassT* instance, Args&&...args)
	{
		return invoke_member(force_cast<T>(get_func_from_vtable(instance, index)), instance, std::forward<Args>(args)...);
	}
}

struct __declspec(novtable) original_func_setter
{
	virtual ~original_func_setter( ) = default;
	virtual void set_original_method(void* fn) = 0;
};

template <typename ClassT>
class object_instance_holder
{
	ClassT* instance_ = nullptr;
public:
	void set_object_instance(void* ptr)
	{
		reinterpret_cast<void*&>(instance_) = ptr;
	}

	ClassT* get_object_instance( ) const
	{
		return instance_;
	}
};

template < >
class object_instance_holder<void>
{
};

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

#define DHOOKS_COMPARE_CALL_CVS(_CALL_CVS_)\
if constexpr(CallCvs == call_conversion::_CALL_CVS_##__)

#define DHOOKS_GENERATE_MEMBER_FUNC(_CALL_CVS_)\
DHOOKS_COMPARE_CALL_CVS(_CALL_CVS_)\
{\
	Ret (__##_CALL_CVS_ ClassT::*fn)(Args ...) = nullptr;\
	return fn;\
}\
else

#define DHOOKS_GENERATE_GLOBAL_FUNC(_CALL_CVS_)\
DHOOKS_COMPARE_CALL_CVS(_CALL_CVS_)\
{\
	Ret (__##_CALL_CVS_ *fn)(Args ...) = nullptr;\
	return fn;\
}\
else

template <typename Ret, call_conversion CallCvs, typename ClassT, typename ...Args>
auto generate_function_type( )
{
	if constexpr (std::is_class_v<ClassT>)
	{
		DHOOKS_CALL_CVS_HELPER_ALL(DHOOKS_GENERATE_MEMBER_FUNC)
		{
			assert("unknown member function type");
		}
	}
	else
	{
		DHOOKS_CALL_CVS_HELPER_GLOBAL(DHOOKS_GENERATE_GLOBAL_FUNC)
		{
			assert("unknown global function type");
		}
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
			return std::move(*this).get_return_value( );
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

template <typename Ret, call_conversion CallCvs, typename ClassT, typename ...Args>
class original_function :public object_instance_holder<ClassT>, protected virtual original_func_setter, public return_value_holder<Ret>
{
	using func_type = decltype(generate_function_type<Ret, CallCvs, ClassT, Args...>( ));

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
		if constexpr (std::is_class_v<ClassT>)
			return invoke_member(original_func_, this->get_object_instance( ), static_cast<Args>(args)...);
		else
			return invoke_global(original_func_, static_cast<Args>(args)...);
	}

	void set_original_method(void* fn) final
	{
		original_func_void_ = fn;
	}

	Ret call_original_and_store_result(Args ...args)
	{
		if constexpr (!std::is_void_v<Ret>)
		{
			decltype(auto) ret = this->call_original(static_cast<Args>(args)...);
			this->store_return_value(ret);
			return ret;
		}
		else
		{
			this->call_original(static_cast<Args>(args)...);
			this->store_return_value( );
		}
	}
};

template<typename T>
void* to_void_ptr(T obj)
{
	if constexpr (std::invocable<T>)
		return to_void_ptr(std::invoke(obj));
	else if constexpr (std::is_member_function_pointer_v<T>)
		return force_cast<void*>(obj);
	else
		return static_cast<void*>(obj);
}

export namespace dhooks
{
	class hook_holder_data : protected virtual original_func_setter
	{
		mutable std::mutex mtx_;
		hook_entry entry_;
		/*std::atomic<bool>*/bool disable_after_call_ = false;

	protected:
		hook_holder_data( );

	public:
		hook_holder_data(hook_holder_data&& other)noexcept;
		hook_holder_data& operator=(hook_holder_data&& other)noexcept;

		bool hook( );

		bool enable( );
		bool disable( );
		void request_disable( );

		bool hooked( ) const;
		bool enabled( ) const;

	private:
		void set_target_method_impl(void* fn);
		void set_replace_method_impl(void* fn);

	protected:
		bool process_disable_request( );

		template<typename T>
		void set_target_method(T source)
		{
			set_target_method_impl(to_void_ptr(source));
		}
		template<typename T>
		void set_replace_method(T source)
		{
			set_replace_method_impl(to_void_ptr(source));
		}
	};

#define DHOOKS_HOOK_HOLDER_HEAD_TEMPLATE_ARGS\
	size_t InstanceIdx, typename Ret

#define DHOOKS_HOOK_HOLDER_TYPE_IMPL(_NAME_,_CALL_CVS_,_CLASS_) _NAME_<InstanceIdx, Ret, call_conversion::_CALL_CVS_##__, _CLASS_, Args...>
#define DHOOKS_HOOK_HOLDER_BASE_TYPE(_CALL_CVS_,_CLASS_) DHOOKS_HOOK_HOLDER_TYPE_IMPL(hook_holder_base,_CALL_CVS_,_CLASS_)
#define DHOOKS_HOOK_HOLDER_TYPE(_CALL_CVS_,_CLASS_)	DHOOKS_HOOK_HOLDER_TYPE_IMPL(hook_holder,_CALL_CVS_,_CLASS_)

	template<DHOOKS_HOOK_HOLDER_HEAD_TEMPLATE_ARGS, call_conversion CallCvs, typename ClassT, typename ...Args>
	struct hook_holder;

	template<DHOOKS_HOOK_HOLDER_HEAD_TEMPLATE_ARGS, call_conversion CallCvs, typename ClassT, typename ...Args>
	class hook_holder_base : public original_function<Ret, CallCvs, ClassT, Args...>, public hook_holder_data
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
			this->callback(static_cast<Args>(args)...);
			if (!this->have_return_value( ))
				this->call_original_and_store_result(static_cast<Args>(args)...);
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

#define HOOK_HOLDER_STATIC_void static
#define HOOK_HOLDER_STATIC_ClassT

#define HOOK_HOLDER_SET_OBJ_INST_void
#define HOOK_HOLDER_SET_OBJ_INST_ClassT hook_base::instance( )->set_object_instance(this);

#define DHOOKS_HOOK_HOLDER_IMPL(_CALL_CVS_,_CLASS_TYPE_)\
struct DHOOKS_HOOK_HOLDER_TYPE(_CALL_CVS_,_CLASS_TYPE_) : DHOOKS_HOOK_HOLDER_BASE_TYPE(_CALL_CVS_,_CLASS_TYPE_)\
{\
	using hook_base = DHOOKS_HOOK_HOLDER_BASE_TYPE(_CALL_CVS_,_CLASS_TYPE_);\
	hook_holder( )\
	{\
		this->set_replace_method(&hook_holder::replace_method);\
	}\
private:\
	HOOK_HOLDER_STATIC_##_CLASS_TYPE_ Ret __##_CALL_CVS_ replace_method(Args...args)\
	{\
		HOOK_HOLDER_SET_OBJ_INST_##_CLASS_TYPE_;\
		return hook_base::instance( )->callback_proxy(static_cast<Args>(args)...);\
	}\
};

#define DHOOKS_HOOK_HOLDER_MEMBER(_CALL_CVS_)\
	template<DHOOKS_HOOK_HOLDER_HEAD_TEMPLATE_ARGS, typename ClassT, typename ...Args>\
	DHOOKS_HOOK_HOLDER_IMPL(_CALL_CVS_,ClassT)

#define DHOOKS_HOOK_HOLDER_GLOBAL(_CALL_CVS_)\
	template<DHOOKS_HOOK_HOLDER_HEAD_TEMPLATE_ARGS, typename ...Args>\
	DHOOKS_HOOK_HOLDER_IMPL(_CALL_CVS_,void)

	DHOOKS_CALL_CVS_HELPER_ALL(DHOOKS_HOOK_HOLDER_MEMBER);
	DHOOKS_CALL_CVS_HELPER_GLOBAL(DHOOKS_HOOK_HOLDER_GLOBAL);

#define DHOOKS_HOOK_HOLDER_SELECTOR_MEMBER_IMPL(_CALL_CVS_,_CONST_)\
	template <DHOOKS_HOOK_HOLDER_HEAD_TEMPLATE_ARGS, typename ClassT, typename ...Args>\
	DHOOKS_HOOK_HOLDER_TYPE(_CALL_CVS_,ClassT)\
	select_hook_holder_impl(Ret (__##_CALL_CVS_ ClassT::*fn)(Args ...) _CONST_) { return {}; }

#define DHOOKS_HOOK_HOLDER_SELECTOR_MEMBER(_CALL_CVS_)\
	DHOOKS_HOOK_HOLDER_SELECTOR_MEMBER_IMPL(_CALL_CVS_,)\
	DHOOKS_HOOK_HOLDER_SELECTOR_MEMBER_IMPL(_CALL_CVS_,const)

#define DHOOKS_HOOK_HOLDER_SELECTOR_GLOBAL(_CALL_CVS_)\
	template <DHOOKS_HOOK_HOLDER_HEAD_TEMPLATE_ARGS, typename ...Args>\
	DHOOKS_HOOK_HOLDER_TYPE(_CALL_CVS_,void)\
	select_hook_holder_impl(Ret (__##_CALL_CVS_ *fn)(Args ...)) { return {}; }

	DHOOKS_CALL_CVS_HELPER_ALL(DHOOKS_HOOK_HOLDER_SELECTOR_MEMBER);
	DHOOKS_CALL_CVS_HELPER_GLOBAL(DHOOKS_HOOK_HOLDER_SELECTOR_GLOBAL);

	template<typename Fn, size_t InstanceIdx = 0>
	using select_hook_holder = decltype(select_hook_holder_impl<InstanceIdx>(std::declval<Fn>( )));

	/*template<typename Fn, size_t InstanceIdx = 0>
	using select_hook_holder_base = select_hook_holder<Fn, InstanceIdx>::hook_base;*/
}

