module;

#include <nstd/runtime_assert_core.h>

#include <vector>

export module dhooks.entry;
import nstd.mem.protect;

//#define DHOOKS_ENTRY_STORE_IPS

class function_getter
{
	void* fn_ptr_;
	uint8_t ptr_size_;

public:
	operator void* () const noexcept
	{
		return fn_ptr_;
	}

	uint8_t size( ) const noexcept
	{
		return ptr_size_;
	}

	void* get( ) const noexcept
	{
		return fn_ptr_;
	}

	function_getter( )
	{
		fn_ptr_ = nullptr;
		ptr_size_ = 0;
	}

	template<typename Fn>
	function_getter(Fn fn)
	{
		fn_ptr_ = reinterpret_cast<void*&>(fn);
		ptr_size_ = sizeof(fn);
	}

	template<class C, class Fn = void*>
	function_getter(C* instance, const size_t index, Fn = {})
	{
		const auto vtable = *reinterpret_cast<void***>(instance);
		fn_ptr_ = vtable[index];
		ptr_size_ = sizeof(Fn);
	}
};

export namespace dhooks
{
	class hook_entry
	{
	public:
		hook_entry( );
		~hook_entry( );

		hook_entry(hook_entry&& other) noexcept;
		hook_entry& operator=(hook_entry&& other) noexcept;

		bool create( ) runtime_assert_noexcept;
		bool created( ) const noexcept;
		bool enabled( ) const noexcept;

		bool enable( ) runtime_assert_noexcept;
		bool disable( ) runtime_assert_noexcept;

		void* get_original_method( ) const runtime_assert_noexcept;
		void* get_target_method( ) const noexcept;
		void* get_replace_method( ) const noexcept;

		void set_target_method(const function_getter getter) runtime_assert_noexcept;
		void set_replace_method(const function_getter getter) runtime_assert_noexcept;

	private:
		function_getter target_ = nullptr;
		function_getter detour_ = nullptr; // [In] Address of the detour function.
#if defined(_M_X64) || defined(__x86_64__)
		void* pRelay = nullptr; // [Out] Address of the relay function.
#endif
		bool patch_above_ = false; // [Out] Should use the hot patch area?
		//uint32_t_t ips_count   = 0;     // [Out] Number of the instruction boundaries.

#ifdef DHOOKS_ENTRY_STORE_IPS
		std::vector<uint8_t> old_ips_; // [Out] Instruction boundaries of the target function.
		std::vector<uint8_t> new_ips_; // [Out] Instruction boundaries of the trampoline function.
#endif

		std::vector<uint8_t> trampoline_;
		nstd::mem::protect trampoline_protection_;

		bool enabled_ = false;
		std::vector<uint8_t> target_backup_;
	};



}
