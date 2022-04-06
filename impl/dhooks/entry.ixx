module;

#include <vector>

export module dhooks.entry;
import nstd.mem.protect;

//#define DHOOKS_ENTRY_STORE_IPS

export namespace dhooks
{
	class hook_entry final
	{
	public:
		hook_entry( );
		~hook_entry( );

		hook_entry(hook_entry&& other) noexcept;
		hook_entry& operator=(hook_entry&& other) noexcept;

		bool create( );
		bool created( ) const;
		bool enabled( ) const;

		bool enable( );
		bool disable( );

		void* get_original_method( )const;
		void* get_target_method( )const;
		void* get_replace_method( )const;

	private:
		void set_target_method_impl(void* ptr);
		void set_replace_method_impl(void* ptr);

	public:
		template<typename T>
		void set_target_method(T obj)
		{
			set_target_method_impl(reinterpret_cast<void*&>(obj));
		}
		template<typename T>
		void set_replace_method(T obj)
		{
			set_replace_method_impl(reinterpret_cast<void*&>(obj));
		}

	private:
		void* target_ = nullptr;
		void* detour_ = nullptr; // [In] Address of the detour function.
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
