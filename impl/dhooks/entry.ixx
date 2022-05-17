module;

#include <nstd/runtime_assert_core.h>

#include <vector>

export module dhooks.entry;
import nstd.mem.protect;

//#define DHOOKS_ENTRY_STORE_IPS

export namespace dhooks
{
	class hook_entry
	{
	public:
		hook_entry();
		~hook_entry();

		hook_entry(hook_entry&& other) noexcept;
		hook_entry& operator=(hook_entry&& other) noexcept;

		bool create() runtime_assert_noexcept;
		bool created() const noexcept;
		bool enabled() const noexcept;

		bool enable() runtime_assert_noexcept;
		bool disable() runtime_assert_noexcept;

		void* get_original_method() const runtime_assert_noexcept;
		void* get_target_method() const noexcept;
		void* get_replace_method() const noexcept;

		void set_target_method(void* getter) runtime_assert_noexcept;
		void set_replace_method(void* getter) runtime_assert_noexcept;

	private:
		void* target_ = nullptr;
		void* detour_ = nullptr; // [In] Address of the detour function.
#ifdef DHOOKS_X64
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
