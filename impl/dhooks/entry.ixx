module;

#include <vector>

export module dhooks:entry;
export import :trampoline;
export import :status;

export namespace dhooks
{
	struct hook_entry final : trampoline2
	{
		hook_entry( );
		~hook_entry( ) override;

		hook_entry(hook_entry&& other) noexcept;
		hook_entry& operator=(hook_entry&& other) noexcept;

		bool create(void* target, void* detour) override;

		bool enable( );
		bool disable( );

		hook_status set_state(bool enable);
		using trampoline2::fix_page_protection;
		void init_backup(void* from, size_t bytes_count);

		bool enabled = false;
	private:
		std::vector<uint8_t> backup_;
	};

}
