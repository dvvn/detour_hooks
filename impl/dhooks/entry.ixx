module;

#include <windows.h>
#include <vector>

export module dhooks:entry;
export import :trampoline;
export import :status;

export namespace dhooks
{
	class hook_entry final : public trampoline2
	{
	public:
		hook_entry( );
		~hook_entry( ) override;

		hook_entry(hook_entry&& other) noexcept;
		hook_entry& operator=(hook_entry&& other) noexcept;

		hook_status set_state(bool enable);

		bool enabled( ) const;
		void init_backup(LPVOID from, size_t bytes_count);
		void mark_disabled( );
	private:
		bool enabled_ = false;
		std::vector<uint8_t> backup_;
	};
}
