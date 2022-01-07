module;

#include <nstd/one_instance.h>

#include <vector>
#include <mutex>

export module dhooks:context;
export import :status;
export import :entry;

export namespace dhooks
{
	struct hook_result
	{
		template <std::convertible_to<hook_status> T>
		hook_result(T status)
			: status(status)
		{
			//runtime_assert(this->status == hook_status::OK);
		}

		hook_status status;
		hook_entry* entry = nullptr;
	};

	class __declspec(novtable) basic_context
	{
	public:
		virtual ~basic_context( ) = default;

		virtual hook_result create_hook(void* target, void* detour) = 0;
		virtual hook_status remove_hook(void* target, bool force = false) = 0;
		virtual hook_status enable_hook(void* target) = 0;
		virtual hook_status disable_hook(void* target) = 0;
		virtual hook_result find_hook(void* target) const = 0;
		virtual void remove_all_hooks( ) = 0;
		virtual hook_status enable_all_hooks( ) = 0;
		virtual hook_status disable_all_hooks( ) = 0;
	};

	class context final : public basic_context
	{
	public:
		using value_type = std::vector<hook_entry>;

		context( ) = default;

		hook_result create_hook(void* target, void* detour) override;
		hook_status remove_hook(void* target, bool force) override;
		hook_status enable_hook(void* target) override;
		hook_status disable_hook(void* target) override;
		hook_result find_hook(void* target) const override;
		void remove_all_hooks( ) override;
		hook_status enable_all_hooks( ) override;
		hook_status disable_all_hooks( ) override;

	private:
		value_type storage_;
	};

	class context_safe final : public basic_context
	{
	public:
		context_safe(std::unique_ptr<basic_context>&& ctx);
		context_safe(std::unique_ptr<context_safe>&& ctx) = delete;

		hook_result create_hook(void* target, void* detour) override;
		hook_status remove_hook(void* target, bool force) override;
		hook_status enable_hook(void* target) override;
		hook_status disable_hook(void* target) override;
		hook_result find_hook(void* target) const override;
		void remove_all_hooks( ) override;
		hook_status enable_all_hooks( ) override;
		hook_status disable_all_hooks( ) override;

	private:
		std::unique_ptr<basic_context> ctx_;
		mutable std::recursive_mutex mtx_;
	};

	using current_context_base = nstd::one_instance<std::shared_ptr<basic_context>>;
	struct current_context
	{
		using element_type = current_context_base::element_type;

		static void set(element_type&& ctx);
		static void reset( );
		static basic_context& get( );
		static const element_type& share( );
	};

#if 0
	/// @brief Creates a Hook for the specified Windows API function, in disabled state.
	/// @param pszModule A pointer to the loaded module name which contains the target function.
	/// @param pszProcName A pointer to the target function name, which will be overridden by the detour function.
	/// @param pDetour A pointer to the detour function, which will override the target function.
	/// @return
	[[deprecated("use CreateHook directly. result are same")]]
	auto create_hook_win_api(LPCWSTR pszModule, LPCSTR pszProcName, void* pDetour)->hook_result;
#endif
}
