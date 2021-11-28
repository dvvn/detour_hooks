#pragma once

#include <memory>

namespace dhooks
{
	enum class hook_status : uint8_t;
	class hook_entry;

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
		context( );
		~context( ) override;

		hook_result create_hook(void* target, void* detour) override;
		hook_status remove_hook(void* target, bool force) override;
		hook_status enable_hook(void* target) override;
		hook_status disable_hook(void* target) override;
		hook_result find_hook(void* target) const override;
		void remove_all_hooks( ) override;
		hook_status enable_all_hooks( ) override;
		hook_status disable_all_hooks( ) override;

	private:
		struct storage_type;
		std::unique_ptr<storage_type> storage_;
	};

	class context_safe final : public basic_context
	{
	public:
		context_safe(std::unique_ptr<basic_context>&& ctx);
		template <std::derived_from<context_safe> T>
		context_safe(std::unique_ptr<T>&& ctx) = delete;

		~context_safe( ) override;
		context_safe(context_safe&&) noexcept;
		context_safe& operator=(context_safe&&) noexcept;

		hook_result create_hook(void* target, void* detour) override;
		hook_status remove_hook(void* target, bool force) override;
		hook_status enable_hook(void* target) override;
		hook_status disable_hook(void* target) override;
		hook_result find_hook(void* target) const override;
		void remove_all_hooks( ) override;
		hook_status enable_all_hooks( ) override;
		hook_status disable_all_hooks( ) override;

	private:
		struct impl;
		std::unique_ptr<impl> impl_;
	};

	struct current_context
	{
		current_context(const current_context& other)                = delete;
		current_context(current_context&& other) noexcept            = delete;
		current_context& operator=(const current_context& other)     = delete;
		current_context& operator=(current_context&& other) noexcept = delete;

		static void set(std::shared_ptr<basic_context>&& ctx);
		static void reset( );
		static const std::shared_ptr<basic_context>& get( );
	private:
		static std::shared_ptr<basic_context>& get_ref( );
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
