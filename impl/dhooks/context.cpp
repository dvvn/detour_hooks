#if 0

module;

#include <nstd/runtime_assert.h>
#include <nstd/ranges.h>
#include <nstd/mem/block_includes.h>

#include <Windows.h>

#include <vector>
#include <mutex>
#ifdef _DEBUG
#include <stdexcept>
#endif

module dhooks:context;
import nstd.mem;

using namespace dhooks;

#if 0

//i found it useless

static DWORD_PTR FindOldIP(HOOK_ENTRY& pHook, DWORD_PTR ip)
{
	if (pHook.patchAbove && ip == ((DWORD_PTR)pHook.target - sizeof(JMP_REL)))
		return (DWORD_PTR)pHook.target;

	for (UINT i = 0; i < pHook.nIP; ++i)
	{
		if (ip == ((DWORD_PTR)pHook.pTrampoline.get( ) + pHook.newIPs[i]))
			return (DWORD_PTR)pHook.target + pHook.oldIPs[i];
	}

#if defined(_M_X64) || defined(_x86_64_)
	// Check relay function.
	if (ip == (DWORD_PTR)pHook.pDetour)
		return (DWORD_PTR)pHook.target;
#endif

	return 0;
}

static DWORD_PTR FindNewIP(HOOK_ENTRY& pHook, DWORD_PTR ip)
{
	for (UINT i = 0; i < pHook.nIP; ++i)
	{
		if (ip == ((DWORD_PTR)pHook.target + pHook.oldIPs[i]))
			return (DWORD_PTR)pHook.pTrampoline.get( ) + pHook.newIPs[i];
	}

	return 0;
}

static void ProcessThreadIPs(HANDLE hThread, const hooks_storage::iterator& pos, bool enable)
{
	// If the thread suspended in the overwritten area,
	// std::move IP to the proper address.

	CONTEXT c;
#if defined(_M_X64) || defined(_x86_64_)
	const auto pIP = &c.Rip;
#else
	const auto pIP = &c.Eip;
#endif

	c.ContextFlags = CONTEXT_CONTROL;
	if (!GetThreadContext(hThread, &c))
		return;

	for (auto pHook : storage::get( ).filter_enabled(std::span{pos, storage::get( ).end( )}, enable))
	{
		DWORD_PTR ip;

		if (enable)
			ip = FindNewIP(*pHook, *pIP);
		else
			ip = FindOldIP(*pHook, *pIP);

		if (ip != 0)
		{
			*pIP = ip;
			SetThreadContext(hThread, &c);
		}
	}
}
#endif

#ifdef _DEBUG_OFF
status_ex::status_ex(status s) : status_ex_impl{s}
{
	if (s == status::OK)
		return;

	const auto start = string_view("Error detected: status ");
	const auto end = status_to_string(s);

	std::string str;
	str.reserve(start.size( ) + end.size( ));

	str += start;
	str += end;

	throw std::runtime_error(std::move(str));
}
#endif

template <typename T>
static auto _Find_hook_itr(T& storage, void* target)
{
	runtime_assert(target != nullptr);
	//return std::ranges::find(storage, target, &hook_entry::target*);
	auto end = storage.end( );
	for (auto itr = storage.begin( ); itr != end; ++itr)
	{
		auto& entry = *itr;
		if (target == entry->target)
			return itr;
	}
	return end;
}

template <typename T>
static hook_entry_shared _Find_hook(T& storage, void* target)
{
	auto itr = _Find_hook_itr(storage, target);
	if (itr == storage.end( ))
		return nullptr;
	else
		return *itr;
}

template <typename T>
static hook_status _Set_hook_state(T& storage, void* target, bool enable)
{
	auto entry = _Find_hook(storage, target);
	if (!entry)
		return hook_status::ERROR_NOT_CREATED;

	if (entry->enabled == enable)
		return enable ? hook_status::ERROR_ENABLED : hook_status::ERROR_DISABLED;

	return entry->set_state(enable);
}

template <typename T>
static hook_status _Set_hook_state_all(T& storage, bool enable, bool ignore_errors = false)
{
	constexpr auto transform_fn = [](const hook_entry_shared& h)->hook_entry&
	{
		return *h;
	};

	constexpr auto filter_fn = [](const hook_entry& h)
	{
		return h.target != nullptr;
	};

	auto storage_active = storage | std::views::transform(transform_fn) | std::views::filter(filter_fn);
	const auto begin = storage_active.begin( );
	const auto end = storage_active.end( );

	for (auto itr_main = begin; itr_main != end; ++itr_main)
	{
		auto& value = *itr_main;
		if (value.enabled == enable)
			continue;

#if 0
		if (pause_threads)
		{
			//fill only if any hook enabled
			frozen.fill( );
		}
#endif

#ifdef _DEBUG
		hook_status main_status = hook_status::UNKNOWN;
		try
		{
			main_status = value.set_state(enable);
			if (main_status == hook_status::OK)
				runtime_assert("Error in code");
			continue;
		}
		catch ([[maybe_unused]] const std::runtime_error& e)
		{
			if (ignore_errors)
				continue;
		}
#else
		const auto main_status = value.set_state(enable);
		if (main_status == hook_status::OK)
			continue;
		if (ignore_errors)
			continue;
#endif

		//restore changes back
		enable = !enable;
		for (auto itr_child = begin; itr_child != itr_main; ++itr_child)
		{
			auto& value_child = *itr_child;
			if (value_child.enabled == enable)
				continue;
			const auto temp_status = value_child.set_state(enable);
			if (temp_status != hook_status::OK)
			{
				runtime_assert("Unable to revert hook state!");
				return temp_status;
			}
		}
		return main_status;
	}

	return hook_status::OK;
}

//--------


//moved
hook_result context::create_hook(void* target, void* detour)
{
	if (!nstd::mem::block(target).executable( ) || !nstd::mem::block(detour).executable( ))
		return hook_status::ERROR_NOT_EXECUTABLE;

#if 0
	if (storage_.find(target) != nullptr)
		return hook_status::ERROR_ALREADY_CREATED;
	if (storage_.find(pDetour) != nullptr)
		return hook_status::ERROR_ALREADY_CREATED;
#endif

	if (target == detour)
		return hook_status::ERROR_UNSUPPORTED_FUNCTION;

	const auto check_ptr_helper = [&](void* checked)
	{
		return checked == target || checked == detour;
	};
	for (const auto& value : storage_)
	{
		if (check_ptr_helper(value->target) || check_ptr_helper(value->detour))
			return hook_status::ERROR_ALREADY_CREATED;
	}

	auto new_hook = std::make_shared<hook_entry>( );

	if (!new_hook->create())
		return hook_status::ERROR_UNSUPPORTED_FUNCTION;
	if (!new_hook->fix_page_protection( ))
		return hook_status::ERROR_MEMORY_PROTECT;

#if defined(_M_X64) || defined(__x86_64__)
	new_hook->detour = ct.pRelay;
#endif
	// Back up the target function.

	if (new_hook->patch_above)
		new_hook->init_backup(static_cast<LPBYTE>(target) - sizeof(JMP_REL), sizeof(JMP_REL) + sizeof(JMP_REL_SHORT));
	else
		new_hook->init_backup(target, sizeof(JMP_REL));

	storage_.push_back(new_hook);
	return {hook_status::OK,std::move(new_hook)};
}

//moved
hook_status context::remove_hook(void* target, bool force)
{
	const auto entry_itr = _Find_hook_itr(storage_, target);
	if (entry_itr == storage_.end( ))
		return hook_status::ERROR_NOT_CREATED;

	auto& entry = *entry_itr;

	if (entry->enabled)
	{
		const auto status = entry->set_state(false);
		if (status != hook_status::OK)
		{
			if (!force || status != hook_status::ERROR_MEMORY_PROTECT)
				return status;
		}
		//normally set_state sets it
		//force it to prevent assert in destructor
		entry->enabled = false;
	}

	storage_.erase(entry_itr);
	return hook_status::OK;
}
#if 0
hook_status context::enable_hook(void* target)
{
	return _Set_hook_state(storage_, target, true);
}

hook_status context::disable_hook(void* target)
{
	return _Set_hook_state(storage_, target, false);
}
#endif
hook_result context::find_hook(void* target) const
{
	auto entry = _Find_hook(storage_, target);
	if (!entry)
		return hook_status::ERROR_NOT_CREATED;

	return {hook_status::OK,std::move(entry)};
}
#if 0
auto minhook::create_hook_win_api(LPCWSTR pszModule, LPCSTR pszProcName, void* pDetour) -> hook_result
{
	const auto hModule = GetModuleHandleW(pszModule);
	if (hModule == nullptr)
		return hook_status::ERROR_MODULE_NOT_FOUND;

	const auto target = static_cast<void*>(GetProcAddress(hModule, pszProcName));
	if (target == nullptr)
		return hook_status::ERROR_FUNCTION_NOT_FOUND;

	return create_hook(target, pDetour);
}
#endif
void context::remove_all_hooks( )
{
	_Set_hook_state_all(storage_, false, true);
	storage_.clear( );
}

hook_status context::enable_all_hooks( )
{
	return _Set_hook_state_all(storage_, true);
}

hook_status context::disable_all_hooks( )
{
	return _Set_hook_state_all(storage_, false);
}

context_safe::context_safe(std::unique_ptr<basic_context>&& ctx)
	:ctx_(std::move(ctx))
{

}

#define LOCK_AND_WORK(_FN_,...) \
	const auto lock = std::scoped_lock(mtx_);\
	return ctx_->_FN_(__VA_ARGS__)

hook_result context_safe::create_hook(void* target, void* detour)
{
	LOCK_AND_WORK(create_hook, target, detour);
}

hook_status context_safe::remove_hook(void* target, bool force)
{
	LOCK_AND_WORK(remove_hook, target, force);
}

#if 0
hook_status context_safe::enable_hook(void* target)
{
	LOCK_AND_WORK(enable_hook, target);
}

hook_status context_safe::disable_hook(void* target)
{
	LOCK_AND_WORK(disable_hook, target);
}
#endif

hook_result context_safe::find_hook(void* target) const
{
	LOCK_AND_WORK(find_hook, target);
}

void context_safe::remove_all_hooks( )
{
	LOCK_AND_WORK(remove_all_hooks);
}

hook_status context_safe::enable_all_hooks( )
{
	LOCK_AND_WORK(enable_all_hooks);
}

hook_status context_safe::disable_all_hooks( )
{
	LOCK_AND_WORK(disable_all_hooks);
}

//--

void current_context::set(element_type&& ctx)
{
	auto& ref = current_context_base::get( );
	runtime_assert(ref == nullptr);
	ref = std::move(ctx);
}

void current_context::reset( )
{
	auto& ref = current_context_base::get( );
	runtime_assert(ref != nullptr);
	ref.reset( );
}

basic_context& current_context::get( )
{
	return *current_context_base::get( );
}

auto current_context::share( )->const element_type&
{
	return current_context_base::get( );
}
#endif