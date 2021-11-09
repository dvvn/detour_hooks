#include "context.h"
#include "entry.h"

#include <nstd/runtime_assert_fwd.h>
#include <nstd/mem/block.h>
#include <nstd/address.h>

#include <Windows.h>

#include <vector>
#include <stdexcept>
#include <mutex>
#include <ranges>

using namespace dhooks;
using namespace dhooks::detail;

#if 0

//i found it uselles

static DWORD_PTR FindOldIP(HOOK_ENTRY& pHook, DWORD_PTR ip)
{
	if (pHook.patchAbove && ip == ((DWORD_PTR)pHook.target - sizeof(JMP_REL)))
		return (DWORD_PTR)pHook.target;

	for (UINT i = 0; i < pHook.nIP; ++i)
	{
		if (ip == ((DWORD_PTR)pHook.pTrampoline.get() + pHook.newIPs[i]))
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
			return (DWORD_PTR)pHook.pTrampoline.get() + pHook.newIPs[i];
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

	for (auto pHook : storage::get().filter_enabled(std::span{ pos, storage::get().end() }, enable))
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
status_ex::status_ex(status s) : status_ex_impl{ s }
{
	if (s == status::OK)
		return;

	const auto start = string_view("Error detected: status ");
	const auto end = status_to_string(s);

	std::string str;
	str.reserve(start.size() + end.size());

	str += start;
	str += end;

	throw std::runtime_error(std::move(str));
}
#endif

struct context::storage_type : std::vector<element_type>
{
};

static auto _Find_hook_itr(context::storage_type& storage, void* target)
{
    runtime_assert(target != nullptr);
    return std::ranges::find(storage, target, &context::element_type::target);
}

static hook_entry* _Find_hook(context::storage_type& storage, void* target)
{
    auto itr = _Find_hook_itr(storage, target);
    return itr == storage.end( ) ? nullptr : std::addressof(*itr);
}

static hook_status _Set_hook_state(context::storage_type& storage, void* target, bool enable)
{
    const auto entry = _Find_hook(storage, target);
    if (!entry)
        return hook_status::ERROR_NOT_CREATED;

    if (entry->enabled( ) == enable)
        return enable ? hook_status::ERROR_ENABLED : hook_status::ERROR_DISABLED;

    return entry->set_state(enable);
}

static hook_status _Set_hook_state_all(context::storage_type& storage, bool enable, bool ignore_errors = false)
{
    //auto frozen = frozen_threads_storage(false);

    auto storage_active = storage | std::views::filter([](const hook_entry& h)
    {
        return h.target( ) != nullptr;
    });
    const auto begin = storage_active.begin( );
    const auto end   = storage_active.end( );

    for (auto itr_main = begin; itr_main != end; ++itr_main)
    {
        auto& value = *itr_main;
        if (value.enabled( ) == enable)
            continue;

#if 0
		if (pause_threads)
		{
			//fill only if any hook enabled
			frozen.fill();
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
            if (value_child.enabled( ) == enable)
                continue;
            if (const auto temp_status = value_child.set_state(enable); temp_status != hook_status::OK)
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

context::context( )
{
    storage_ = std::make_unique<storage_type>( );
}

context::~context( ) = default;

hook_result context::create_hook(void* target, void* detour)
{
    if (!nstd::mem::block(target).executable( ) || !nstd::mem::block(detour).executable( ))
        return hook_status::ERROR_NOT_EXECUTABLE;

#if 0
	if (storage_->find(target) != nullptr)
		return hook_status::ERROR_ALREADY_CREATED;
	if (storage_->find(pDetour) != nullptr)
		return hook_status::ERROR_ALREADY_CREATED;
#endif

    if (target == detour)
        return hook_status::ERROR_UNSUPPORTED_FUNCTION;

    const auto check_ptr_helper = [&](void* checked)
    {
        return checked == target || checked == detour;
    };
    for (const auto& value: *storage_)
    {
        if (check_ptr_helper(value.target( )) || check_ptr_helper(value.detour( )))
            return hook_status::ERROR_ALREADY_CREATED;
    }

    auto ct = trampoline2( );

    if (!ct.create(target, detour))
        return hook_status::ERROR_UNSUPPORTED_FUNCTION;
    if (!ct.fix_page_protection( ))
        return hook_status::ERROR_MEMORY_PROTECT;

    auto& new_hook = storage_->emplace_back( );

    static_cast<trampoline2&>(new_hook) = std::move(ct);

#if defined(_M_X64) || defined(__x86_64__)
	new_hook.detour = ct.pRelay;
#endif
    // Back up the target function.

    if (new_hook.patch_above( ))
        new_hook.init_backup((static_cast<LPBYTE>(target) - sizeof(JMP_REL)), sizeof(JMP_REL) + sizeof(JMP_REL_SHORT));
    else
        new_hook.init_backup(target, sizeof(JMP_REL));

    hook_result ret(hook_status::OK);
    ret.entry = std::addressof(new_hook);

    return ret;
}

hook_status context::remove_hook(void* target, bool force)
{
    const auto entry = _Find_hook(*storage_, target);
    if (!entry)
        return hook_status::ERROR_NOT_CREATED;

    if (entry->enabled( ))
    {
        if (const auto status = entry->set_state(false); status != hook_status::OK)
        {
            if (!force || status != hook_status::ERROR_MEMORY_PROTECT)
                return status;
        }
        entry->mark_disabled( );
    }

    storage_->erase(_Find_hook_itr(*storage_, target));
    return hook_status::OK;
}

hook_status context::enable_hook(void* target)
{
    return _Set_hook_state(*storage_, target, true);
}

hook_status context::disable_hook(void* target)
{
    return _Set_hook_state(*storage_, target, false);
}

hook_result context::find_hook(void* target) const
{
    const auto entry = _Find_hook(*storage_, target);
    if (!entry)
        return hook_status::ERROR_NOT_CREATED;

    hook_result result(hook_status::OK);
    result.entry = /*boost::addressof(entry->second)*/entry;
    return result;
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
    _Set_hook_state_all(*storage_, false, true);
    storage_->clear( );
}

hook_status context::enable_all_hooks( )
{
    return _Set_hook_state_all(*storage_, true);
}

hook_status context::disable_all_hooks( )
{
    return _Set_hook_state_all(*storage_, false);
}

struct context_safe::lock_type : std::mutex
{
};

template <typename ...Args>
static auto _Lock_and_work(context_safe::lock_type& mtx, Args&&...args)
{
    const auto lock = std::scoped_lock(mtx);
    return std::invoke(std::forward<Args>(args)...);
}

#define LOCK_AND_WORK(fn,...)\
	_Lock_and_work(*mtx_, &basic_context::##fn, ctx_,## __VA_ARGS__)

context_safe::context_safe( )
{
    mtx_ = std::make_unique<lock_type>( );
}

hook_result context_safe::create_hook(void* target, void* detour)
{
    return LOCK_AND_WORK(create_hook, target, detour);
}

hook_status context_safe::remove_hook(void* target, bool force)
{
    return LOCK_AND_WORK(remove_hook, target, force);
}

hook_status context_safe::enable_hook(void* target)
{
    return LOCK_AND_WORK(enable_hook, target);
}

hook_status context_safe::disable_hook(void* target)
{
    return LOCK_AND_WORK(disable_hook, target);
}

hook_result context_safe::find_hook(void* target) const
{
    return LOCK_AND_WORK(find_hook, target);
}

void context_safe::remove_all_hooks( )
{
    LOCK_AND_WORK(remove_all_hooks);
}

hook_status context_safe::enable_all_hooks( )
{
    return LOCK_AND_WORK(enable_all_hooks);
}

hook_status context_safe::disable_all_hooks( )
{
    return LOCK_AND_WORK(disable_all_hooks);
}

//--

void current_context::set(std::shared_ptr<basic_context>&& ctx)
{
    auto& ref = get_ref( );
    runtime_assert(ref == nullptr);
    ref = std::move(ctx);
}

void current_context::reset( )
{
    auto& ref = get_ref( );
    runtime_assert(ref != nullptr);
    ref.reset( );
}

const std::shared_ptr<basic_context>& current_context::get( )
{
    return get_ref( );
}

std::shared_ptr<basic_context>& current_context::get_ref( )
{
    static std::shared_ptr<basic_context> ctx;
    return ctx;
}
