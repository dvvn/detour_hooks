module;

#include <memory>

export module dhooks.entry;

struct basic_hook_entry
{
    virtual ~basic_hook_entry();

    virtual bool create() = 0;
    virtual bool created() const = 0;
    virtual bool enabled() const = 0;

    virtual bool enable() = 0;
    virtual bool disable() = 0;

    virtual void* get_original_method() const = 0;
    virtual void* get_target_method() const = 0;
    virtual void* get_replace_method() const = 0;

    virtual void set_target_method(void* getter) = 0;
    virtual void set_replace_method(void* getter) = 0;
};

using hook_entry_ptr = std::unique_ptr<basic_hook_entry>;
hook_entry_ptr create_hook_entry();

export namespace dhooks
{
    using ::basic_hook_entry;
    using hook_entry = ::hook_entry_ptr;

    using ::create_hook_entry;
} // namespace dhooks
