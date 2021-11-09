#pragma once

namespace dhooks
{
    class __declspec(novtable) hook_holder_base
    {
    protected:
        virtual ~hook_holder_base( ) = default;

    public:
        virtual bool hook( ) = 0;
        virtual bool unhook( ) = 0;
        virtual void unhook_after_call( ) = 0;

        virtual bool enable( ) = 0;
        virtual bool disable( ) = 0;
        virtual void disable_after_call( ) = 0;

        virtual bool hooked( ) const = 0;
        virtual bool enabled( ) const = 0;
    };

    struct __declspec(novtable) original_func_setter
    {
        virtual ~original_func_setter( ) = default;
        virtual void set_original_func(void* fn) =0;
    };

    template <typename Ret, /*typename Arg1,*/ typename ...Args>
    struct __declspec(novtable) hook_callback
    {
        virtual ~hook_callback( ) = default;
        virtual void callback(Args ...) = 0;
    };
}
