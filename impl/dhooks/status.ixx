module;

#include <string_view>

export module dhooks:status;

export namespace dhooks
{
    enum class hook_status:uint8_t
    {
        /// @brief Unknown error. Should not be returned.
        UNKNOWN = 0
       ,

        /// @brief Successful.
        OK
       ,

        /// @brief The hook for the specified target function is already created.
        ERROR_ALREADY_CREATED
       ,

        /// @brief The hook for the specified target function is not created yet.
        ERROR_NOT_CREATED
       ,

        /// @brief The hook for the specified target function is already enabled.
        ERROR_ENABLED
       ,

        /// @brief The hook for the specified target function is not enabled yet, or already disabled.
        ERROR_DISABLED
       ,

        /// @brief The specified pointer is invalid. It points the address of non-allocated and/or non-executable region.
        ERROR_NOT_EXECUTABLE
       ,

        /// @brief The specified pointer is invalid. It points the address of non-allocated and/or non-readable region.
        ERROR_NOT_READABLE
       ,

        /// @brief The specified target function cannot be hooked.
        ERROR_UNSUPPORTED_FUNCTION
       ,

        /// @brief Failed to allocate mem.
        ERROR_MEMORY_ALLOC
       ,

        /// @brief Failed to change the mem protection.

        ERROR_MEMORY_PROTECT
       ,

        /// @brief The specified module is not loaded.
        ERROR_MODULE_NOT_FOUND
       ,

        /// @brief The specified class is not virtual.
        ERROR_VTABLE_NOT_FOUND
       ,

        /// @brief The specified function is not found.
        ERROR_FUNCTION_NOT_FOUND
      , COUNT
    };

    std::string_view hook_status_to_string(hook_status status);
}
