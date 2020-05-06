#ifndef VMM_VCPU_EXECUTE_HPP
#define VMM_VCPU_EXECUTE_HPP

#include <bsl/errc_type.hpp>

namespace vmm
{

class execute
{
public:

    /// @brief Load a vcpu for execution on the physical cpu that executes
    ///     this function. This function does not yield execution to the vcpu,
    ///     but prepares the vcpu so that it may be executed using run()
    ///
    /// @return Returns 0 if the operation was successful, else an error code
    virtual bsl::errc_type load() noexcept = 0;

    /// @brief Unloads a vcpu from the physical cpu that executes this function.
    ///
    /// @return Returns 0 if the operation was successful, else an error code
    virtual bsl::errc_type unload() noexcept = 0;
    
    /// @brief Yield the execution of the physical cpu that executes this
    ///     function to a vcpu.
    ///
    /// @return This function will not return on success. On failure, an error
    ///     code is returned
    virtual bsl::errc_type run() noexcept = 0;

    virtual ~execute() noexcept = default;
protected:
    execute() noexcept = default;
    execute(execute &&) noexcept = default;
    execute &operator=(execute &&) noexcept = default;
    execute(execute const &) = delete;
    execute &operator=(execute const &) & = delete;
};

}

#endif
