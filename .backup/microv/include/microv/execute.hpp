#ifndef MICROV_EXECUTE_HPP
#define MICROV_EXECUTE_HPP

#include <microv/vmexit_context.hpp>
#include <bsl/errc_type.hpp>

namespace microv
{

/// @brief Load a vcpu for execution on the physical cpu that executes
///     this function. This function does not yield execution to the vcpu,
///     but prepares the vcpu so that it may be executed using run()
///
/// @return Returns 0 if the operation was successful, else an error code
bsl::errc_type load(vmexit_context &vc) noexcept;

/// @brief Unloads a vcpu from the physical cpu that executes this function.
///
/// @return Returns 0 if the operation was successful, else an error code
bsl::errc_type unload(vmexit_context &vc) noexcept;

/// @brief Yield the execution of the physical cpu that executes this
///     function to a vcpu.
///
/// @return This function will not return on success. On failure, an error
///     code is returned
bsl::errc_type run(vmexit_context &vc) noexcept;
}

#endif
