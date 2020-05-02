#ifndef MICROV_INIT_HANDLER_HPP
#define MICROV_INIT_HANDLER_HPP

#include <bsl/exit_code.hpp>
#include <microv/vmexit_context.hpp>
#include <microv/vmexit_delegate.hpp>

namespace microv
{

/// @brief Set a vmexit handler that will be called for all vmexits caused
///     by execution of a cpuid instruction while a vcpu is executing.
///
/// @param func The delegate function to be called
void set_init_handler(vmexit_context &vc, vmexit_delegate func) noexcept;

}

#endif
