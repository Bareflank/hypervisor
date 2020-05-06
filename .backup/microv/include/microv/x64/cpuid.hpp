#ifndef MICROV_X64_CPUID_HPP
#define MICROV_X64_CPUID_HPP

#include <microv/vmexit_context.hpp>
#include <microv/vmexit_delegate.hpp>
#include <bsl/cstdint.hpp>

namespace microv
{

/// @brief Set a vmexit handler that will be called for all vmexits caused
///     by execution of a cpuid instruction while a vcpu is executing.
///
/// @param func The delegate function to be called
void set_cpuid_vmexit_handler(vmexit_context &vc, vmexit_delegate func) noexcept;

/// @brief Returns the cpuid leaf (value in register eax) that caused
///     a vmexit to occur when a vcpu executed a cpuid instruction
///
/// @return The cpuid leaf that caused a vmexit to occur
uint32_t get_cpuid_vmexit_leaf(vmexit_context &vc) noexcept;

/// @brief Returns the cpuid subleaf (value in register ecx) that caused
///     a vmexit to occur when a vcpu executed a cpuid instruction
///
/// @return The cpuid subleaf that caused a vmexit to occur
uint32_t get_cpuid_vmexit_subleaf(vmexit_context &vc) noexcept;

/// @brief Provide the result of a cpuid instruction to the given
///     vmexit_context. The given values are written into the context's general
///     registers eax, ebx, ecx, and edx.
///
/// @param eax The emulated output value to place in register eax
/// @param ebx The emulated output value to place in register ebx
/// @param ecx The emulated output value to place in register ecx
/// @param edx The emulated output value to place in register edx
void provide_cpuid_result(vmexit_context &vc, uint32_t eax, uint32_t ebx, uint32_t ecx, uint32_t edx) noexcept;

}

#endif

