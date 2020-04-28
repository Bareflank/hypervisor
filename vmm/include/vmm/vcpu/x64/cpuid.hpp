#ifndef VMM_VCPU_X64_CPUID_HPP
#define VMM_VCPU_X64_CPUID_HPP

#include <vmm/vcpu/x64/x64_vcpu_delegate.hpp>

namespace vmm
{

class x64_vcpu;

class cpuid
{
public:

    /// @brief Set a vmexit handler that will be called for all vmexits caused
    ///     by execution of a cpuid instruction while a vcpu is executing.
    ///
    /// @param func The delegate function to be called
    virtual void set_cpuid_vmexit_handler(x64_vcpu_delegate func) noexcept = 0;

    /// @brief Returns the cpuid leaf (value in register eax) that caused
    ///     a vmexit to occur when a vcpu executed a cpuid instruction
    ///
    /// @return The cpuid leaf that caused a vmexit to occur
    virtual uint32_t get_cpuid_vmexit_leaf() noexcept = 0;

    /// @brief Returns the cpuid subleaf (value in register ecx) that caused
    ///     a vmexit to occur when a vcpu executed a cpuid instruction
    ///
    /// @return The cpuid subleaf that caused a vmexit to occur
    virtual uint32_t get_cpuid_vmexit_subleaf() noexcept = 0;

    /// @brief Execute (on the physical cpu) a cpuid instruction that caused a
    ///     vmexit to occur, using the vcpu's registers as the source and
    ///     destination registers for the operation. This allows a user defined
    ///     vm exit handler to pass through a cpuid instruction from a vcpu to a
    ///     physical cpu.
    virtual void execute_cpuid() noexcept = 0;

    /// @brief Emulate a cpuid instruction that caused a vmexit to occur while a
    ///     vcpu was executing. The emulated value is written into the vcpu's
    ///     registers withough reading from or writing to the physical cpu. 
    ///
    /// @param eax The emulated output value to place in register eax
    /// @param ebx The emulated output value to place in register ebx
    /// @param ecx The emulated output value to place in register ecx
    /// @param edx The emulated output value to place in register edx
    virtual void emulate_cpuid(uint32_t eax, uint32_t ebx, uint32_t ecx, uint32_t edx) noexcept = 0;

    virtual ~cpuid() noexcept = default;
protected:
    cpuid() noexcept = default;
    cpuid(cpuid &&) noexcept = default;
    cpuid &operator=(cpuid &&) noexcept = default;
    cpuid(cpuid const &) = delete;
    cpuid &operator=(cpuid const &) & = delete;
};

}

#endif
