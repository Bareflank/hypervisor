#ifndef VMM_VCPU_X64_CPUID_HPP
#define VMM_VCPU_X64_CPUID_HPP

#include <bsl/delegate.hpp>

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
    virtual void cpuid_vmexit_handler_set(bsl::delegate<void (x64_vcpu &)> func) noexcept = 0;

    /// @brief Execute (on the physical cpu) a cpuid instruction that caused a
    ///     vmexit to occur, using the vcpu's registers as the source and
    ///     destination registers for the operation. This allows a user defined
    ///     vm exit handler to pass through a cpuid instruction from a vcpu to a
    ///     physical cpu.
    virtual void cpuid_execute() noexcept = 0;

    /// @brief Emulate a cpuid instruction that caused a vmexit to occur while a
    ///     vcpu was executing. The emulated value is written into the vcpu's
    ///     registers withough reading from or writing to the physical cpu. 
    virtual void cpuid_emulate(uint64_t cpuid_value) noexcept = 0;

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
