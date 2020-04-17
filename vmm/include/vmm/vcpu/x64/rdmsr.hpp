#ifndef VMM_VCPU_X64_RDMSR_HPP
#define VMM_VCPU_X64_RDMSR_HPP

#include <vmm/vcpu/x64/x64_vcpu_delegate.hpp>

namespace vmm
{

class rdmsr
{
public:

    /// @brief Enable vmexits for a model specific register accesses via the
    ///     rdmsr instruction at the specified msr address during vcpu execution. 
    ///
    /// @param msr_address The msr address to enable rdmsr vmexits for
    virtual void rdmsr_vmexit_enable(uint32_t msr_address) noexcept = 0;

    /// @brief Enable vmexits for a range of model specific register accesses
    ///     via the rdmsr instruction with msr addresses in the range
    ///     @param begin to @param end (inclusive) during vcpu execution. 
    ///
    /// @expects begin <= end
    ///
    /// @param begin The lower bound of msr addresses to enable vmexits for
    /// @param end The upper bound of msr addresses to enable rdmsr vmexits for
    virtual void rdmsr_vmexit_range_enable(uint32_t begin, uint32_t end) noexcept = 0;

    /// @brief Disable vmexits for a model specific register accesses via the
    ///     rdmsr instruction at the specified msr address during vcpu execution. 
    ///
    /// @param msr_address The msr address to disable rdmsr vmexits for
    virtual void rdmsr_vmexit_disable(uint32_t msr_address) noexcept = 0;

    /// @brief Disable vmexits for a range of model specific register accesses
    ///     via the rdmsr instruction with msr addresses in the range
    ///     @param begin to @param end (inclusive) during vcpu execution. 
    ///
    /// @expects begin <= end
    ///
    /// @param begin The lower bound of msr addresses to disable vmexits for
    /// @param end The upper bound of msr addresses to disable rdmsr vmexits for
    virtual void rdmsr_vmexit_range_disable(uint32_t begin, uint32_t end) noexcept = 0;

    /// @brief Set a vmexit handler that will be called for all vmexits caused
    ///     by a rdmsr instruction while a vcpu is executing.
    ///
    /// @param func The delegate function to be called
    virtual void rdmsr_vmexit_handler_set(x64_vcpu_delegate func) noexcept = 0;

    /// @brief Returns the msr address of a rdmsr instruction that caused a
    ///     vmexit to occur while a vcpu was executing
    ///
    /// @return The msr address used in a rdmsr instruction that caused a
    ///     vmexit to occur
    virtual uint32_t rdmsr_vmexit_address_get() noexcept = 0;

    /// @brief Execute (on the vcpu) a rdmsr instruction that caused a vmexit
    ///     to occur, using the vcpu's registers as the destination registers
    ///     for the operation. This allows a user defined vm exit handler to
    ///     pass through a rdmsr instruction from a vcpu.
    virtual void rdmsr_execute() noexcept = 0;

    /// @brief Emulate a rdmsr instruction that caused a vmexit to occur
    ///     while a vcpu was executing. The given value is read into the
    ///     vcpu's destination registers, instead of the value at the physical
    ///     machine's msr.
    ///
    /// @param value The value to be emulated as a the result of a rdmsr
    ///     instruction
    virtual void rdmsr_emulate(uint64_t value) noexcept = 0;

    virtual ~rdmsr() noexcept = default;
protected:
    rdmsr() noexcept = default;
    rdmsr(rdmsr &&) noexcept = default;
    rdmsr &operator=(rdmsr &&) noexcept = default;
    rdmsr(rdmsr const &) = delete;
    rdmsr &operator=(rdmsr const &) & = delete;
};

}

#endif
