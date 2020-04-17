#ifndef VMM_VCPU_X64_CR0_HPP
#define VMM_VCPU_X64_CR0_HPP

#include <vmm/vcpu/x64/x64_vcpu_delegate.hpp>

namespace vmm
{

class x64_vcpu;

class cr0
{
public:

    /// @brief Enable vmexits for all writes to control register cr0
    virtual void write_cr0_vmexit_enable() noexcept = 0;

    /// @brief Disable vmexits for all writes to control register cr0
    virtual void write_cr0_vmexit_disable() noexcept = 0;

    /// @brief Set a vmexit handler that will be called for all vmexits caused
    ///     by a write to control register cr0 while a vcpu is executing.
    ///
    /// @param func The delegate function to be called
    virtual void write_cr0_vmexit_handler_set(x64_vcpu_delegate func) noexcept = 0;

    /// @brief Returns the value being written to control register cr0 that
    ///     caused a vmexit to occur while a vcpu was executing
    ///
    /// @return The value written to cr0
    virtual uint64_t write_cr0_vmexit_value_get() noexcept = 0;

    /// @brief Execute (on the vcpu) a write to cr0 that caused a vmexit
    ///     to occur, using the vcpu's registers as the source and destination
    ///     registers for the operation. This allows a user defined vm exit
    ///     handler to pass through a write to a vcpu's cr0.
    virtual void write_cr0_execute() noexcept = 0;

    /// @brief Emulate a write to cr0 that caused a vmexit to occur while a
    ///     vcpu was executing. The given value is written into the vcpu's
    ///     cr0, instead of the value that caused the vm exit to occur. 
    ///
    /// @param cr0_value The value to be written to a vcpu's cr0
    virtual void write_cr0_emulate(uint64_t cr0_value) noexcept = 0;

    virtual ~cr0() noexcept = default;
protected:
    cr0() noexcept = default;
    cr0(cr0 &&) noexcept = default;
    cr0 &operator=(cr0 &&) noexcept = default;
    cr0(cr0 const &) = delete;
    cr0 &operator=(cr0 const &) & = delete;
};

}

#endif
