#ifndef VMM_VCPU_X64_CR4_HPP
#define VMM_VCPU_X64_CR4_HPP

#include <vmm/vcpu/x64/x64_vcpu_delegate.hpp>

namespace vmm
{

class cr4
{
public:

    /// @brief Enable vmexits for all writes to control register cr4
    virtual void write_cr4_vmexit_enable() noexcept = 0;

    /// @brief Disable vmexits for all writes to control register cr4
    virtual void write_cr4_vmexit_disable() noexcept = 0;

    /// @brief Set a vmexit handler that will be called for all vmexits caused
    ///     by a write to control register cr4 while a vcpu is executing.
    ///
    /// @param func The delegate function to be called
    virtual void write_cr4_vmexit_handler_set(x64_vcpu_delegate func) noexcept = 0;

    /// @brief Returns the value being written to control register cr4 that
    ///     caused a vmexit to occur while a vcpu was executing
    ///
    /// @return The value written to cr4
    virtual uint64_t write_cr4_vmexit_value_get() noexcept = 0;

    /// @brief Execute (on the vcpu) a write to cr4 that caused a vmexit
    ///     to occur, using the vcpu's registers as the source and destination
    ///     registers for the operation. This allows a user defined vm exit
    ///     handler to pass through a write to a vcpu's cr4.
    virtual void write_cr4_execute() noexcept = 0;

    /// @brief Emulate a write to cr4 that caused a vmexit to occur while a
    ///     vcpu was executing. The given value is written into the vcpu's
    ///     cr4, instead of the value that caused the vm exit to occur. 
    ///
    /// @param cr4_value The value to be written to a vcpu's cr4
    virtual void write_cr4_emulate(uint64_t cr4_value) noexcept = 0;

    virtual ~cr4() noexcept = default;
protected:
    cr4() noexcept = default;
    cr4(cr4 &&) noexcept = default;
    cr4 &operator=(cr4 &&) noexcept = default;
    cr4(cr4 const &) = delete;
    cr4 &operator=(cr4 const &) & = delete;
};

}

#endif
