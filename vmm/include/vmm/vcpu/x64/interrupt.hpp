#ifndef VMM_VCPU_X64_EXTERNAL_INTERRUPT_HPP
#define VMM_VCPU_X64_EXTERNAL_INTERRUPT_HPP

#include <vmm/vcpu/x64/x64_vcpu_delegate.hpp>

namespace vmm
{

class interrupt
{
public:

    /// @brief Enable vmexits for all external interrupts that arrive during
    ///     execution of a vcpu
    virtual void interrupt_vmexit_enable() noexcept = 0;

    /// @brief Disable vmexits for all external interrupts that arrive during
    ///     execution of a vcpu
    virtual void interrupt_vmexit_disable() noexcept = 0;

    /// @brief Set a vmexit handler that will be called for all vmexits caused
    ///     by arrival of an external interrupt while a vcpu is executing.
    ///
    /// @param func The delegate function to be called
    virtual void interrupt_vmexit_handler_set(x64_vcpu_delegate func) noexcept = 0;

    /// @brief Inject an external interrupt into a vcpu
    ///
    /// @param vector The vector of the external interrupt to be injected
    virtual void interrupt_inject(uint64_t vector) noexcept = 0;

    virtual ~interrupt() noexcept = default;
protected:
    interrupt() noexcept = default;
    interrupt(interrupt &&) noexcept = default;
    interrupt &operator=(interrupt &&) noexcept = default;
    interrupt(interrupt const &) = delete;
    interrupt &operator=(interrupt const &) & = delete;
};

}

#endif
