#ifndef VMM_VCPU_X64_INTERRUPT_WINDOW_HPP
#define VMM_VCPU_X64_INTERRUPT_WINDOW_HPP

#include <vmm/vcpu/x64/x64_vcpu_delegate.hpp>

namespace vmm
{

class interrupt_window
{
public:

    /// @brief Enable vmexits for interrupt windows
    virtual void interrupt_window_vmexit_enable() noexcept = 0;

    /// @brief Disable vmexits for interrupt windows
    virtual void interrupt_window_vmexit_disable() noexcept = 0;

    /// @brief Set a vmexit handler that will be called for all vmexits caused
    ///     by an interrupt window vmexit while a vcpu is executing.
    ///
    /// @param func The delegate function to be called
    virtual void interrupt_window_vmexit_handler_set(x64_vcpu_delegate func) noexcept = 0;

    virtual ~interrupt_window() noexcept = default;
protected:
    interrupt_window() noexcept = default;
    interrupt_window(interrupt_window &&) noexcept = default;
    interrupt_window &operator=(interrupt_window &&) noexcept = default;
    interrupt_window(interrupt_window const &) = delete;
    interrupt_window &operator=(interrupt_window const &) & = delete;
};

}

#endif

