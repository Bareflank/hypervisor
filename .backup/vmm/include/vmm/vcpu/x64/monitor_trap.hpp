#ifndef VMM_VCPU_X64_MONITOR_TRAP_HPP
#define VMM_VCPU_X64_MONITOR_TRAP_HPP

#include <vmm/vcpu/x64/x64_vcpu_delegate.hpp>

namespace vmm
{

class monitor_trap
{
public:

    /// @brief Enable vmexits for all instructions that execute on a vcpu
    virtual void enable_monitor_trap_vmexit() noexcept = 0;

    /// @brief Disable vmexits for all instructions that execute on a vcpu
    virtual void disable_monitor_trap_vmexit() noexcept = 0;

    /// @brief Set a vmexit handler that will be called for all monitor trap
    ///     vmexits caused by exectuion of a vcpu
    ///
    /// @param func The delegate function to be called
    virtual void set_monitor_trap_vmexit_handler(x64_vcpu_delegate func) noexcept = 0;

    virtual ~monitor_trap() noexcept = default;
protected:
    monitor_trap() noexcept = default;
    monitor_trap(monitor_trap &&) noexcept = default;
    monitor_trap &operator=(monitor_trap &&) noexcept = default;
    monitor_trap(monitor_trap const &) = delete;
    monitor_trap &operator=(monitor_trap const &) & = delete;
};

}

#endif

