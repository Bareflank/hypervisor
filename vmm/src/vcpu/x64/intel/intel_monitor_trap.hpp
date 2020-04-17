#ifndef VMM_VCPU_X64_INTEL_MONITOR_TRAP_HPP
#define VMM_VCPU_X64_INTEL_MONITOR_TRAP_HPP

#include <vmm/vcpu/x64/monitor_trap.hpp>

namespace vmm
{

class intel_monitor_trap :
    public monitor_trap
{
public:

    void monitor_trap_vmexit_enable() noexcept
    {
        return;
    }

    void monitor_trap_vmexit_disable() noexcept
    {
        return;
    }

    void monitor_trap_vmexit_handler_set(x64_vcpu_delegate func)
    {
        return;
    }

    intel_monitor_trap() noexcept = default;
};

}

#endif
