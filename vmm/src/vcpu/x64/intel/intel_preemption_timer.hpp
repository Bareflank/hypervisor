#ifndef VMM_VCPU_X64_INTEL_PREEMPTION_TIMER_HPP
#define VMM_VCPU_X64_INTEL_PREEMPTION_TIMER_HPP

#include <vmm/vcpu/x64/preemption_timer.hpp>

namespace vmm
{

class intel_preemption_timer :
    public preemption_timer
{
public:

    void preemption_timer_vmexit_enable() noexcept
    {
        // TODO: Implement Me!
        return;
    }

    void preemption_timer_vmexit_disable() noexcept
    {
        // TODO: Implement Me!
        return;
    }

    void preemption_timer_vmexit_handler_set(x64_vcpu_delegate func)
    {
        // TODO: Implement Me!
        return;
    }

    void preemption_timer_set(uint64_t value) noexcept
    {
        // TODO: Implement Me!
        return;
    }

    intel_preemption_timer() noexcept = default;
};

}

#endif
