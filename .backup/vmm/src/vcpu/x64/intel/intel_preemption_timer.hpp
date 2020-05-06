#ifndef VMM_VCPU_X64_INTEL_PREEMPTION_TIMER_HPP
#define VMM_VCPU_X64_INTEL_PREEMPTION_TIMER_HPP

#include <vmm/vcpu/x64/preemption_timer.hpp>

namespace vmm
{

class intel_preemption_timer :
    public preemption_timer
{
public:

    void enable_preemption_timer_vmexit() noexcept
    {
        // TODO: Implement Me!
        return;
    }

    void disable_preemption_timer_vmexit() noexcept
    {
        // TODO: Implement Me!
        return;
    }

    void set_preemption_timer_vmexit_handler(x64_vcpu_delegate func)
    {
        // TODO: Implement Me!
        return;
    }

    void set_preemption_timer(uint64_t value) noexcept
    {
        // TODO: Implement Me!
        return;
    }

    intel_preemption_timer() noexcept = default;
};

}

#endif
