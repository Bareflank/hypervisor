#ifndef VMM_VCPU_X64_INTEL_EXTERNAL_INTERRUPT_HPP
#define VMM_VCPU_X64_INTEL_EXTERNAL_INTERRUPT_HPP

#include <vmm/vcpu/x64/interrupt.hpp>

namespace vmm
{

class intel_interrupt :
    public interrupt
{
public:

    void enable_interrupt_vmexit() noexcept
    {
        return;
    }

    void disable_interrupt_vmexit() noexcept
    {
        return;
    }

    void set_interrupt_vmexit_handler(x64_vcpu_delegate func)
    {
        return;
    }

    void inject_interrupt(uint64_t vector) noexcept
    {
        return;
    }

    intel_interrupt() noexcept = default;
};

}

#endif
