#ifndef VMM_VCPU_X64_INTEL_EXTERNAL_INTERRUPT_HPP
#define VMM_VCPU_X64_INTEL_EXTERNAL_INTERRUPT_HPP

#include <vmm/vcpu/x64/external_interrupt.hpp>

namespace vmm
{

class intel_external_interrupt :
    public external_interrupt
{
public:

    void external_interrupt_vmexit_enable() noexcept
    {
        return;
    }

    void external_interrupt_vmexit_disable() noexcept
    {
        return;
    }

    void external_interrupt_vmexit_handler_set(bsl::delegate<void (x64_vcpu &)> func)
    {
        return;
    }

    void external_interrupt_inject(uint64_t vector) noexcept
    {
        return;
    }

    intel_external_interrupt() noexcept = default;
};

}

#endif
