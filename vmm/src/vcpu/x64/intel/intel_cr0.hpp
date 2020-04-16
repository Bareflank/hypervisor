#ifndef VMM_VCPU_X64_INTEL_CR0_HPP
#define VMM_VCPU_X64_INTEL_CR0_HPP

#include <vmm/vcpu/x64/cr0.hpp>

namespace vmm
{

class intel_cr0 :
    public cr0
{
public:

    void write_cr0_vmexit_enable() noexcept
    {
        // TODO: Implement Me!
        return;
    }

    void write_cr0_vmexit_disable() noexcept
    {
        // TODO: Implement Me!
        return;
    }

    void write_cr0_vmexit_handler_set(bsl::delegate<void (x64_vcpu &)> func)
    {
        // TODO: Implement Me!
        return;
    }

    uint64_t write_cr0_vmexit_value_get() noexcept
    {
        // TODO: Implement Me!
        return 0;
    }

    void write_cr0_execute() noexcept
    {
        // TODO: Implement Me!
        return;
    }

    void write_cr0_emulate(uint64_t cr0_value) noexcept
    {
        // TODO: Implement Me!
        return;
    }

    intel_cr0() noexcept = default;
};

}

#endif
