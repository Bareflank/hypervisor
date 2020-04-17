#ifndef VMM_VCPU_X64_INTEL_WRMSR_HPP
#define VMM_VCPU_X64_INTEL_WRMSR_HPP

#include <vmm/vcpu/x64/wrmsr.hpp>

namespace vmm
{

class intel_wrmsr :
    public wrmsr
{
public:

    void wrmsr_vmexit_enable(uint32_t msr_address) noexcept
    {
        // TODO: Implement Me!
        return;
    }

    void wrmsr_vmexit_range_enable(uint32_t begin, uint32_t end) noexcept
    {
        // TODO: Implement Me!
        return;
    }

    void wrmsr_vmexit_disable(uint32_t msr_address) noexcept
    {
        // TODO: Implement Me!
        return;
    }

    void wrmsr_vmexit_range_disable(uint32_t begin, uint32_t end) noexcept
    {
        // TODO: Implement Me!
        return;
    }

    void wrmsr_vmexit_handler_set(x64_vcpu_delegate func) noexcept
    {
        // TODO: Implement Me!
        return;
    }

    uint32_t wrmsr_vmexit_address_get() noexcept
    {
        // TODO: Implement Me!
        return 0;
    }

    uint64_t wrmsr_vmexit_value_get() noexcept
    {
        // TODO: Implement Me!
        return 0;
    }

    void wrmsr_execute() noexcept
    {
        // TODO: Implement Me!
        return;
    }

    void wrmsr_emulate(uint64_t value) noexcept
    {
        // TODO: Implement Me!
        return;
    }

    intel_wrmsr() noexcept = default;
};

}

#endif
