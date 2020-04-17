#ifndef VMM_VCPU_X64_INTEL_RDMSR_HPP
#define VMM_VCPU_X64_INTEL_RDMSR_HPP

#include <vmm/vcpu/x64/rdmsr.hpp>

namespace vmm
{

class intel_rdmsr :
    public rdmsr
{
public:

    void rdmsr_vmexit_enable(uint32_t msr_address) noexcept
    {
        // TODO: Implement Me!
        return;
    }

    void rdmsr_vmexit_range_enable(uint32_t begin, uint32_t end) noexcept
    {
        // TODO: Implement Me!
        return;
    }

    void rdmsr_vmexit_disable(uint32_t msr_address) noexcept
    {
        // TODO: Implement Me!
        return;
    }

    void rdmsr_vmexit_range_disable(uint32_t begin, uint32_t end) noexcept
    {
        // TODO: Implement Me!
        return;
    }

    void rdmsr_vmexit_handler_set(x64_vcpu_delegate func) noexcept
    {
        // TODO: Implement Me!
        return;
    }

    uint32_t rdmsr_vmexit_address_get() noexcept
    {
        // TODO: Implement Me!
        return 0;
    }

    void rdmsr_execute() noexcept
    {
        // TODO: Implement Me!
        return;
    }

    void rdmsr_emulate(uint64_t value) noexcept
    {
        // TODO: Implement Me!
        return;
    }

    intel_rdmsr() noexcept = default;
};

}

#endif
