#ifndef VMM_VCPU_X64_INTEL_RDMSR_HPP
#define VMM_VCPU_X64_INTEL_RDMSR_HPP

#include <vmm/vcpu/x64/rdmsr.hpp>

namespace vmm
{

class intel_rdmsr :
    public rdmsr
{
public:

    void enable_rdmsr_vmexit(uint32_t msr_address) noexcept
    {
        // TODO: Implement Me!
        return;
    }

    void enable_rdmsr_vmexit_range(uint32_t begin, uint32_t end) noexcept
    {
        // TODO: Implement Me!
        return;
    }

    void disable_rdmsr_vmexit(uint32_t msr_address) noexcept
    {
        // TODO: Implement Me!
        return;
    }

    void disable_rdmsr_vmexit_range(uint32_t begin, uint32_t end) noexcept
    {
        // TODO: Implement Me!
        return;
    }

    void set_rdmsr_vmexit_handler(x64_vcpu_delegate func) noexcept
    {
        // TODO: Implement Me!
        return;
    }

    uint32_t get_rdmsr_vmexit_address() noexcept
    {
        // TODO: Implement Me!
        return 0;
    }

    void execute_rdmsr() noexcept
    {
        // TODO: Implement Me!
        return;
    }

    void emulate_rdmsr(uint64_t value) noexcept
    {
        // TODO: Implement Me!
        return;
    }

    intel_rdmsr() noexcept = default;
};

}

#endif
