#ifndef VMM_VCPU_X64_INTEL_CPUID_HPP
#define VMM_VCPU_X64_INTEL_CPUID_HPP

#include <vmm/vcpu/x64/cpuid.hpp>

namespace vmm
{

class intel_cpuid :
    public cpuid
{
public:

    void cpuid_vmexit_handler_set(x64_vcpu_delegate func)
    {
        // TODO: Implement Me!
        return;
    }

    uint32_t cpuid_vmexit_leaf_get() noexcept
    {
        // TODO: Implement Me!
        return 0;
    }

    uint32_t cpuid_vmexit_subleaf_get() noexcept
    {
        // TODO: Implement Me!
        return 0;
    }

    void cpuid_execute() noexcept
    {
        // TODO: Implement Me!
        return;
    }

    void cpuid_emulate(uint32_t eax, uint32_t ebx, uint32_t ecx, uint32_t edx) noexcept
    {
        // TODO: Implement Me!
        return;
    }

    intel_cpuid() noexcept = default;
};

}

#endif
