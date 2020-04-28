#ifndef VMM_VCPU_X64_INTEL_CPUID_HPP
#define VMM_VCPU_X64_INTEL_CPUID_HPP

#include <vmm/vcpu/x64/cpuid.hpp>

namespace vmm
{

class intel_cpuid :
    public cpuid
{
public:

    void set_cpuid_vmexit_handler(x64_vcpu_delegate func)
    {
        // TODO: Implement Me!
        return;
    }

    uint32_t get_cpuid_vmexit_leaf() noexcept
    {
        // TODO: Implement Me!
        return 0;
    }

    uint32_t get_cpuid_vmexit_subleaf() noexcept
    {
        // TODO: Implement Me!
        return 0;
    }

    void execute_cpuid() noexcept
    {
        // TODO: Implement Me!
        return;
    }

    void emulate_cpuid(uint32_t eax, uint32_t ebx, uint32_t ecx, uint32_t edx) noexcept
    {
        // TODO: Implement Me!
        return;
    }

    intel_cpuid() noexcept = default;
};

}

#endif
