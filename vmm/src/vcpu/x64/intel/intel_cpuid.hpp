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
        return;
    }

    void cpuid_execute() noexcept
    {
        return;
    }

    void cpuid_emulate(uint64_t cpuid_value) noexcept
    {
        return;
    }

    intel_cpuid() noexcept = default;
};

}

#endif
