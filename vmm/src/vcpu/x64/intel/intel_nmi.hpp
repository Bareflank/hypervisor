#ifndef VMM_VCPU_X64_INTEL_NMI_HPP
#define VMM_VCPU_X64_INTEL_NMI_HPP

#include <vmm/vcpu/x64/nmi.hpp>

namespace vmm
{

class intel_nmi :
    public nmi
{
public:

    void enable_nmi_vmexit() noexcept
    {
        return;
    }

    void disable_nmi_vmexit() noexcept
    {
        return;
    }

    void set_nmi_vmexit_handler(x64_vcpu_delegate func)
    {
        return;
    }

    void inject_nmi() noexcept
    {
        return;
    }

    intel_nmi() noexcept = default;
};

}

#endif
