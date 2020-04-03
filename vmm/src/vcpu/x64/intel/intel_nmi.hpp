#ifndef VMM_VCPU_X64_INTEL_NMI_HPP
#define VMM_VCPU_X64_INTEL_NMI_HPP

#include <vmm/vcpu/x64/nmi.hpp>

namespace vmm
{

class intel_nmi :
    public nmi
{
public:

    void nmi_vmexit_enable() noexcept
    {
        return;
    }

    void nmi_vmexit_disable() noexcept
    {
        return;
    }

    void nmi_vmexit_handler_set(bsl::delegate<void (x64_vcpu &)> func)
    {
        return;
    }

    void nmi_inject() noexcept
    {
        return;
    }

    intel_nmi() noexcept = default;
};

}

#endif
