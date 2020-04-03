#ifndef VMM_VCPU_X64_INTEL_NMI_WINDOW_HPP
#define VMM_VCPU_X64_INTEL_NMI_WINDOW_HPP

#include <vmm/vcpu/x64/nmi_window.hpp>

namespace vmm
{

class intel_nmi_window :
    public nmi_window
{
public:

    void nmi_window_vmexit_enable() noexcept
    {
        return;
    }

    void nmi_window_vmexit_disable() noexcept
    {
        return;
    }

    void nmi_window_vmexit_handler_set(bsl::delegate<void (x64_vcpu &)> func)
    {
        return;
    }

    intel_nmi_window() noexcept = default;
};

}

#endif
