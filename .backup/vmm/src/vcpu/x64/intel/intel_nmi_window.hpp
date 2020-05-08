#ifndef VMM_VCPU_X64_INTEL_NMI_WINDOW_HPP
#define VMM_VCPU_X64_INTEL_NMI_WINDOW_HPP

#include <vmm/vcpu/x64/nmi_window.hpp>

namespace vmm
{

class intel_nmi_window :
    public nmi_window
{
public:

    void enable_nmi_window_vmexit() noexcept
    {
        return;
    }

    void disable_nmi_window_vmexit() noexcept
    {
        return;
    }

    void set_nmi_window_vmexit_handler(x64_vcpu_delegate func)
    {
        return;
    }

    intel_nmi_window() noexcept = default;
};

}

#endif
