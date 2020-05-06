#ifndef VMM_VCPU_X64_INTEL_INTERRUPT_WINDOW_HPP
#define VMM_VCPU_X64_INTEL_INTERRUPT_WINDOW_HPP

#include <vmm/vcpu/x64/interrupt_window.hpp>

namespace vmm
{

class intel_interrupt_window :
    public interrupt_window
{
public:

    void enable_interrupt_window_vmexit() noexcept
    {
        return;
    }

    void disable_interrupt_window_vmexit() noexcept
    {
        return;
    }

    void set_interrupt_window_vmexit_handler(x64_vcpu_delegate func)
    {
        return;
    }

    intel_interrupt_window() noexcept = default;
};

}

#endif
