#ifndef VMM_VCPU_X64_INTEL_INIT_SIGNAL_HPP
#define VMM_VCPU_X64_INTEL_INIT_SIGNAL_HPP

#include <vmm/vcpu/x64/init_signal.hpp>

namespace vmm
{

class intel_init_signal :
    public init_signal
{
public:

    void init_signal_vmexit_handler_set(x64_vcpu_delegate func)
    {
        // TODO: Implement Me!
        return;
    }

    intel_init_signal() noexcept = default;
};

}

#endif
