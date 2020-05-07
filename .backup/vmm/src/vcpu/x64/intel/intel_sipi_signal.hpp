#ifndef VMM_VCPU_X64_INTEL_SIPI_SIGNAL_HPP
#define VMM_VCPU_X64_INTEL_SIPI_SIGNAL_HPP

#include <vmm/vcpu/x64/sipi_signal.hpp>

namespace vmm
{

class intel_sipi_signal :
    public sipi_signal
{
public:

    void set_sipi_signal_vmexit_handler(x64_vcpu_delegate func)
    {
        // TODO: Implement Me!
        return;
    }

    intel_sipi_signal() noexcept = default;
};

}

#endif
