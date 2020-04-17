#ifndef VMM_VCPU_X64_INTEL_XCR0_HPP
#define VMM_VCPU_X64_INTEL_XCR0_HPP

#include <vmm/vcpu/x64/xcr0.hpp>

namespace vmm
{

class intel_xcr0 :
    public xcr0
{
public:

    void write_xcr0_vmexit_handler_set(x64_vcpu_delegate func)
    {
        // TODO: Implement Me!
        return;
    }

    intel_xcr0() noexcept = default;
};

}

#endif
