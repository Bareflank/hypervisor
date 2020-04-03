#ifndef VMM_VCPU_X64_INTEL_VPID_HPP
#define VMM_VCPU_X64_INTEL_VPID_HPP

#include <vmm/vcpu/x64/vpid.hpp>

namespace vmm
{

class intel_vpid :
    public vpid
{
public:

    void
    vpid_enable() noexcept final
    {
        // TODO: Implement Me!
    }

    intel_vpid() noexcept = default;
};

}

#endif
