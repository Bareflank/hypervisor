#ifndef VMM_VCPU_X64_INTEL_NETSTED_PAGING_HPP
#define VMM_VCPU_X64_INTEL_NETSTED_PAGING_HPP

#include <vmm/vcpu/nested_paging.hpp>

namespace vmm
{

class intel_nested_paging :
    public nested_paging
{
public:

    intel_nested_paging() noexcept = default;

    // TODO: Implement Me!
};

}

#endif
