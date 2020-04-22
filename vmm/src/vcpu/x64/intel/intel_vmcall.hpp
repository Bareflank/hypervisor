#ifndef VMM_VCPU_X64_INTEL_VMCALL_HPP
#define VMM_VCPU_X64_INTEL_VMCALL_HPP

#include <vmm/vcpu/x64/vmcall.hpp>

namespace vmm
{

class intel_vmcall :
    public vmcall
{
public:

    void vmcall_vmexit_handler_set(x64_vcpu_delegate func) noexcept final
    {
        // TODO: Implement Me!
        return;
    }

    intel_vmcall() noexcept = default;
};

}

#endif
