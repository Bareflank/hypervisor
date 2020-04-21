#ifndef VMM_VCPU_X64_INTEL_NETSTED_PAGING_HPP
#define VMM_VCPU_X64_INTEL_NETSTED_PAGING_HPP

#include <vmm/vcpu/x64/nested_paging.hpp>

namespace vmm
{

class intel_nested_paging :
    public nested_paging
{
public:

    void nested_paging_enable() noexcept final
    {
        // TODO: Implement Me!
        return;
    }

    void nested_paging_disable() noexcept final
    {
        // TODO: Implement Me!
        return;
    }

    void nested_paging_base_address_set(uintptr_t phys_addr) noexcept final
    {
        // TODO: Implement Me!
        return;
    }

    void nested_paging_violation_vmexit_handler_set(x64_vcpu_delegate func) noexcept final
    {
        // TODO: Implement Me!
        return;
    }

    void nested_paging_misconfiguration_vmexit_handler_set(x64_vcpu_delegate func) noexcept final
    {
        // TODO: Implement Me!
        return;
    }

    bool nested_paging_vmexit_is_read() noexcept final
    {
        // TODO: Implement Me!
        return false;
    }

    bool nested_paging_vmexit_is_write() noexcept final
    {
        // TODO: Implement Me!
        return false;
    }

    bool nested_paging_vmexit_is_execute() noexcept final
    {
        // TODO: Implement Me!
        return false;
    }

    bool nested_paging_vmexit_is_violation() noexcept final
    {
        // TODO: Implement Me!
        return false;
    }

    bool nested_paging_vmexit_is_misconfiguration() noexcept final
    {
        // TODO: Implement Me!
        return false;
    }

    intel_nested_paging() noexcept = default;
};

}

#endif
