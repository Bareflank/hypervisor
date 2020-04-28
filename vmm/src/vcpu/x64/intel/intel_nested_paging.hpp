#ifndef VMM_VCPU_X64_INTEL_NETSTED_PAGING_HPP
#define VMM_VCPU_X64_INTEL_NETSTED_PAGING_HPP

#include <vmm/vcpu/x64/nested_paging.hpp>

namespace vmm
{

class intel_nested_paging :
    public nested_paging
{
public:

    void enable_nested_paging() noexcept final
    {
        // TODO: Implement Me!
        return;
    }

    void disable_nested_paging() noexcept final
    {
        // TODO: Implement Me!
        return;
    }

    void set_nested_paging_base_address(uintptr_t phys_addr) noexcept final
    {
        // TODO: Implement Me!
        return;
    }

    void set_nested_paging_violation_vmexit_handler(x64_vcpu_delegate func) noexcept final
    {
        // TODO: Implement Me!
        return;
    }

    void set_nested_paging_misconfiguration_vmexit_handler(x64_vcpu_delegate func) noexcept final
    {
        // TODO: Implement Me!
        return;
    }

    bool is_nested_paging_vmexit_read() noexcept final
    {
        // TODO: Implement Me!
        return false;
    }

    bool is_nested_paging_vmexit_write() noexcept final
    {
        // TODO: Implement Me!
        return false;
    }

    bool is_nested_paging_vmexit_execute() noexcept final
    {
        // TODO: Implement Me!
        return false;
    }

    bool is_nested_paging_vmexit_violation() noexcept final
    {
        // TODO: Implement Me!
        return false;
    }

    bool is_nested_paging_vmexit_misconfiguration() noexcept final
    {
        // TODO: Implement Me!
        return false;
    }

    intel_nested_paging() noexcept = default;
};

}

#endif
