#ifndef VMM_VIRTUAL_MACHINE_MONITOR_INSTANCE_HPP
#define VMM_VIRTUAL_MACHINE_MONITOR_INSTANCE_HPP

#include <bsl/errc_type.hpp>

namespace vmm
{

template<
    class platform_type,
    class vcpu_type,
    class vm_type
>
class virtual_machine_monitor_instance
{
public:

    virtual_machine_monitor_instance() noexcept = default;

    vm_type &
    make_virtual_machine(uint32_t n_vcpus) noexcept
    {
        // TODO: Allocate a new VM from a pool of uninitialized VMs
        return m_vm_pool[0];
    }

    vcpu_type &
    make_vcpu() noexcept
    {
        // TODO: Allocate a new vcpu from a pool of uninitialized vcpus 
        return m_vcpu_pool[0];
    }

    platform_type &
    platform_instance() noexcept
    {
        return m_platform;
    }

private:
    platform_type m_platform{};
    vcpu_type m_vcpu_pool[1024]{};
    vm_type m_vm_pool[64]{};
};

}

#endif


