#ifndef VMM_X64_VM_INSTANCE_HPP
#define VMM_X64_VM_INSTANCE_HPP

#include<vmm/vcpu/x64/x64_vcpu.hpp>
#include <vmm/vm/x64/x64_vm.hpp>

namespace vmm
{

template<
    class vm_property_type,
    class vcpu_op_type
>
class x64_vm_seam :
    public vmm::x64_vm
{
public:

    // ------------------------- vm_property seam ------------------------------
    uint32_t id_get() noexcept final
    { return m_vm_property_type.id_get(); }

    // ------------------------- x64_vcpu_op seam ------------------------------
    void vcpu_init_handler_set(bsl::delegate<void (x64_vcpu &)> func) noexcept final
    { return m_vcpu_ops.vcpu_init_handler_set(func); }

    void vcpu_fini_handler_set(bsl::delegate<void (x64_vcpu &)> func) noexcept final
    { return m_vcpu_ops.vcpu_fini_handler_set(func); }

private:
    vm_property_type m_vm_property_type;
    vcpu_op_type m_vcpu_ops;
};

}

#endif
