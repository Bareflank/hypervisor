#ifndef VMM_X64_VM_INSTANCE_HPP
#define VMM_X64_VM_INSTANCE_HPP

#include <vmm/vm/x64/x64_vm.hpp>
#include <vmm/vcpu/x64/x64_vcpu.hpp>
#include <vmm/vcpu/x64/x64_vcpu_delegate.hpp>

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
    uint32_t get_id() noexcept final
    { return m_vm_property_type.get_id(); }

    // ------------------------- x64_vcpu_op seam ------------------------------
    void set_vcpu_init_handler(x64_vcpu_delegate func) noexcept final
    { return m_vcpu_ops.set_vcpu_init_handler(func); }

    void set_vcpu_fini_handler(x64_vcpu_delegate func) noexcept final
    { return m_vcpu_ops.set_vcpu_fini_handler(func); }

private:
    vm_property_type m_vm_property_type;
    vcpu_op_type m_vcpu_ops;
};

}

#endif
