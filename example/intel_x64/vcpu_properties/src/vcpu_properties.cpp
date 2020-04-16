#include <vmm/x64.hpp>

namespace vmm
{

void
root_vcpu_init(x64_vcpu &vcpu) noexcept
{
    auto id = vcpu.id_get();

    if(vcpu.is_root_vcpu()) {
        return;
    }

    return;
}

bsl::errc_type
root_vm_init(x64_vm &root_vm) noexcept
{
    root_vm.vcpu_init_handler_set(root_vcpu_init);
    return 0;
}

}
