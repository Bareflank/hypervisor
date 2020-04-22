#include <vmm/x64.hpp>

namespace vmm
{

void root_vcpu_init(x64_vcpu &vcpu) noexcept
{
    // Properties of a vcpu can be read from a vcpu init handler
    // Here are a few useful ones:
    auto id = vcpu.id_get();

    if(vcpu.is_root_vcpu()) {
        return;
    }

    return;
}

bsl::errc_type vmm_init(x64_vm &root_vm, x64_platform &platform) noexcept
{
    // Properties of the host system that the vmm is executing on can be read
    // from the given platform object. For example:
    uintptr_t dmar_hpa = platform.acpi_dmar_hpa_get();
    bool late_launch = platform.loader_is_late_launch();

    // Virtual machines (such as the root virtual machine) also have properties
    auto vm_id = root_vm.id_get();

    root_vm.vcpu_init_handler_set(root_vcpu_init);
    return 0;
}

}
