#include <vmm/x64.hpp>

namespace vmm
{

void init_root_vcpu(x64_vcpu &vcpu) noexcept
{
    // Properties of a vcpu can be read from a vcpu init handler
    // Here are a few useful ones:
    auto id = vcpu.get_id();

    if(vcpu.is_root_vcpu()) {
        return;
    }

    return;
}

bsl::errc_type init_vmm(x64_vm &root_vm, x64_platform &platform) noexcept
{
    // Properties of the host system that the vmm is executing on can be read
    // from the given platform object. For example:
    uintptr_t dmar_hpa = platform.get_acpi_dmar_hpa();
    bool late_launch = platform.is_late_launch();

    // Virtual machines (such as the root virtual machine) also have properties
    auto vm_id = root_vm.get_id();

    root_vm.set_vcpu_init_handler(init_root_vcpu);
    return 0;
}

}
