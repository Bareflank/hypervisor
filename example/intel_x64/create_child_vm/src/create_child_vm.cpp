#include <vmm/x64.hpp>

namespace vmm
{

void root_vcpu_init(x64_vcpu &vcpu) noexcept
{
    // Initilize the root vm's vcpus here
    return;
}

void child_vcpu_init(x64_vcpu &vcpu) noexcept
{
    // Initilize the child vm's vcpus here
    return;
}

bsl::errc_type vmm_init(x64_vm &root_vm, x64_platform &platform) noexcept
{
    uint32_t n_vcpus = 1;
    x64_vm &child_vm = vmm::x64_vm_create(n_vcpus);

    // How to give memory to the vm?
    // TODO

    // How to set the VM's cpu/vcpu affinity, or setup parent vcpus?
    // TODO

    // Set a vcpu init handler for the child vm
    child_vm.vcpu_init_handler_set(child_vcpu_init);

    // Set a different init handler for the root vm's vcpus 
    root_vm.vcpu_init_handler_set(root_vcpu_init);

    return -1;
}

}
