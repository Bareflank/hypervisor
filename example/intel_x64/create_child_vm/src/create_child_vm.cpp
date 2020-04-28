#include <vmm/x64.hpp>

namespace vmm
{

void init_root_vcpu(x64_vcpu &vcpu) noexcept
{
    // Initilize the root vm's vcpus here
    return;
}

void init_child_vcpu(x64_vcpu &vcpu) noexcept
{
    // Initilize the child vm's vcpus here
    return;
}

bsl::errc_type init_vmm(x64_vm &root_vm, x64_platform &platform) noexcept
{
    uint32_t n_vcpus = 1;
    x64_vm &child_vm = vmm::create_x64_vm(n_vcpus);

    // How to give memory to the vm?
    // TODO

    // How to set the VM's cpu/vcpu affinity, or setup parent vcpus?
    // TODO

    // Set a vcpu init handler for the child vm
    child_vm.set_vcpu_init_handler(init_child_vcpu);

    // Set a different init handler for the root vm's vcpus 
    root_vm.set_vcpu_init_handler(init_root_vcpu);

    return -1;
}

}
