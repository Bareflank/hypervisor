#include <vmm/x64.hpp>
// #include <bsl/print.hpp> // <-- I don't think this work in a vmm context yet

namespace vmm
{

void init_hello_world_vcpu(x64_vcpu &vcpu) noexcept
{
    // The following would print once on each host vcpu right after it is
    // initilized
    //
    // bsl::print() << "Your host is now in a vm";
    return;
}

void fini_hello_world_vcpu(x64_vcpu &vcpu) noexcept
{
    // The following would print once on each host vcpu right before it is
    // destroyed
    //
    // bsl::print() << "Your host is not in a vm";
    return;
}

bsl::errc_type init_vmm(x64_vm &root_vm, x64_platform &platform) noexcept
{
    root_vm.set_vcpu_init_handler(init_hello_world_vcpu);
    root_vm.set_vcpu_fini_handler(fini_hello_world_vcpu);

    // The following would print once from a vmx-root context on the bootstrap
    // vcpu, before any of the other print statements
    //
    // bsl::print() << "Root virtual machine initialized";

    return 0;
}

}
