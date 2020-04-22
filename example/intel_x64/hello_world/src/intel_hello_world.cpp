#include <vmm/x64.hpp>
// #include <bsl/print.hpp> // <-- I don't think this work in a vmm context yet

namespace vmm
{

void hello_world_vcpu_init(x64_vcpu &vcpu) noexcept
{
    // The following would print once on each host vcpu right after it is
    // initilized
    //
    // bsl::print() << "Your host is now in a vm";
    return;
}

void hello_world_vcpu_fini(x64_vcpu &vcpu) noexcept
{
    // The following would print once on each host vcpu right before it is
    // destroyed
    //
    // bsl::print() << "Your host is not in a vm";
    return;
}

bsl::errc_type vmm_init(x64_vm &root_vm, x64_platform &platform) noexcept
{
    root_vm.vcpu_init_handler_set(hello_world_vcpu_init);
    root_vm.vcpu_fini_handler_set(hello_world_vcpu_fini);

    // The following would print once from a vmx-root context on the bootstrap
    // vcpu, before any of the other print statements
    //
    // bsl::print() << "Root virtual machine initialized";

    return 0;
}

}
