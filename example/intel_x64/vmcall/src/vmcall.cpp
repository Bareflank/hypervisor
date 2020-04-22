#include <vmm/x64.hpp>

// This example demonstrates how to set up a hypercall interface using a
// vmcall vmexit handler. This example's hypercall interface consists of a
// single input/output register: rax. If the value "0xF00D" is in the register
// rax when the hypercall is made, the value "0xBEEF" is placed into rax
// as a return value. Otherwise, the value "0xBADC0FFEE" is placed into rax.

namespace vmm
{

void vmcall_handler(x64_vcpu &vcpu) noexcept
{
    auto rax = vcpu.rax_get();

    if (rax == 0xF00D) {
        vcpu.rax_set(0xBEEF);
    }
    else {
        vcpu.rax_set(0xBADC0FFEE);
    }

    vcpu.instruction_pointer_advance();
    vcpu.run();
}

void root_vcpu_init(x64_vcpu &vcpu) noexcept
{
    vcpu.vmexit_handler_set(vmcall_handler);
}

bsl::errc_type vmm_init(x64_vm &root_vm, x64_platform &platform) noexcept
{
    root_vm.vcpu_init_handler_set(root_vcpu_init);
    return 0;
}

}
