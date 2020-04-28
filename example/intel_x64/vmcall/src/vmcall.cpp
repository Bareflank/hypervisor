#include <vmm/x64.hpp>

// This example demonstrates how to set up a hypercall interface using a
// vmcall vmexit handler. This example's hypercall interface consists of a
// single input/output register: rax. If the value "0xF00D" is in the register
// rax when the hypercall is made, the value "0xBEEF" is placed into rax
// as a return value. Otherwise, the value "0xBADC0FFEE" is placed into rax.

namespace vmm
{

void handle_vmcall(x64_vcpu &vcpu) noexcept
{
    auto rax = vcpu.get_rax();

    if (rax == 0xF00D) {
        vcpu.set_rax(0xBEEF);
    }
    else {
        vcpu.set_rax(0xBADC0FFEE);
    }

    vcpu.advance_instruction_pointer();
    vcpu.run();
}

void init_root_vcpu(x64_vcpu &vcpu) noexcept
{
    vcpu.set_vmexit_handler(handle_vmcall);
}

bsl::errc_type init_vmm(x64_vm &root_vm, x64_platform &platform) noexcept
{
    root_vm.set_vcpu_init_handler(init_root_vcpu);
    return 0;
}

}
