#include <vmm/x64.hpp>

namespace vmm
{

void my_vmexit_handler(x64_vcpu &vcpu) noexcept
{
    // This handler gets called on every vmexit that occurs on the given vcpu
    auto reason = vcpu.vmexit_reason_get();
    auto qualification = vcpu.vmexit_qualification_get();

    // You get to choose if the instruction pointer gets advanced or not.
    // The base won't do anything on your behalf
    vcpu.instruction_pointer_advance();

    // You are responsible for returning execution to a vcpu. It could be this
    // one, or it could be a different one
    vcpu.run();
}

void root_vcpu_init(x64_vcpu &vcpu) noexcept
{
    // Set the handler for *all* vmexits on the given vcpu
    vcpu.vmexit_handler_set(my_vmexit_handler);
}

bsl::errc_type
root_vm_init(x64_vm &root_vm) noexcept
{
    root_vm.vcpu_init_handler_set(root_vcpu_init);
    return 0;
}

}
