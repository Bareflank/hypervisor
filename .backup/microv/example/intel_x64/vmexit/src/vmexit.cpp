#include <vmm/x64.hpp>

namespace vmm
{

void handle_vmexit(x64_vcpu &vcpu) noexcept
{
    // This handler gets called on every vmexit that occurs on the given vcpu
    auto reason = vcpu.get_vmexit_reason();
    auto qualification = vcpu.get_vmexit_qualification();

    // You get to choose if the instruction pointer gets advanced or not.
    // The base won't do anything on your behalf
    vcpu.advance_instruction_pointer();

    // You are responsible for returning execution to a vcpu. It could be this
    // one, or it could be a different one
    vcpu.run();
}

void init_root_vcpu(x64_vcpu &vcpu) noexcept
{
    // Set the handler for *all* vmexits on the given vcpu
    vcpu.set_vmexit_handler(handle_vmexit);
}

bsl::errc_type init_vmm(x64_vm &root_vm, x64_platform &platform) noexcept
{
    root_vm.set_vcpu_init_handler(init_root_vcpu);
    return 0;
}

}
