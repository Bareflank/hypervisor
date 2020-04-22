#include <vmm/x64.hpp>
#include <pal/msr/ia32_efer.h>

// This example demonstrates how to virtualize model specific registers (MSRs)
// on an x64 platform using the Bareflank Hypervisor SDK. The example
// emulates reads and writes to the IA32_EFER MSR, and passes through all other
// MSR accesses from the guest to hardware.
//
// The following behaviors are emulated by this VMM:
//
//      - When the guest reads from IA32_EFER, the VMM advertises that the CPU
//        is not running in IA-32e long mode by emulating the "LMA" bit
//
//      - When the guest writes to IA32_EFER, the VMM prevents the CPU from
//        switching into IA-32e long mode by emulating the "LME" bit

namespace vmm
{

void emulate_ia32_efer_read(x64_vcpu &vcpu) noexcept
{
    uint64_t emulated_msr = pal::ia32_efer::get();
    pal::ia32_efer::lma::disable(emulated_msr);
    vcpu.rdmsr_emulate(emulated_msr);
}

void emulate_ia32_efer_write(x64_vcpu &vcpu) noexcept
{
    uint64_t emulated_value = vcpu.wrmsr_vmexit_value_get();
    pal::ia32_efer::lme::disable(emulated_value);
    vcpu.wrmsr_emulate(emulated_value);
}

void rdmsr_vmexit_handler(x64_vcpu &vcpu) noexcept
{
    uint64_t msr_address = vcpu.rdmsr_vmexit_address_get(); 

    switch(msr_address) {
        case pal::ia32_efer::address:
            emulate_ia32_efer_read(vcpu);
        default:
            vcpu.rdmsr_execute();
    }

    vcpu.instruction_pointer_advance();
    vcpu.run();
}

void wrmsr_vmexit_handler(x64_vcpu &vcpu) noexcept
{
    uint64_t msr_address = vcpu.wrmsr_vmexit_address_get(); 

    switch(msr_address) {
        case pal::ia32_efer::address:
            emulate_ia32_efer_write(vcpu);
        default:
            vcpu.wrmsr_execute();
    }

    vcpu.instruction_pointer_advance();
    vcpu.run();
}

void root_vcpu_init(x64_vcpu &vcpu) noexcept
{
    vcpu.rdmsr_vmexit_handler_set(rdmsr_vmexit_handler);
    vcpu.rdmsr_vmexit_enable(pal::ia32_efer::address);

    vcpu.wrmsr_vmexit_handler_set(wrmsr_vmexit_handler);
    vcpu.wrmsr_vmexit_enable(pal::ia32_efer::address);
}

bsl::errc_type vmm_init(x64_vm &root_vm, x64_platform &platform) noexcept
{
    root_vm.vcpu_init_handler_set(root_vcpu_init);
    return 0;
}

}
