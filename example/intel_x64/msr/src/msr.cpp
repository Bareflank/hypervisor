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
    vcpu.emulate_rdmsr(emulated_msr);
}

void emulate_ia32_efer_write(x64_vcpu &vcpu) noexcept
{
    uint64_t emulated_value = vcpu.get_wrmsr_vmexit_value();
    pal::ia32_efer::lme::disable(emulated_value);
    vcpu.emulate_wrmsr(emulated_value);
}

void handle_rdmsr_vmexit(x64_vcpu &vcpu) noexcept
{
    uint64_t msr_address = vcpu.get_rdmsr_vmexit_address(); 

    switch(msr_address) {
        case pal::ia32_efer::address:
            emulate_ia32_efer_read(vcpu);
        default:
            vcpu.execute_rdmsr();
    }

    vcpu.advance_instruction_pointer();
    vcpu.run();
}

void handle_wrmsr_vmexit(x64_vcpu &vcpu) noexcept
{
    uint64_t msr_address = vcpu.get_wrmsr_vmexit_address(); 

    switch(msr_address) {
        case pal::ia32_efer::address:
            emulate_ia32_efer_write(vcpu);
        default:
            vcpu.execute_wrmsr();
    }

    vcpu.advance_instruction_pointer();
    vcpu.run();
}

void init_root_vcpu(x64_vcpu &vcpu) noexcept
{
    vcpu.set_rdmsr_vmexit_handler(handle_rdmsr_vmexit);
    vcpu.enable_rdmsr_vmexit(pal::ia32_efer::address);

    vcpu.set_wrmsr_vmexit_handler(handle_wrmsr_vmexit);
    vcpu.enable_wrmsr_vmexit(pal::ia32_efer::address);
}

bsl::errc_type init_vmm(x64_vm &root_vm, x64_platform &platform) noexcept
{
    root_vm.set_vcpu_init_handler(init_root_vcpu);
    return 0;
}

}
