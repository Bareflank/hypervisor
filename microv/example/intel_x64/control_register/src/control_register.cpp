#include <vmm/x64.hpp>
#include <pal/control_register/cr0.h>
#include <pal/control_register/cr3.h>
#include <pal/control_register/cr4.h>

// This example demonstrates how to virtualize control registers on an x64
// platform using the Bareflank Hypervisor SDK. The example includes emulation
// for the root virtual machine's cr0, cr3, and cr4.
//
// The following behaviors are emulated by this VMM:
//
//      - Attempts to disable protected mode (cr0.pe) and paging (cr0.pg) from
//        within the root virtual machine are transparently blocked by the vmm.
//
//      - Reads to cr3 from within the root virtual machine are passed through
//
//      - If the root virtual machine writes the value "0x1337" to it's cr3,
//        the vmm prints its own cr3 out to a serial port
//
//      - Attempts to enable virtual machine extensions (cr4.vmxe) from within
//        root virtual machine are transparently blocked by the vmm.

namespace vmm
{

void handle_cr0_write_vmexit(x64_vcpu &vcpu) noexcept
{
    uint64_t emulated_cr0 = vcpu.get_cr0_write_vmexit_value();
    pal::cr0::pe::enable(emulated_cr0);
    pal::cr0::pg::enable(emulated_cr0);
    vcpu.emulate_cr0_write(emulated_cr0);

    vcpu.advance_instruction_pointer();
    vcpu.run();
}

void handle_cr3_read_vmexit(x64_vcpu &vcpu) noexcept
{
    vcpu.emulate_cr3_read(0xBADC0FFEE);

    vcpu.advance_instruction_pointer();
    vcpu.run();
}

void handle_cr3_write_vmexit(x64_vcpu &vcpu) noexcept
{
    uint64_t cr3_value = vcpu.get_cr3_write_vmexit_value();
    if (cr3_value == 0x1337) {
        pal::cr3::dump();
    }

    vcpu.advance_instruction_pointer();
    vcpu.run();
}

void handle_cr4_write_vmexit(x64_vcpu &vcpu) noexcept
{
    uint64_t emulated_cr4 = vcpu.get_cr4_write_vmexit_value();
    pal::cr4::vmxe::disable(emulated_cr4);
    vcpu.emulate_cr4_write(emulated_cr4);

    vcpu.advance_instruction_pointer();
    vcpu.run();
}

void init_root_vcpu(x64_vcpu &vcpu) noexcept
{
    vcpu.set_cr0_write_vmexit_handler(handle_cr0_write_vmexit);
    vcpu.enable_cr0_write_vmexit();

    vcpu.set_cr3_read_vmexit_handler(handle_cr3_write_vmexit);
    vcpu.set_cr3_write_vmexit_handler(handle_cr3_write_vmexit);
    vcpu.enable_cr3_read_vmexit();
    vcpu.enable_cr3_write_vmexit();

    vcpu.set_cr4_write_vmexit_handler(handle_cr4_write_vmexit);
    vcpu.enable_cr4_write_vmexit();
}

bsl::errc_type init_vmm(x64_vm &root_vm, x64_platform &platform) noexcept
{
    root_vm.set_vcpu_init_handler(init_root_vcpu);
    return 0;
}

}
