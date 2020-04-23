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

void cr0_write_vmexit_handler(x64_vcpu &vcpu) noexcept
{
    uint64_t emulated_cr0 = vcpu.cr0_write_vmexit_value_get();
    pal::cr0::pe::enable(emulated_cr0);
    pal::cr0::pg::enable(emulated_cr0);
    vcpu.cr0_write_emulate(emulated_cr0);

    vcpu.instruction_pointer_advance();
    vcpu.run();
}

void cr3_read_vmexit_handler(x64_vcpu &vcpu) noexcept
{
    vcpu.cr3_read_emulate(0xBADC0FFEE);

    vcpu.instruction_pointer_advance();
    vcpu.run();
}

void cr3_write_vmexit_handler(x64_vcpu &vcpu) noexcept
{
    uint64_t cr3_value = vcpu.cr3_write_vmexit_value_get();
    if (cr3_value == 0x1337) {
        pal::cr3::dump();
    }

    vcpu.instruction_pointer_advance();
    vcpu.run();
}

void cr4_write_vmexit_handler(x64_vcpu &vcpu) noexcept
{
    uint64_t emulated_cr4 = vcpu.cr4_write_vmexit_value_get();
    pal::cr4::vmxe::disable(emulated_cr4);
    vcpu.cr4_write_emulate(emulated_cr4);

    vcpu.instruction_pointer_advance();
    vcpu.run();
}

void root_vcpu_init(x64_vcpu &vcpu) noexcept
{
    vcpu.cr0_write_vmexit_handler_set(cr0_write_vmexit_handler);
    vcpu.cr0_write_vmexit_enable();

    vcpu.cr3_read_vmexit_handler_set(cr0_write_vmexit_handler);
    vcpu.cr3_read_vmexit_enable();
    vcpu.cr3_write_vmexit_handler_set(cr0_write_vmexit_handler);
    vcpu.cr3_write_vmexit_enable();

    vcpu.cr4_write_vmexit_handler_set(cr0_write_vmexit_handler);
    vcpu.cr4_write_vmexit_enable();
}

bsl::errc_type vmm_init(x64_vm &root_vm, x64_platform &platform) noexcept
{
    root_vm.vcpu_init_handler_set(root_vcpu_init);
    return 0;
}

}
