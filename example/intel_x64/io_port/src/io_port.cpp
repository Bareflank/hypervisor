#include <vmm/x64.hpp>

// This example demonstrates how to virtualize I/O ports on an x64 platform
// using the Bareflank Hypervisor SDK. The example emulates reads and writes to
// the I/O port at address range 0xBF0 - 0xBFF, and passes through all other I/O
// port accesses from the root vm through to hardware.
//
// The following behaviors are emulated by this VMM:
//
//      - When the root vm reads from an I/O port in the range 0xBF0-0xBFF, the
//        VMM emulates a return value
//
//      - When the guest writes to an I/O port in the range 0xBF0-0xBFF, the VMM
//        discards the write so that it does not get written to a hardware port

namespace vmm
{

constexpr const uint16_t emulated_range_low = 0xBF0;
constexpr const uint16_t emulated_range_high = 0xBFF;

void handle_in(x64_vcpu &vcpu) noexcept
{
    uint64_t port = vcpu.io_port_vmexit_port_number_get(); 

    if ((port > emulated_range_low) && (port < emulated_range_high)) {
        vcpu.io_port_in_emulate(0xBFBFBFBF);
    }
    else {
        vcpu.io_port_in_execute();
    }
}

void handle_out(x64_vcpu &vcpu) noexcept
{
    uint64_t port = vcpu.io_port_vmexit_port_number_get(); 

    if ((port < emulated_range_low) || (port > emulated_range_high)) {
        vcpu.io_port_out_execute();
    }
}

void io_port_vmexit_handler(x64_vcpu &vcpu) noexcept
{
    if (vcpu.io_port_vmexit_is_in()) {
        handle_in(vcpu);
    }
    else if(vcpu.io_port_vmexit_is_out()) {
        handle_out(vcpu);
    }

    vcpu.instruction_pointer_advance();
    vcpu.run();
}

void root_vcpu_init(x64_vcpu &vcpu) noexcept
{
    vcpu.io_port_vmexit_handler_set(io_port_vmexit_handler);
    vcpu.io_port_vmexit_range_enable(emulated_range_low, emulated_range_high);
}

bsl::errc_type vmm_init(x64_vm &root_vm, x64_platform &platform) noexcept
{
    root_vm.vcpu_init_handler_set(root_vcpu_init);
    return 0;
}

}
