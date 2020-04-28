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
    uint64_t port = vcpu.get_io_port_vmexit_port_number(); 

    if ((port > emulated_range_low) && (port < emulated_range_high)) {
        vcpu.emulate_io_port_in(0xBFBFBFBF);
    }
    else {
        vcpu.execute_io_port_in();
    }
}

void handle_out(x64_vcpu &vcpu) noexcept
{
    uint64_t port = vcpu.get_io_port_vmexit_port_number(); 

    if ((port < emulated_range_low) || (port > emulated_range_high)) {
        vcpu.execute_io_port_out();
    }
}

void handle_io_port_vmexit(x64_vcpu &vcpu) noexcept
{
    if (vcpu.is_io_port_vmexit_in()) {
        handle_in(vcpu);
    }
    else if(vcpu.is_io_port_vmexit_out()) {
        handle_out(vcpu);
    }

    vcpu.advance_instruction_pointer();
    vcpu.run();
}

void init_root_vcpu(x64_vcpu &vcpu) noexcept
{
    vcpu.set_io_port_vmexit_handler(handle_io_port_vmexit);
    vcpu.enable_io_port_vmexit_range(emulated_range_low, emulated_range_high);
}

bsl::errc_type init_vmm(x64_vm &root_vm, x64_platform &platform) noexcept
{
    root_vm.set_vcpu_init_handler(init_root_vcpu);
    return 0;
}

}
