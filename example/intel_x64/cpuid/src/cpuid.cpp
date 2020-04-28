#include <vmm/x64.hpp>

// This example demonstrates how to virtualize cpuid leaves on an x64 platform
// using the Bareflank Hypervisor SDK. The example adds a virtual cpuid leaf
// to the root vm at leaf number 0xBF000000, with emulated values returned in
// all cpuid output registers (eax, ebx, ecx, and edx). All other cpuid
// leaves/subleaves are passed through from the root vm to hardware.

namespace vmm
{

void handle_cpuid_vmexit(x64_vcpu &vcpu) noexcept
{
    uint64_t leaf = vcpu.get_cpuid_vmexit_leaf(); 

    switch(leaf) {
        case 0xBF000000:
            vcpu.emulate_cpuid(0xBFBFBFBF, 0, 0xFFFFFFFF, 0xA55A5AA5);
        default:
            vcpu.execute_cpuid();
    }

    vcpu.advance_instruction_pointer();
    vcpu.run();
}

void init_root_vcpu(x64_vcpu &vcpu) noexcept
{
    vcpu.set_cpuid_vmexit_handler(handle_cpuid_vmexit);
}

bsl::errc_type init_vmm(x64_vm &root_vm, x64_platform &platform) noexcept
{
    root_vm.set_vcpu_init_handler(init_root_vcpu);
    return 0;
}

}
