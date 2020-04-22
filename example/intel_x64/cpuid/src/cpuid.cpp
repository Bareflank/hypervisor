#include <vmm/x64.hpp>

// This example demonstrates how to virtualize cpuid leaves on an x64 platform
// using the Bareflank Hypervisor SDK. The example adds a virtual cpuid leaf
// to the root vm at leaf number 0xBF000000, with emulated values returned in
// all cpuid output registers (eax, ebx, ecx, and edx). All other cpuid
// leaves/subleaves are passed through from the root vm to hardware.

namespace vmm
{

void cpuid_vmexit_handler(x64_vcpu &vcpu) noexcept
{
    uint64_t leaf = vcpu.cpuid_vmexit_leaf_get(); 

    switch(leaf) {
        case 0xBF000000:
            vcpu.cpuid_emulate(0xBFBFBFBF, 0, 0xFFFFFFFF, 0xA55A5AA5);
        default:
            vcpu.cpuid_execute();
    }

    vcpu.instruction_pointer_advance();
    vcpu.run();
}

void root_vcpu_init(x64_vcpu &vcpu) noexcept
{
    vcpu.cpuid_vmexit_handler_set(cpuid_vmexit_handler);
}

bsl::errc_type vmm_init(x64_vm &root_vm, x64_platform &platform) noexcept
{
    root_vm.vcpu_init_handler_set(root_vcpu_init);
    return 0;
}

}
