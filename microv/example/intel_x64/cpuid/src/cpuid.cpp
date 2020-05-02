#include <microv/microv.hpp>
#include <microv/x64/x64.hpp>

// This example demonstrates how to virtualize cpuid leaves on an x64 platform
// using the Bareflank Hypervisor SDK. The example adds a virtual cpuid leaf
// to the root vm at leaf number 0xBF000000, with emulated values returned in
// all cpuid output registers (eax, ebx, ecx, and edx). All other cpuid
// leaves/subleaves are passed through from the root vm to hardware.

void handle_cpuid_vmexit(vmexit_context &vc) noexcept
{
    uint64_t leaf = microv::get_cpuid_vmexit_leaf(vc); 
    uint64_t subleaf = microv::get_cpuid_vmexit_subleaf(vc); 

    uint64_t rax_out;
    uint64_t rbx_out;
    uint64_t rcx_out;
    uint64_t rdx_out;

    switch(leaf) {
        case 0xBF000000:
            rax_out = 0xBFBFBFBF;
            rbx_out = 0x0;
            rcx_out = 0xFFFFFFFF;
            rdx_out = 0xA55A5AA5;
            break;
        case 1:
            // rax_out = pal::get_cpuid_leaf_01_eax(vc);
            rbx_out = 0x0;
            // rcx_out = pal::get_cpuid_leaf_01_ecx(vc);
            rdx_out = 0x0;
            break;
        default:
            rax_out = 0x0;
            rbx_out = 0x0;
            rcx_out = 0x0;
            rdx_out = 0x0;
            break;
    }

    microv::provide_cpuid_result(vc, rax_out, rbx_out, rcx_out, rdx_out);
    microv::advance_instruction_pointer(vc);
    microv::run(vc);
}

void init_root_vmexit_context(vmexit_context &vc) noexcept
{
    microv::set_cpuid_vmexit_handler(vc, handle_cpuid_vmexit);
}

bsl::exit_code main(vmexit_context &vc)
{
    microv::set_init_handler(vc, init_root_vmexit_context);
    microv::run(vc);

    return 0;
}
