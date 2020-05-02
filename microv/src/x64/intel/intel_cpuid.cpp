#include <microv/x64/cpuid.hpp>

namespace microv
{

void set_cpuid_vmexit_handler(vmexit_context &vc, vmexit_delegate func) noexcept
{
    // TODO: Implement Me!
    return;
}

uint32_t get_cpuid_vmexit_leaf(vmexit_context &vc) noexcept
{
    // TODO: Implement Me!
    return 0;
}

uint32_t get_cpuid_vmexit_subleaf(vmexit_context &vc) noexcept
{
    // TODO: Implement Me!
    return 0;
}

void provide_cpuid_result(vmexit_context &vc, uint32_t eax, uint32_t ebx, uint32_t ecx, uint32_t edx) noexcept
{
    // TODO: Implement Me!
    return;
}

}
