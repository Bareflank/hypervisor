#ifndef VMM_VCPU_X64_INTEL_CR4_HPP
#define VMM_VCPU_X64_INTEL_CR4_HPP

#include <vmm/vcpu/x64/cr4.hpp>

namespace vmm
{

class intel_cr4 :
    public cr4
{
public:

    void cr4_write_vmexit_enable() noexcept
    {
        return;
    }

    void cr4_write_vmexit_disable() noexcept
    {
        return;
    }

    void cr4_write_vmexit_handler_set(x64_vcpu_delegate func)
    {
        return;
    }

    uint64_t cr4_write_vmexit_value_get() noexcept
    {
        return 0;
    }

    void cr4_write_execute() noexcept
    {
        return;
    }

    void cr4_write_emulate(uint64_t cr4_value) noexcept
    {
        return;
    }

    intel_cr4() noexcept = default;
};

}

#endif
