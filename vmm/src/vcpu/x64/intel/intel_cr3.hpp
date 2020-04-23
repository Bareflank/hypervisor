#ifndef VMM_VCPU_X64_INTEL_CR3_HPP
#define VMM_VCPU_X64_INTEL_CR3_HPP

#include <vmm/vcpu/x64/cr3.hpp>

namespace vmm
{

class intel_cr3 :
    public cr3
{
public:

    void cr3_read_vmexit_enable() noexcept
    {
        return;
    }

    void cr3_read_vmexit_disable() noexcept
    {
        return;
    }

    void cr3_read_vmexit_handler_set(x64_vcpu_delegate func)
    {
        return;
    }

    void cr3_read_execute() noexcept
    {
        return;
    }

    void cr3_read_emulate(uint64_t cr3_value) noexcept
    {
        return;
    }

    void cr3_write_vmexit_enable() noexcept
    {
        return;
    }

    void cr3_write_vmexit_disable() noexcept
    {
        return;
    }

    void cr3_write_vmexit_handler_set(x64_vcpu_delegate func)
    {
        return;
    }

    uint64_t cr3_write_vmexit_value_get() noexcept
    {
        return 0;
    }

    void cr3_write_execute() noexcept
    {
        return;
    }

    void cr3_write_emulate(uint64_t cr3_value) noexcept
    {
        return;
    }

    intel_cr3() noexcept = default;
};

}

#endif
