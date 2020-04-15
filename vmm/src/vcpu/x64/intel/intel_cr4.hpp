#ifndef VMM_VCPU_X64_INTEL_CR4_HPP
#define VMM_VCPU_X64_INTEL_CR4_HPP

#include <vmm/vcpu/x64/cr4.hpp>

namespace vmm
{

class intel_cr4 :
    public cr4
{
public:

    void write_cr4_vmexit_enable() noexcept
    {
        return;
    }

    void write_cr4_vmexit_disable() noexcept
    {
        return;
    }

    void write_cr4_vmexit_handler_set(bsl::delegate<void (x64_vcpu &)> func)
    {
        return;
    }

    uint64_t write_cr4_vmexit_value() noexcept
    {
        return 0;
    }

    void write_cr4_execute() noexcept
    {
        return;
    }

    void write_cr4_emulate(uint64_t cr4_value) noexcept
    {
        return;
    }

    intel_cr4() noexcept = default;
};

}

#endif
