#ifndef VMM_VCPU_X64_INTEL_CR4_HPP
#define VMM_VCPU_X64_INTEL_CR4_HPP

#include <vmm/vcpu/x64/cr4.hpp>

namespace vmm
{

class intel_cr4 :
    public cr4
{
public:

    void enable_cr4_write_vmexit() noexcept
    {
        return;
    }

    void disable_cr4_write_vmexit() noexcept
    {
        return;
    }

    void set_cr4_write_vmexit_handler(x64_vcpu_delegate func)
    {
        return;
    }

    uint64_t get_cr4_write_vmexit_value() noexcept
    {
        return 0;
    }

    void execute_cr4_write() noexcept
    {
        return;
    }

    void emulate_cr4_write(uint64_t cr4_value) noexcept
    {
        return;
    }

    intel_cr4() noexcept = default;
};

}

#endif
