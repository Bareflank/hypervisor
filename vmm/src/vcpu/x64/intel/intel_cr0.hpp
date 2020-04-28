#ifndef VMM_VCPU_X64_INTEL_CR0_HPP
#define VMM_VCPU_X64_INTEL_CR0_HPP

#include <vmm/vcpu/x64/cr0.hpp>

namespace vmm
{

class intel_cr0 :
    public cr0
{
public:

    void enable_cr0_write_vmexit() noexcept
    {
        // TODO: Implement Me!
        return;
    }

    void disable_cr0_write_vmexit() noexcept
    {
        // TODO: Implement Me!
        return;
    }

    void set_cr0_write_vmexit_handler(x64_vcpu_delegate func)
    {
        // TODO: Implement Me!
        return;
    }

    uint64_t get_cr0_write_vmexit_value() noexcept
    {
        // TODO: Implement Me!
        return 0;
    }

    void execute_cr0_write() noexcept
    {
        // TODO: Implement Me!
        return;
    }

    void emulate_cr0_write(uint64_t cr0_value) noexcept
    {
        // TODO: Implement Me!
        return;
    }

    intel_cr0() noexcept = default;
};

}

#endif
