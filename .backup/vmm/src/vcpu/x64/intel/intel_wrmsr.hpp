#ifndef VMM_VCPU_X64_INTEL_WRMSR_HPP
#define VMM_VCPU_X64_INTEL_WRMSR_HPP

#include <vmm/vcpu/x64/wrmsr.hpp>

namespace vmm
{

class intel_wrmsr :
    public wrmsr
{
public:

    void enable_wrmsr_vmexit(uint32_t msr_address) noexcept
    {
        // TODO: Implement Me!
        return;
    }

    void enable_wrmsr_vmexit_range(uint32_t begin, uint32_t end) noexcept
    {
        // TODO: Implement Me!
        return;
    }

    void disable_wrmsr_vmexit(uint32_t msr_address) noexcept
    {
        // TODO: Implement Me!
        return;
    }

    void disable_wrmsr_vmexit_range(uint32_t begin, uint32_t end) noexcept
    {
        // TODO: Implement Me!
        return;
    }

    void set_wrmsr_vmexit_handler(x64_vcpu_delegate func) noexcept
    {
        // TODO: Implement Me!
        return;
    }

    uint32_t get_wrmsr_vmexit_address() noexcept
    {
        // TODO: Implement Me!
        return 0;
    }

    uint64_t get_wrmsr_vmexit_value() noexcept
    {
        // TODO: Implement Me!
        return 0;
    }

    void execute_wrmsr() noexcept
    {
        // TODO: Implement Me!
        return;
    }

    void emulate_wrmsr(uint64_t value) noexcept
    {
        // TODO: Implement Me!
        return;
    }

    intel_wrmsr() noexcept = default;
};

}

#endif
