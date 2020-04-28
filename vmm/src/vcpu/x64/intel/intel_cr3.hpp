#ifndef VMM_VCPU_X64_INTEL_CR3_HPP
#define VMM_VCPU_X64_INTEL_CR3_HPP

#include <vmm/vcpu/x64/cr3.hpp>

namespace vmm
{

class intel_cr3 :
    public cr3
{
public:

    void enable_cr3_read_vmexit() noexcept
    {
        return;
    }

    void disable_cr3_read_vmexit() noexcept
    {
        return;
    }

    void set_cr3_read_vmexit_handler(x64_vcpu_delegate func)
    {
        return;
    }

    void execute_cr3_read() noexcept
    {
        return;
    }

    void emulate_cr3_read(uint64_t cr3_value) noexcept
    {
        return;
    }

    void enable_cr3_write_vmexit() noexcept
    {
        return;
    }

    void disable_cr3_write_vmexit() noexcept
    {
        return;
    }

    void set_cr3_write_vmexit_handler(x64_vcpu_delegate func)
    {
        return;
    }

    uint64_t get_cr3_write_vmexit_value() noexcept
    {
        return 0;
    }

    void execute_cr3_write() noexcept
    {
        return;
    }

    void emulate_cr3_write(uint64_t cr3_value) noexcept
    {
        return;
    }

    intel_cr3() noexcept = default;
};

}

#endif
