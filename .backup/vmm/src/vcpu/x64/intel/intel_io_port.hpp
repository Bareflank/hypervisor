#ifndef VMM_VCPU_X64_INTEL_IO_PORT_HPP
#define VMM_VCPU_X64_INTEL_IO_PORT_HPP

#include <vmm/vcpu/x64/io_port.hpp>

namespace vmm
{

class intel_io_port :
    public io_port
{
public:

    void enable_io_port_vmexit(uint16_t port_number) noexcept
    {
        // TODO: Implement Me!
        return;
    }

    void enable_io_port_vmexit_range(uint16_t begin, uint16_t end) noexcept
    {
        // TODO: Implement Me!
        return;
    }

    void disable_io_port_vmexit(uint16_t port_number) noexcept
    {
        // TODO: Implement Me!
        return;
    }

    void disable_io_port_vmexit_range(uint16_t begin, uint16_t end) noexcept
    {
        // TODO: Implement Me!
        return;
    }

    void set_io_port_vmexit_handler(x64_vcpu_delegate func) noexcept
    {
        // TODO: Implement Me!
        return;
    }

    uint64_t get_io_port_vmexit_size() noexcept
    {
        // TODO: Implement Me!
        return 0;
    }

    bool is_io_port_vmexit_in() noexcept
    {
        // TODO: Implement Me!
        return false;
    }

    bool is_io_port_vmexit_out() noexcept
    {
        // TODO: Implement Me!
        return false;
    }

    uint16_t get_io_port_vmexit_port_number() noexcept
    {
        // TODO: Implement Me!
        return 0;
    }

    uint64_t get_io_port_vmexit_value() noexcept
    {
        // TODO: Implement Me!
        return 0;
    }

    void execute_io_port_out() noexcept
    {
        // TODO: Implement Me!
        return;
    }

    void emulate_io_port_out(uint64_t value) noexcept
    {
        // TODO: Implement Me!
        return;
    }

    void execute_io_port_in() noexcept
    {
        // TODO: Implement Me!
        return;
    }

    void emulate_io_port_in(uint64_t value) noexcept
    {
        // TODO: Implement Me!
        return;
    }

    intel_io_port() noexcept = default;
};

}

#endif
