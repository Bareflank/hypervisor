#ifndef VMM_VCPU_X64_INTEL_IO_PORT_HPP
#define VMM_VCPU_X64_INTEL_IO_PORT_HPP

#include <vmm/vcpu/x64/io_port.hpp>

namespace vmm
{

class intel_io_port :
    public io_port
{
public:

    void io_port_vmexit_enable(uint16_t port_number) noexcept
    {
        // TODO: Implement Me!
        return;
    }

    void io_port_vmexit_range_enable(uint16_t begin, uint16_t end) noexcept
    {
        // TODO: Implement Me!
        return;
    }

    void io_port_vmexit_disable(uint16_t port_number) noexcept
    {
        // TODO: Implement Me!
        return;
    }

    void io_port_vmexit_range_disable(uint16_t begin, uint16_t end) noexcept
    {
        // TODO: Implement Me!
        return;
    }

    void io_port_vmexit_handler_set(x64_vcpu_delegate func) noexcept
    {
        // TODO: Implement Me!
        return;
    }

    uint64_t io_port_vmexit_size_get() noexcept
    {
        // TODO: Implement Me!
        return 0;
    }

    bool io_port_vmexit_is_read() noexcept
    {
        // TODO: Implement Me!
        return false;
    }

    bool io_port_vmexit_is_write() noexcept
    {
        // TODO: Implement Me!
        return false;
    }

    uint16_t io_port_vmexit_port_number_get() noexcept
    {
        // TODO: Implement Me!
        return 0;
    }

    uint64_t io_port_vmexit_value_get() noexcept
    {
        // TODO: Implement Me!
        return 0;
    }

    void write_io_port_execute() noexcept
    {
        // TODO: Implement Me!
        return;
    }

    void write_io_port_emulate(uint64_t value) noexcept
    {
        // TODO: Implement Me!
        return;
    }

    void read_io_port_execute() noexcept
    {
        // TODO: Implement Me!
        return;
    }

    void read_io_port_emulate(uint64_t value) noexcept
    {
        // TODO: Implement Me!
        return;
    }

    intel_io_port() noexcept = default;
};

}

#endif
