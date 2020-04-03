#ifndef VMM_VCPU_X64_IO_PORT_HPP
#define VMM_VCPU_X64_IO_PORT_HPP

#include <bsl/errc_type.hpp>

namespace vmm
{

class io_port
{
public:

    /// @brief Enable vmexits for io port accesses at the specified port number
    ///     during vcpu execution. 
    ///
    /// @param port_number The port number to enable vmexits for
    virtual void io_port_vmexit_enable(uint16_t port_number) noexcept = 0;

    /// @brief Enable vmexits for a range of io port accesses with port numbers
    ///     from @param begin to @param end (inclusive) during vcpu execution. 
    ///
    /// @expects begin <= end
    ///
    /// @param begin The lower bound of port numbers to enable vmexits for
    /// @param end The upper bound of port numbers to enable vmexits for
    virtual void io_port_vmexit_range_enable(uint16_t begin, uint16_t end) noexcept = 0;

    /// @brief Disable vmexits for io port accesses at the specified port number
    ///     during vcpu execution. 
    ///
    /// @param port_number The port number to disable vmexits for
    virtual void io_port_vmexit_disable(uint16_t port_number) noexcept = 0;

    /// @brief Disable vmexits for a range of io port accesses with port numbers
    ///     from @param begin to @param end (inclusive) during vcpu execution. 
    ///
    /// @expects begin <= end
    ///
    /// @param begin The lower bound of port numbers to enable vmexits for
    /// @param end The upper bound of port numbers to enable vmexits for
    virtual void io_port_vmexit_range_disable(uint16_t begin, uint16_t end) noexcept = 0;

    /// @brief Set a vmexit handler that will be called for all vmexits caused
    ///     by an io port access while a vcpu is executing.
    ///
    /// @param func The delegate function to be called
    virtual void io_port_vmexit_handler_set(bsl::delegate<void (x64_vcpu &)> func) noexcept = 0;

    /// @brief Returns the size of the value being read from or written to an
    ///     io port, that caused a vmexit to occur while a vcpu was executing
    ///
    /// @return The size (in bytes) of the value read from or written to an io
    ///     port when a vmexit occurred
    virtual uint64_t io_port_vmexit_size() noexcept = 0;

    /// @brief Returns true if the current vmexit execution context was
    ///     triggered as a result of a read operation from an io port
    ///
    /// @return True if io port read caused the current vmexit, else false
    virtual bool io_port_vmexit_is_read() noexcept = 0;

    /// @brief Returns true if the current vmexit execution context was
    ///     triggered as a result of a write operation to an io port
    ///
    /// @return True if io port write caused the current vmexit, else false
    virtual bool io_port_vmexit_is_write() noexcept = 0;

    /// @brief Returns the port number of an io instruction that caused a
    ///     vmexit to occur while a vcpu was executing
    ///
    /// @return The io port number that caused a vmexit to occur
    virtual uint16_t io_port_vmexit_port_number() noexcept = 0;

    /// @brief Returns the value being read from or written to an io port, that
    ///     caused a vmexit to occur while a vcpu was executing
    ///
    /// @return The value read from or written to an io port when a vmexit
    ///     occurred
    virtual uint64_t io_port_vmexit_value() noexcept = 0;

    /// @brief Execute (on the vcpu) a write to an io port that caused a vmexit
    ///     to occur, using the vcpu's registers as the source registers for
    ///     the operation. This allows a user defined vm exit handler to pass
    ///     through a write to an io port from a vcpu.
    virtual void write_io_port_execute() noexcept = 0;

    /// @brief Emulate a write to an io port that caused a vmexit to occur
    ///     while a vcpu was executing. The given value is written to the
    ///     to the io port (at the vmexit port number) instead of the value
    ///     that caused the vmexit to occur. 
    ///
    /// @param value The value to be written to the io port
    virtual void write_io_port_emulate(uint64_t value) noexcept = 0;

    /// @brief Execute (on the vcpu) a read from an io port that caused a vmexit
    ///     to occur, using the vcpu's registers as the destination registers
    ///     for the operation. This allows a user defined vm exit handler to
    ///     pass through a read to an io port from a vcpu.
    virtual void read_io_port_execute() noexcept = 0;

    /// @brief Emulate a read from an io port that caused a vmexit to occur
    ///     while a vcpu was executing. The given value is read into the
    ///     vcpu's destination register, instead of the value at the physical
    ///     io port number.
    ///
    /// @param value The value to be emulated as a read from an io port
    virtual void read_io_port_emulate(uint64_t value) noexcept = 0;

    virtual ~io_port() noexcept = default;
protected:
    io_port() noexcept = default;
    io_port(io_port &&) noexcept = default;
    io_port &operator=(io_port &&) noexcept = default;
    io_port(io_port const &) = delete;
    io_port &operator=(io_port const &) & = delete;
};

}

#endif
