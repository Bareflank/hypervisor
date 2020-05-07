#ifndef VMM_VCPU_X64_IO_PORT_HPP
#define VMM_VCPU_X64_IO_PORT_HPP

#include <vmm/vcpu/x64/x64_vcpu_delegate.hpp>

namespace vmm
{

class io_port
{
public:

    /// @brief Enable vmexits for io port accesses at the specified port number
    ///     during vcpu execution. 
    ///
    /// @param port_number The port number to enable vmexits for
    virtual void enable_io_port_vmexit(uint16_t port_number) noexcept = 0;

    /// @brief Enable vmexits for a range of io port accesses with port numbers
    ///     from @param begin to @param end (inclusive) during vcpu execution. 
    ///
    /// @expects begin <= end
    ///
    /// @param begin The lower bound of port numbers to enable vmexits for
    /// @param end The upper bound of port numbers to enable vmexits for
    virtual void enable_io_port_vmexit_range(uint16_t begin, uint16_t end) noexcept = 0;

    /// @brief Disable vmexits for io port accesses at the specified port number
    ///     during vcpu execution. 
    ///
    /// @param port_number The port number to disable vmexits for
    virtual void disable_io_port_vmexit(uint16_t port_number) noexcept = 0;

    /// @brief Disable vmexits for a range of io port accesses with port numbers
    ///     from @param begin to @param end (inclusive) during vcpu execution. 
    ///
    /// @expects begin <= end
    ///
    /// @param begin The lower bound of port numbers to enable vmexits for
    /// @param end The upper bound of port numbers to enable vmexits for
    virtual void disable_io_port_vmexit_range(uint16_t begin, uint16_t end) noexcept = 0;

    /// @brief Set a vmexit handler that will be called for all vmexits caused
    ///     by an io port access while a vcpu is executing.
    ///
    /// @param func The delegate function to be called
    virtual void set_io_port_vmexit_handler(x64_vcpu_delegate func) noexcept = 0;

    /// @brief Returns the size of the value being read in or written out to an
    ///     io port, that caused a vmexit to occur while a vcpu was executing
    ///
    /// @return The size (in bytes) of the value read in from or written to an
    ///     io port when a vmexit occurred
    virtual uint64_t get_io_port_vmexit_size() noexcept = 0;

    /// @brief Returns true if the current vmexit execution context was
    ///     triggered as a result of an "in" operation from an io port
    ///
    /// @return True if io port in caused the current vmexit, else false
    virtual bool is_io_port_vmexit_in() noexcept = 0;

    /// @brief Returns true if the current vmexit execution context was
    ///     triggered as a result of an "out" operation to an io port
    ///
    /// @return True if io port out caused the current vmexit, else false
    virtual bool is_io_port_vmexit_out() noexcept = 0;

    /// @brief Returns the port number of an io instruction that caused a
    ///     vmexit to occur while a vcpu was executing
    ///
    /// @return The io port number that caused a vmexit to occur
    virtual uint16_t get_io_port_vmexit_port_number() noexcept = 0;

    /// @brief Returns the value being read in from or written out to an io
    ///     port, that caused a vmexit to occur while a vcpu was executing
    ///
    /// @return The value read in from or written out to an io port when a
    ///     vmexit occurred
    virtual uint64_t get_io_port_vmexit_value() noexcept = 0;

    /// @brief Execute (on the vcpu) an out to an io port that caused a vmexit
    ///     to occur, using the vcpu's registers as the source registers for
    ///     the operation. This allows a user defined vm exit handler to pass
    ///     through an out to an io port from a vcpu.
    virtual void execute_io_port_out() noexcept = 0;

    /// @brief Emulate an out to an io port that caused a vmexit to occur
    ///     while a vcpu was executing. The given value is written to the
    ///     io port (at the vmexit port number) instead of the value
    ///     that caused the vmexit to occur. 
    ///
    /// @param value The value to be written to the io port
    virtual void emulate_io_port_out(uint64_t value) noexcept = 0;

    /// @brief Execute (on the vcpu) an in from an io port that caused a vmexit
    ///     to occur, using the vcpu's registers as the destination registers
    ///     for the operation. This allows a user defined vm exit handler to
    ///     pass through an in to an io port from a vcpu.
    virtual void execute_io_port_in() noexcept = 0;

    /// @brief Emulate an in from an io port that caused a vmexit to occur
    ///     while a vcpu was executing. The given value is placed into the
    ///     vcpu's destination register, instead of the value at the physical
    ///     io port number.
    ///
    /// @param value The value to be emulated as read in from an io port
    virtual void emulate_io_port_in(uint64_t value) noexcept = 0;

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
