//
// Copyright (C) 2019 Assured Information Security, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#ifndef VMEXIT_IO_INSTRUCTION_INTEL_X64_H
#define VMEXIT_IO_INSTRUCTION_INTEL_X64_H

#include <list>

#include <bfgsl.h>
#include <bfdelegate.h>

#include "../exit_handler.h"

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

namespace bfvmm::intel_x64
{

class vcpu;

/// IO instruction
///
/// Provides an interface for handling port I/O exits base on the port number
///
class io_instruction_handler
{
public:

    ///
    /// Info
    ///
    /// This struct is created by io_instruction_handler::handle before being
    /// passed to each registered handler. Note that default values are
    /// given for each field below (these are the values contained in the
    /// info struct that is passed to each handler).
    ///
    struct info_t {

        /// Port number
        ///
        /// The port number accessed by the guest.
        ///
        /// default: (rdx & 0xFFFF) if operand encoding == dx
        /// default: vmcs_n::exit_qualification::io_instruction::port_number if
        ///          operand encoding != dx
        ///
        uint64_t port_number;

        /// Size of access
        ///
        /// The size of the accessed operand.
        ///
        /// default: vmcs_n::exit_qualification::io_instruction::size_of_access
        ///
        uint64_t size_of_access;

        /// Address
        ///
        /// For accesses via string instructions, the guest linear address.
        ///
        /// default: vmcs_n::guest_linear_address
        ///
        uint64_t address;

        /// Value
        ///
        /// The value from the port
        ///
        /// default: inb(info.port_number) if 'in' access
        /// default: the value from guest memory at info.address if 'out' access
        ///
        uint64_t val;

        /// Ignore write (out)
        ///
        /// - For 'in' accesses, do not update the guest's memory at info.address with
        ///   info.val if this field is true. Set this to true if your handler
        ///   returns true and has already updated the guest's memory.
        ///
        /// - For 'out' accesses, do not write info.val to the port info.port_number
        ///   if this field is true. Set this to true if your handler
        ///   returns true and has written to the guest's port
        ///
        /// default: false
        ///
        bool ignore_write;

        /// Ignore advance (out)
        ///
        /// If true, do not advance the guest's instruction pointer.
        /// Set this to true if your handler returns true and has already
        /// advanced the guest's instruction pointer.
        ///
        /// default: false
        ///
        bool ignore_advance;
    };

    /// Handler delegate type
    ///
    /// The type of delegate clients must use when registering
    /// handlers
    ///
    using handler_delegate_t =
        delegate<bool(vcpu *, info_t &)>;

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vcpu the vcpu object for this io instruction handler
    ///
    io_instruction_handler(
        gsl::not_null<vcpu *> vcpu);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~io_instruction_handler() = default;

public:

    /// Add Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param port the port to listen to
    /// @param in_d the handler to call when an in exit occurs
    /// @param out_d the handler to call when an out exit occurs
    ///
    void add_handler(
        vmcs_n::value_type port,
        const handler_delegate_t &in_d,
        const handler_delegate_t &out_d
    );

    /// Emulate
    ///
    /// Prevents the APIs from talking to physical hardware which means that
    /// no reads or writes are happening with the actual hardware, and
    /// everything must be emulated. This should be used for guests to
    /// prevent guest operations from leaking to the host.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param port the address to ignore
    ///
    void emulate(vmcs_n::value_type port);

    /// Add Default Handler
    ///
    /// This is called when no registered handlers have been called and
    /// the internal implementation is needed. Note that this function
    /// can still return false and let the internal implementation pass
    /// the instruction through
    ///
    /// Also note that the handler registered here is a base exit handler
    /// delegate. The info structure is not passed, and therefor,
    /// no emulation is provided to this handler.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the handler to call when an exit occurs
    ///
    void set_default_handler(const ::handler_delegate_t &d);

public:

    /// Trap On Access
    ///
    /// Sets a '1' in the IO bitmap corresponding with the provided port. All
    /// attempts made by the guest to read from the provided port will
    /// trap to hypervisor.
    ///
    /// Example:
    /// @code
    /// this->trap_on_port_access(0x42);
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    /// @param port the port to trap on
    ///
    void trap_on_access(vmcs_n::value_type port);

    /// Trap On All Accesses
    ///
    /// Sets a '1' in the IO bitmap corresponding with all of the ports. All
    /// attempts made by the guest to read from any port will
    /// trap to hypervisor.
    ///
    /// Example:
    /// @code
    /// this->trap_on_all_accesses();
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    void trap_on_all_accesses();

    /// Pass Through Access
    ///
    /// Sets a '0' in the IO bitmap corresponding with the provided port. All
    /// attempts made by the guest to read from the provided port will be
    /// executed by the guest and will not trap to the hypervisor.
    ///
    /// Example:
    /// @code
    /// this->pass_through_access(0x42);
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    /// @param port the port to pass through
    ///
    void pass_through_access(vmcs_n::value_type port);

    /// Pass Through All Access
    ///
    /// Sets a '0' in the IO bitmap corresponding with all of the ports. All
    /// attempts made by the guest to read from any port will be
    /// executed by the guest and will not trap to the hypervisor.
    ///
    /// Example:
    /// @code
    /// this->pass_through_all_accesses();
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    void pass_through_all_accesses();

public:

    /// @cond

    bool handle(vcpu *vcpu);

    /// @endcond

private:

    bool handle_in(vcpu *vcpu, info_t &info);
    bool handle_out(vcpu *vcpu, info_t &info);

    void emulate_in(info_t &info);
    void emulate_out(info_t &info);

    void load_operand(vcpu *vcpu, info_t &info);
    void store_operand(vcpu *vcpu, info_t &info);

private:

    vcpu *m_vcpu;

    gsl::span<uint8_t> m_io_bitmap_a;
    gsl::span<uint8_t> m_io_bitmap_b;

    ::handler_delegate_t m_default_handler{};
    std::unordered_map<vmcs_n::value_type, bool> m_emulate;
    std::unordered_map<vmcs_n::value_type, std::list<handler_delegate_t>> m_in_handlers;
    std::unordered_map<vmcs_n::value_type, std::list<handler_delegate_t>> m_out_handlers;

public:

    /// @cond

    io_instruction_handler(io_instruction_handler &&) = default;
    io_instruction_handler &operator=(io_instruction_handler &&) = default;

    io_instruction_handler(const io_instruction_handler &) = delete;
    io_instruction_handler &operator=(const io_instruction_handler &) = delete;

    /// @endcond
};

using io_instruction_handler_delegate_t = io_instruction_handler::handler_delegate_t;

}

#endif
