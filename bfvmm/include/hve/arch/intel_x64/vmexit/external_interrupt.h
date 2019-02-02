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

#ifndef VMEXIT_EXTERNAL_INTERRUPT_INTEL_X64_H
#define VMEXIT_EXTERNAL_INTERRUPT_INTEL_X64_H

#include <list>

#include <bfgsl.h>
#include <bfdelegate.h>

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

namespace bfvmm::intel_x64
{

class vcpu;

/// External interrupt
///
/// Provides an interface for registering handlers for external-interrupt
/// exits.
///
class external_interrupt_handler
{
public:

    ///
    /// Info
    ///
    /// This struct is created by external_interrupt_handler::handle before being
    /// passed to each registered handler.
    ///
    struct info_t {

        /// Vector (in)
        ///
        /// The vector that caused the exit
        ///
        /// default: vmcs_n::vm_exit_interruption_information::vector
        ///
        uint64_t vector{0};
    };

    /// Handler delegate type
    ///
    /// The type of delegate clients must use when registering
    /// handlers
    ///
    using handler_delegate_t =
        delegate<bool(gsl::not_null<vcpu *>, info_t &)>;

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vcpu the vcpu object for this external-interrupt handler
    ///
    external_interrupt_handler(
        gsl::not_null<vcpu *> vcpu);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~external_interrupt_handler() = default;

public:

    /// Add Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the handler to call when an exit occurs
    ///
    void add_handler(const handler_delegate_t &d);

public:

    /// Enable exiting
    ///
    /// Example:
    /// @code
    /// this->enable_exiting();
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    void enable_exiting();

    /// Disable exiting
    ///
    /// Example:
    /// @code
    /// this->disable_exiting();
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    void disable_exiting();

public:

    /// @cond

    bool handle(gsl::not_null<vcpu *> vcpu);

    /// @endcond

private:

    vcpu *m_vcpu;
    std::list<handler_delegate_t> m_handlers;

public:

    /// @cond

    external_interrupt_handler(external_interrupt_handler &&) = default;
    external_interrupt_handler &operator=(external_interrupt_handler &&) = default;

    external_interrupt_handler(const external_interrupt_handler &) = delete;
    external_interrupt_handler &operator=(const external_interrupt_handler &) = delete;

    /// @endcond
};

}

#endif
