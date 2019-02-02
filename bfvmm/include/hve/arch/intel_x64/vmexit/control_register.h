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

#ifndef VMEXIT_CONTROL_REGISTER_INTEL_X64_H
#define VMEXIT_CONTROL_REGISTER_INTEL_X64_H

#include <list>

#include <bfgsl.h>
#include <bfdelegate.h>

#include "../vmcs.h"

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

namespace bfvmm::intel_x64
{

class vcpu;

/// Control Register
///
/// Provides an interface for enabling/disabling exiting on control register
/// access. Users may supply handlers and specify shadow values (for CR0 and
/// CR4).
///
class control_register_handler
{
public:

    ///
    /// Info
    ///
    /// This struct is created by control_register_handler::handle before being
    /// passed to each registered handler.
    ///
    struct info_t {

        /// Value (in/out)
        ///
        /// The value the guest VM would like the CR to be, or'd with the
        /// fixed0 bits which the CR must be. This is the value that will be
        /// writen to the CR
        ///
        uint64_t val;

        /// Shadow (out)
        ///
        /// The value the guest VM would like the CR to be. This is the value
        /// that will be written to the shadow
        ///
        ///
        uint64_t shadow;

        /// Ignore write (out)
        ///
        /// If true, do not update the guest's register state. It is assumed
        /// the handler has already done this.
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
        delegate<bool(gsl::not_null<vcpu *>, info_t &)>;

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vcpu the vcpu object for this control register handler
    ///
    control_register_handler(
        gsl::not_null<vcpu *> vcpu);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~control_register_handler() = default;

public:

    /// Add Write CR0 Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the handler to call when an exit occurs
    ///
    void add_wrcr0_handler(const handler_delegate_t &d);

    /// Add Read CR3 Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the handler to call when an exit occurs
    ///
    void add_rdcr3_handler(const handler_delegate_t &d);

    /// Add Write CR3 Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the handler to call when an exit occurs
    ///
    void add_wrcr3_handler(const handler_delegate_t &d);

    /// Add Write CR4 Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the handler to call when an exit occurs
    ///
    void add_wrcr4_handler(const handler_delegate_t &d);

public:

    /// Enable Write CR0 Exiting
    ///
    /// Example:
    /// @code
    /// this->enable_wrcr0_exiting();
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    /// @param mask the value of the cr0 guest/host mask to set in the vmcs
    ///
    void enable_wrcr0_exiting(vmcs_n::value_type mask);

    /// Enable Read CR3 Exiting
    ///
    /// Example:
    /// @code
    /// this->enable_rdcr3_exiting();
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    void enable_rdcr3_exiting();

    /// Enable Write CR3 Exiting
    ///
    /// Example:
    /// @code
    /// this->enable_wrcr3_exiting();
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    void enable_wrcr3_exiting();

    /// Enable Write CR4 Exiting
    ///
    /// Example:
    /// @code
    /// this->enable_wrcr4_exiting();
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    /// @param mask the value of the cr4 guest/host mask to set in the vmcs
    ///
    void enable_wrcr4_exiting(vmcs_n::value_type mask);

    /// @cond

    bool handle(gsl::not_null<vcpu *> vcpu);

    /// @endcond

private:

    bool handle_cr0(gsl::not_null<vcpu *> vcpu);
    bool handle_cr3(gsl::not_null<vcpu *> vcpu);
    bool handle_cr4(gsl::not_null<vcpu *> vcpu);

    bool handle_wrcr0(gsl::not_null<vcpu *> vcpu);
    bool handle_rdcr3(gsl::not_null<vcpu *> vcpu);
    bool handle_wrcr3(gsl::not_null<vcpu *> vcpu);
    bool handle_wrcr4(gsl::not_null<vcpu *> vcpu);

private:

    vcpu *m_vcpu;

    std::list<handler_delegate_t> m_wrcr0_handlers;
    std::list<handler_delegate_t> m_rdcr3_handlers;
    std::list<handler_delegate_t> m_wrcr3_handlers;
    std::list<handler_delegate_t> m_wrcr4_handlers;

public:

    /// @cond

    control_register_handler(control_register_handler &&) = default;
    control_register_handler &operator=(control_register_handler &&) = default;

    control_register_handler(const control_register_handler &) = delete;
    control_register_handler &operator=(const control_register_handler &) = delete;

    /// @endcond
};

}

#endif
