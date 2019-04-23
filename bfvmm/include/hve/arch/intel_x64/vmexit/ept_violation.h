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

#ifndef VMEXIT_EPT_VIOLATION_INTEL_X64_H
#define VMEXIT_EPT_VIOLATION_INTEL_X64_H

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

/// EPT Violation
///
/// Provides an interface for registering handlers for EPT violation
/// exits.
///
class ept_violation_handler
{
public:

    ///
    /// Info
    ///
    /// This struct is created by ept_violation_handler::handle before being
    /// passed to each registered handler.
    ///
    struct info_t {

        /// GVA (in)
        ///
        /// The guest virtual (linear) address that caused the exit
        ///
        uint64_t gva;

        /// GPA (in)
        ///
        /// The guest physical address that caused the exit
        ///
        uint64_t gpa;

        /// Exit qualification (in)
        ///
        /// The VMCS exit qualification that caused the exit
        ///
        uint64_t exit_qualification;

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
    /// @param vcpu the vcpu object for this EPT violation handler
    ///
    ept_violation_handler(
        gsl::not_null<vcpu *> vcpu);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~ept_violation_handler() = default;

public:

    /// Add Read EPT Violation Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the handler to call when an exit occurs
    ///
    void add_read_handler(const handler_delegate_t &d);

    /// Add Write EPT Violation Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the handler to call when an exit occurs
    ///
    void add_write_handler(const handler_delegate_t &d);

    /// Add Execute EPT Violation Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the handler to call when an exit occurs
    ///
    void add_execute_handler(const handler_delegate_t &d);

    /// Add Default Read Handler
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
    void set_default_read_handler(const ::handler_delegate_t &d);

    /// Add Default Write Handler
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
    void set_default_write_handler(const ::handler_delegate_t &d);

    /// Add Default Execute Handler
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
    void set_default_execute_handler(const ::handler_delegate_t &d);

public:

    /// @cond

    bool handle(vcpu *vcpu);

    /// @endcond

private:

    bool handle_read(vcpu *vcpu, info_t &info);
    bool handle_write(vcpu *vcpu, info_t &info);
    bool handle_execute(vcpu *vcpu, info_t &info);

private:

    vcpu *m_vcpu;

    ::handler_delegate_t m_default_read_handler{};
    ::handler_delegate_t m_default_write_handler{};
    ::handler_delegate_t m_default_execute_handler{};

    std::list<handler_delegate_t> m_read_handlers;
    std::list<handler_delegate_t> m_write_handlers;
    std::list<handler_delegate_t> m_execute_handlers;

public:

    /// @cond

    ept_violation_handler(ept_violation_handler &&) = default;
    ept_violation_handler &operator=(ept_violation_handler &&) = default;

    ept_violation_handler(const ept_violation_handler &) = delete;
    ept_violation_handler &operator=(const ept_violation_handler &) = delete;

    /// @endcond
};

using ept_violation_handler_delegate_t = ept_violation_handler::handler_delegate_t;

}

#endif
