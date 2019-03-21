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

#ifndef VMEXIT_MONITOR_TRAP_INTEL_X64_H
#define VMEXIT_MONITOR_TRAP_INTEL_X64_H

#include <list>

#include <bfgsl.h>
#include <bfdelegate.h>

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

namespace bfvmm::intel_x64
{

class vcpu;

/// Monitor Trap
///
/// Provides an interface for registering handlers for monitor-trap flag
/// exits.
///
class monitor_trap_handler
{
public:

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vcpu the vcpu object for this monitor trap handler
    ///
    monitor_trap_handler(
        gsl::not_null<vcpu *> vcpu);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~monitor_trap_handler() = default;

public:

    /// Add Monitor Trap Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the handler to call when an exit occurs
    ///
    void add_handler(const ::handler_delegate_t &d);

    /// Enable
    ///
    /// Example:
    /// @code
    /// this->enable();
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    void enable();

public:

    /// @cond

    bool handle(vcpu *vcpu);

    /// @endcond

private:

    vcpu *m_vcpu;
    std::list<::handler_delegate_t> m_handlers;

public:

    /// @cond

    monitor_trap_handler(monitor_trap_handler &&) = default;
    monitor_trap_handler &operator=(monitor_trap_handler &&) = default;

    monitor_trap_handler(const monitor_trap_handler &) = delete;
    monitor_trap_handler &operator=(const monitor_trap_handler &) = delete;

    /// @endcond
};

}

#endif
