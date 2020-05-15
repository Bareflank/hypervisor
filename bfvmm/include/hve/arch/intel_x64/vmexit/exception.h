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

#ifndef VMEXIT_EXCEPTION_INTEL_X64_H
#define VMEXIT_EXCEPTION_INTEL_X64_H

#include <list>
#include <unordered_map>

#include <bfgsl.h>
#include <bfdelegate.h>

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

namespace bfvmm::intel_x64
{

class vcpu;

/// Exceptions
///
/// Provides an interface for registering handlers for exception
/// exits.
///
class exception_handler
{
public:

    ///
    /// Info
    ///
    /// This struct is created by exception_handler::handle before being
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
        delegate<bool(vcpu *, info_t &)>;

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vcpu the vcpu object for this exception handler
    ///
    exception_handler(
        gsl::not_null<vcpu *> vcpu);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~exception_handler() = default;

public:

    /// Add Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vector the exception vector to enable
    /// @param d the handler to call when an exit occurs
    ///
    void add_handler(vmcs_n::value_type vector, const handler_delegate_t &d);

public:

    /// @cond

    bool handle(vcpu *vcpu);

    /// @endcond

private:

    vcpu *m_vcpu;
    std::unordered_map<vmcs_n::value_type, std::list<handler_delegate_t>> m_handlers;

public:

    /// @cond

    exception_handler(exception_handler &&) = default;
    exception_handler &operator=(exception_handler &&) = default;

    exception_handler(const exception_handler &) = delete;
    exception_handler &operator=(const exception_handler &) = delete;

    /// @endcond
};

using exception_handler_delegate_t = exception_handler::handler_delegate_t;

}

#endif
