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

#ifndef VMEXIT_CPUID_INTEL_X64_H
#define VMEXIT_CPUID_INTEL_X64_H

#include <unordered_map>

#include <bfgsl.h>
#include <bfdelegate.h>

#include "../exit_handler.h"

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

namespace bfvmm::intel_x64
{

class vcpu;

/// CPUID
///
/// Provides an interface for registering handlers for cpuid exits
/// at a given (leaf, subleaf).
///
class cpuid_handler
{
public:

    /// Leaf type
    ///
    ///
    using leaf_t = uint64_t;

    /// Info
    ///
    /// This struct is created by cpuid_handler::handle before being
    /// passed to each registered handler.
    ///
    struct info_t {

        /// RAX (in/out)
        ///
        uint64_t rax;

        /// RBX (in/out)
        ///
        uint64_t rbx;

        /// RCX (in/out)
        ///
        uint64_t rcx;

        /// RDX (in/out)
        ///
        uint64_t rdx;

        /// Ignore write (out)
        ///
        /// If true, do not update the guest's register state with the four
        /// register values above. Set this to true if you do not want the guest
        /// rax, rbx, rcx, or rdx to be written to after your handler completes.
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
    /// @param vcpu the vcpu object for this cpuid_handler
    ///
    cpuid_handler(
        gsl::not_null<vcpu *> vcpu);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~cpuid_handler() = default;

public:

    /// Add Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param leaf the cpuid leaf to call d
    /// @param d the handler to call when an exit occurs
    ///
    void add_handler(leaf_t leaf, const handler_delegate_t &d);

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
    /// @param leaf the address to emulate
    ///
    void emulate(leaf_t leaf);

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

    /// @cond

    bool handle(gsl::not_null<vcpu *> vcpu);

    /// @endcond

private:

    vcpu *m_vcpu;

    ::handler_delegate_t m_default_handler;
    std::unordered_map<leaf_t, bool> m_emulate;
    std::unordered_map<leaf_t, std::list<handler_delegate_t>> m_handlers;

public:

    /// @cond

    cpuid_handler(cpuid_handler &&) = default;
    cpuid_handler &operator=(cpuid_handler &&) = default;

    cpuid_handler(const cpuid_handler &) = delete;
    cpuid_handler &operator=(const cpuid_handler &) = delete;

    /// @endcond
};

}

#endif
