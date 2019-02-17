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

#ifndef BFVMM_DELEGATOR_CPUID_INTEL_X64_H
#define BFVMM_DELEGATOR_CPUID_INTEL_X64_H

#include <stdint.h>
#include <bfdelegate.h>
#include <bfgsl.h>
#include <unordered_map>
#include <list>

#include "../../../../vmm_types.h"

// -----------------------------------------------------------------------------
// Exports
// -----------------------------------------------------------------------------

#include <bfexports.h>

#ifndef STATIC_HVE
#ifdef SHARED_HVE
#define EXPORT_HVE EXPORT_SYM
#else
#define EXPORT_HVE IMPORT_SYM
#endif
#else
#define EXPORT_HVE
#endif

namespace bfvmm::intel_x64::cpuid
{

/// CPUID leaf data type
///
///
using leaf_t = uint64_t;

/// Info
///
/// This struct is created by cpuid::delegator::handle before being
/// passed to each registered handler.
///
struct info_t {

    /// Leaf (in)
    ///
    /// The CPUID leaf (eax) that caused a vmexit
    ///
    leaf_t leaf;

    /// Subleaf (in)
    ///
    /// The CPUID subleaf (ecx) that caused a vmexit
    ///
    leaf_t subleaf;

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

using delegate_t = delegate<bool(vcpu_t, info_t &)>;

/// CPUID delegator
///
/// Delegates processing of CPUID based vmexits to registered handlers
///
class EXPORT_HVE delegator
{

public:

    /// Default Constructor
    ///
    /// @expects none
    /// @ensures none
    ///
    delegator();

    /// Destructor
    ///
    /// @expects none
    /// @ensures none
    ///
    ~delegator() = default;

    /// Add handler
    ///
    /// Add a handler for a CPUID based vmexit for the given CPUID leaf
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param leaf The CPUID leaf to handle
    /// @param d The handler delegate to register
    ///
    void add_handler(leaf_t leaf, const delegate_t &d);

    /// Handle
    ///
    /// Handle a vmexit using registered handlers
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param vcpu The vcpu the vmexit occurred on
    ///
    /// @return True if the vmexit was successfully handled, false otherwise
    ///
    bool handle(vcpu_t vcpu);

private:

    std::unordered_map<cpuid::leaf_t, std::list<cpuid::delegate_t>> m_handlers;
    cpuid::delegate_t m_default_handler;

public:

    /// @cond

    delegator(delegator &&) = default;
    delegator &operator=(delegator &&) = default;

    delegator(const delegator &) = delete;
    delegator &operator=(const delegator &) = delete;

    /// @endcond
};

}

#endif
