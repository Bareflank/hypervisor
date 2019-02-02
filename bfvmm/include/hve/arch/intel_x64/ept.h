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

#ifndef EPT_HANDLER_INTEL_X64_H
#define EPT_HANDLER_INTEL_X64_H

#include "ept/mmap.h"
#include "ept/helpers.h"

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

namespace bfvmm::intel_x64
{

class vcpu;

/// EPT
///
/// Provides an interface for enabling EPT
///
class ept_handler
{
public:

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vcpu the vcpu object for this rdmsr handler
    ///
    ept_handler(
        gsl::not_null<vcpu *> vcpu);


    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~ept_handler() = default;

    /// Set EPTP
    ///
    /// @expects
    /// @ensures
    ///
    /// @param map A pointer to the map to set EPTP to. If the pointer is
    ///     a nullptr, EPT is disabled.
    ///
    void set_eptp(ept::mmap *map);

private:

    vcpu *m_vcpu;

public:

    /// @cond

    ept_handler(ept_handler &&) = default;
    ept_handler &operator=(ept_handler &&) = default;

    ept_handler(const ept_handler &) = delete;
    ept_handler &operator=(const ept_handler &) = delete;

    /// @endcond
};

}

#endif
