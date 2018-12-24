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

#ifndef VMEXIT_INIT_SIGNAL_INTEL_X64_H
#define VMEXIT_INIT_SIGNAL_INTEL_X64_H

#include <bfgsl.h>
#include <bfdelegate.h>

#include "wrmsr.h"

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

namespace bfvmm::intel_x64
{

class vcpu;

/// INIT signal
///
/// Provides an interface for registering handlers of the INIT signal exit.
///
class init_signal_handler
{
public:

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vcpu the vcpu object for this INIT signal handler
    ///
    init_signal_handler(
        gsl::not_null<vcpu *> vcpu);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~init_signal_handler() = default;

public:

    /// @cond

    bool handle(vcpu *vcpu);

    /// @endcond

private:

    vcpu *m_vcpu;

public:

    /// @cond

    init_signal_handler(init_signal_handler &&) = default;
    init_signal_handler &operator=(init_signal_handler &&) = default;

    init_signal_handler(const init_signal_handler &) = delete;
    init_signal_handler &operator=(const init_signal_handler &) = delete;

    /// @endcond
};

}

#endif
