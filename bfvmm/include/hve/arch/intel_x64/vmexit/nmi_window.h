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

#ifndef VMEXIT_NMI_WINDOW_HANDLER_INTEL_X64_H
#define VMEXIT_NMI_WINDOW_HANDLER_INTEL_X64_H

#include <bfgsl.h>
#include <bfdelegate.h>

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

namespace bfvmm::intel_x64
{

class vcpu;

/// NMI window
///
class nmi_window_handler
{
public:

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vcpu the vcpu object for this interrupt window handler
    ///
    nmi_window_handler(gsl::not_null<vcpu *> vcpu);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~nmi_window_handler() = default;

public:

    /// Queue NMI
    ///
    /// Queues an NMI for injection.
    ///
    /// @expects
    /// @ensures
    ///
    void queue_nmi();

    /// Inject NMI
    ///
    /// Inject an NMI on the next VM entry.
    ///
    /// @expects
    /// @ensures
    ///
    void inject_nmi();

public:

    /// @cond

    bool handle(vcpu *vcpu);

    /// @endcond

private:

    void enable_exiting();
    void disable_exiting();

private:

    vcpu *m_vcpu;

public:

    /// @cond

    nmi_window_handler(nmi_window_handler &&) = default;
    nmi_window_handler &operator=(nmi_window_handler &&) = default;

    nmi_window_handler(const nmi_window_handler &) = delete;
    nmi_window_handler &operator=(const nmi_window_handler &) = delete;

    /// @endcond
};

}

#endif
