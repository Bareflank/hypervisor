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

#ifndef VMEXIT_INTERRUPT_WINDOW_INTEL_X64_H
#define VMEXIT_INTERRUPT_WINDOW_INTEL_X64_H

#include <bfgsl.h>
#include <bfdelegate.h>

#include "../interrupt_queue.h"

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

namespace bfvmm::intel_x64
{

class vcpu;

/// Interrupt window
///
class interrupt_window_handler
{
public:

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vcpu the vcpu object for this interrupt window handler
    ///
    interrupt_window_handler(
        gsl::not_null<vcpu *> vcpu);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~interrupt_window_handler() = default;

public:

    /// Queue External Interrupt
    ///
    /// Queue an external interrupt at the given vector on the
    /// next upcoming open interrupt window.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vector the vector to inject into the guest
    ///
    void queue_external_interrupt(uint64_t vector);

    /// Inject Exception
    ///
    /// Inject an exception on the next VM entry. Note that this will overwrite
    /// any interrupts that are already injected for the next VM entry so
    /// care should be taken when using this function
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vector the vector to inject into the guest
    /// @param ec the error code associated with the exception if applicable
    ///
    void inject_exception(uint64_t vector, uint64_t ec = 0);

    /// Inject External Interrupt
    ///
    /// Inject an external interrupt on the next VM entry. Note that this will
    /// overwriteany interrupts that are already injected for the next VM entry
    /// so care should be taken when using this function
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vector the vector to inject into the guest
    ///
    void inject_external_interrupt(uint64_t vector);

public:

    /// @cond

    bool handle(vcpu *vcpu);

    /// @endcond

private:

    void enable_exiting();
    void disable_exiting();

private:

    vcpu *m_vcpu;

    bool m_enabled{false};
    interrupt_queue m_interrupt_queue;

public:

    /// @cond

    interrupt_window_handler(interrupt_window_handler &&) = default;
    interrupt_window_handler &operator=(interrupt_window_handler &&) = default;

    interrupt_window_handler(const interrupt_window_handler &) = delete;
    interrupt_window_handler &operator=(const interrupt_window_handler &) = delete;

    /// @endcond
};

}

#endif
