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

#include <hve/arch/intel_x64/vcpu.h>

namespace bfvmm::intel_x64
{

interrupt_window_handler::interrupt_window_handler(
    gsl::not_null<vcpu *> vcpu
) :
    m_vcpu{vcpu}
{
    using namespace vmcs_n;

    vcpu->add_exit_handler_for_reason(
        exit_reason::basic_exit_reason::interrupt_window,
    {&interrupt_window_handler::handle, this}
    );
}

// -----------------------------------------------------------------------------
// Add Handler / Enablers
// -----------------------------------------------------------------------------

void
interrupt_window_handler::queue_external_interrupt(uint64_t vector)
{
    // Note:
    //
    // There are two ways to handle injection. Currently, we inject using an
    // interrupt window. This means that an interrupt is always queued, and it
    // is only injected when the VM has an open window. The downside to this
    // approach is that when this function is called, it is possible that the
    // window is actually open, which means that we needlessly generate an
    // extra VM exit.
    //
    // The other approach is to check to see if the window is open and inject.
    // The issue with this approach is that we always have to check to see if
    // the window is open which is expensive, and then we have to have a lot of
    // extra logic to handle injecting without overwritting existing
    // interrupts, getting interrupts out of order, etc... There are a lot
    // more edge cases. The beauty of our current approach is that our window
    // handler is the only thing that can inject an interrupt, which is
    // mutually exclusive with queueing (as queueing occurs on any VM exit
    // other than our window) which means there are no race conditions, or
    // overwritting, etc... And, we do not have to make several vmreads per
    // injection. Since we leverage vpid, a VM exit that occurs before an entry
    // has a minimum performance hit as the VMM is still in the cache so this
    // approach is both reliable and performant.
    //
    // Also note that our approach also works fine with exceptions. Exceptions
    // do not need to be queued since they cannot be blocked. This means that
    // exceptions can be injected on any VM exit without fear of overwritting
    // an external interrupt as they are only injected on an open window exit
    // which once again, will not attempt to inject an exception at the same
    // time since that code is managed here, and is very small.
    //

    this->enable_exiting();
    m_interrupt_queue.push(vector);
}

void
interrupt_window_handler::inject_exception(uint64_t vector, uint64_t ec)
{
    namespace info_n = vmcs_n::vm_entry_interruption_information;
    using namespace info_n::interruption_type;

    uint64_t info = 0;

    info_n::vector::set(info, vector);
    info_n::interruption_type::set(info, hardware_exception);
    info_n::valid_bit::enable(info);

    switch (vector) {
        case 8:
        case 10:
        case 11:
        case 12:
        case 13:
        case 14:
        case 17:
            info_n::deliver_error_code_bit::enable(info);
            vmcs_n::vm_entry_exception_error_code::set(ec);
            break;

        default:
            break;
    }

    info_n::set(info);
}

void
interrupt_window_handler::inject_external_interrupt(uint64_t vector)
{
    namespace info_n = vmcs_n::vm_entry_interruption_information;
    using namespace info_n::interruption_type;

    uint64_t info = 0;

    info_n::vector::set(info, vector);
    info_n::interruption_type::set(info, external_interrupt);
    info_n::valid_bit::enable(info);

    info_n::set(info);
}

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

bool
interrupt_window_handler::handle(vcpu *vcpu)
{
    bfignored(vcpu);
    this->inject_external_interrupt(m_interrupt_queue.pop());

    if (m_interrupt_queue.empty()) {
        this->disable_exiting();
    }

    return true;
}

// -----------------------------------------------------------------------------
// Private
// -----------------------------------------------------------------------------

void
interrupt_window_handler::enable_exiting()
{
    using namespace vmcs_n;

    if (m_enabled == false) {
        primary_processor_based_vm_execution_controls::interrupt_window_exiting::enable();
        m_enabled = true;
    }
}

void
interrupt_window_handler::disable_exiting()
{
    using namespace vmcs_n;

    if (m_enabled == true) {
        primary_processor_based_vm_execution_controls::interrupt_window_exiting::disable();
        m_enabled = false;
    }
}

}
