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

external_interrupt_handler::external_interrupt_handler(
    gsl::not_null<vcpu *> vcpu
) :
    m_vcpu{vcpu}
{
    using namespace vmcs_n;

    vcpu->add_exit_handler_for_reason(
        exit_reason::basic_exit_reason::external_interrupt,
    {&external_interrupt_handler::handle, this}
    );
}

// -----------------------------------------------------------------------------
// Add Handler / Enablers
// -----------------------------------------------------------------------------

void
external_interrupt_handler::add_handler(
    const handler_delegate_t &d)
{ m_handlers.push_front(d); }

void
external_interrupt_handler::enable_exiting()
{
    vmcs_n::pin_based_vm_execution_controls::external_interrupt_exiting::enable();
    vmcs_n::vm_exit_controls::acknowledge_interrupt_on_exit::enable();
}

void
external_interrupt_handler::disable_exiting()
{
    vmcs_n::pin_based_vm_execution_controls::external_interrupt_exiting::disable();
    vmcs_n::vm_exit_controls::acknowledge_interrupt_on_exit::disable();
}

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

bool
external_interrupt_handler::handle(vcpu *vcpu)
{
    struct info_t info = {
        vmcs_n::vm_exit_interruption_information::vector::get()
    };

    for (const auto &d : m_handlers) {
        if (d(vcpu, info)) {
            return true;
        }
    }

    throw std::runtime_error(
        "Unhandled interrupt vector: " + std::to_string(info.vector)
    );
}

}
