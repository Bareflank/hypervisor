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

static bool
handle_nmi(vcpu *vcpu)
{
    vcpu->queue_nmi();
    return true;
}

nmi_handler::nmi_handler(
    gsl::not_null<vcpu *> vcpu
) :
    m_vcpu{vcpu}
{
    using namespace vmcs_n;

    vcpu->add_exit_handler_for_reason(
        exit_reason::basic_exit_reason::exception_or_non_maskable_interrupt,
    {&nmi_handler::handle, this}
    );

    this->add_handler(handle_nmi);
}

// -----------------------------------------------------------------------------
// Add Handler / Enablers
// -----------------------------------------------------------------------------

void
nmi_handler::add_handler(
    const handler_delegate_t &d)
{ m_handlers.push_front(d); }

void
nmi_handler::enable_exiting()
{
    vmcs_n::pin_based_vm_execution_controls::nmi_exiting::enable();
    vmcs_n::pin_based_vm_execution_controls::virtual_nmis::enable();
}

void
nmi_handler::disable_exiting()
{
    vmcs_n::pin_based_vm_execution_controls::nmi_exiting::disable();
    vmcs_n::pin_based_vm_execution_controls::virtual_nmis::disable();
}

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

bool
nmi_handler::handle(vcpu *vcpu)
{
    for (const auto &d : m_handlers) {
        if (d(vcpu)) {
            break;
        }
    }

    return true;
}

}
