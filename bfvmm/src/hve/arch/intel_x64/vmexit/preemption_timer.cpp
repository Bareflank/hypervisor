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

preemption_timer_handler::preemption_timer_handler(
    gsl::not_null<vcpu *> vcpu
) :
    m_vcpu{vcpu}
{
    using namespace vmcs_n;

    vcpu->add_exit_handler_for_reason(
        exit_reason::basic_exit_reason::preemption_timer_expired,
    {&preemption_timer_handler::handle, this}
    );
}

// -----------------------------------------------------------------------------
// Add Handler / Enablers
// -----------------------------------------------------------------------------

void
preemption_timer_handler::add_handler(const handler_delegate_t &d)
{ m_handlers.push_front(d); }

void
preemption_timer_handler::enable_exiting()
{
    using namespace ::intel_x64::vmcs;
    pin_based_vm_execution_controls::activate_preemption_timer::enable();
}

void
preemption_timer_handler::disable_exiting()
{
    using namespace ::intel_x64::vmcs;
    pin_based_vm_execution_controls::activate_preemption_timer::disable();
}

void
preemption_timer_handler::set_timer(value_t val)
{ vmcs_n::preemption_timer_value::set(val); }

preemption_timer_handler::value_t
preemption_timer_handler::get_timer() const
{ return vmcs_n::preemption_timer_value::get(); }

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

bool
preemption_timer_handler::handle(vcpu *vcpu)
{
    for (const auto &d : m_handlers) {
        if (d(vcpu)) {
            return true;
        }
    }

    throw std::runtime_error(
        "preemption_timer_handler::handle: unhandled vmx-preemption timer exit"
    );
}

}
