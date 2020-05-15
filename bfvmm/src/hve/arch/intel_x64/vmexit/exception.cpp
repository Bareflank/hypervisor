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

exception_handler::exception_handler(
    gsl::not_null<vcpu *> vcpu
) :
    m_vcpu{vcpu}
{
    using namespace vmcs_n;

    vcpu->add_exit_handler_for_reason(
        exit_reason::basic_exit_reason::exception_or_non_maskable_interrupt,
    {&exception_handler::handle, this}
    );
}

// -----------------------------------------------------------------------------
// Add Handler / Enablers
// -----------------------------------------------------------------------------

void
exception_handler::add_handler(
    vmcs_n::value_type vector, const handler_delegate_t &d)
{
    m_handlers[vector].push_front(d);

    auto bitmap = vmcs_n::exception_bitmap::get();
    bitmap |= (1U << vector);
    vmcs_n::exception_bitmap::set(bitmap);
}

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

bool
exception_handler::handle(vcpu *vcpu)
{
    using namespace vmcs_n::vm_exit_interruption_information;
    auto interrupt_info = vmcs_n::vm_exit_interruption_information::get();

    if (interruption_type::get(interrupt_info) == interruption_type::non_maskable_interrupt) {
        return false;
    }

    struct info_t info = {
        vector::get(interrupt_info)
    };

    const auto &hdlrs =
        m_handlers.find(
            info.vector
        );

    if (GSL_LIKELY(hdlrs != m_handlers.end())) {
        for (const auto &d : hdlrs->second) {
            if (d(vcpu, info)) {
                return true;
            }
        }
    }

    throw std::runtime_error(
        "Unhandled exception vector: " + std::to_string(info.vector)
    );
}

}
