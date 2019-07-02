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

xsetbv_handler::xsetbv_handler(
    gsl::not_null<vcpu *> vcpu
) :
    m_vcpu{vcpu}
{
    using namespace vmcs_n;

    vcpu->add_exit_handler_for_reason(
        vmcs_n::exit_reason::basic_exit_reason::xsetbv,
    {&xsetbv_handler::handle, this}
    );
}

// -----------------------------------------------------------------------------
// Add Handler / Enablers
// -----------------------------------------------------------------------------

void
xsetbv_handler::add_handler(const handler_delegate_t &d)
{ m_handlers.push_front(d); }

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

bool
xsetbv_handler::handle(vcpu *vcpu)
{
    struct info_t info = {
        0,
        false,
        false
    };

    info.val |= ((vcpu->rax() & 0x00000000FFFFFFFF) << 0x00);
    info.val |= ((vcpu->rdx() & 0x00000000FFFFFFFF) << 0x20);

    for (const auto &d : m_handlers) {
        if (d(vcpu, info)) {
            break;
        }
    }

    if (!info.ignore_write) {
        ::intel_x64::xcr0::set(info.val);
    }

    if (!info.ignore_advance) {
        return vcpu->advance();
    }

    return true;
}

}
