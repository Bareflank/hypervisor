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

ept_violation_handler::ept_violation_handler(
    gsl::not_null<vcpu *> vcpu
) :
    m_vcpu{vcpu}
{
    using namespace vmcs_n;

    vcpu->add_exit_handler_for_reason(
        exit_reason::basic_exit_reason::ept_violation,
    {&ept_violation_handler::handle, this}
    );
}

// -----------------------------------------------------------------------------
// Add Handler / Enablers
// -----------------------------------------------------------------------------

void
ept_violation_handler::add_read_handler(
    const handler_delegate_t &d)
{ m_read_handlers.push_front(d); }

void
ept_violation_handler::add_write_handler(
    const handler_delegate_t &d)
{ m_write_handlers.push_front(d); }

void
ept_violation_handler::add_execute_handler(
    const handler_delegate_t &d)
{ m_execute_handlers.push_front(d); }

void
ept_violation_handler::set_default_read_handler(
    const ::handler_delegate_t &d)
{ m_default_read_handler = d; }

void
ept_violation_handler::set_default_write_handler(
    const ::handler_delegate_t &d)
{ m_default_write_handler = d; }

void
ept_violation_handler::set_default_execute_handler(
    const ::handler_delegate_t &d)
{ m_default_execute_handler = d; }

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

bool
ept_violation_handler::handle(vcpu *vcpu)
{
    using namespace vmcs_n;
    auto qual = exit_qualification::ept_violation::get();

    struct info_t info = {
        guest_linear_address::get(),
        guest_physical_address::get(),
        qual,
        true
    };

    if (exit_qualification::ept_violation::data_read::is_enabled(qual)) {
        return handle_read(vcpu, info);
    }

    if (exit_qualification::ept_violation::data_write::is_enabled(qual)) {
        return handle_write(vcpu, info);
    }

    if (exit_qualification::ept_violation::instruction_fetch::is_enabled(qual)) {
        return handle_execute(vcpu, info);
    }

    throw std::runtime_error(
        "ept_violation_handler::handle: unhandled ept violation"
    );
}

bool
ept_violation_handler::handle_read(vcpu *vcpu, info_t &info)
{
    for (const auto &d : m_read_handlers) {
        if (d(vcpu, info)) {

            if (!info.ignore_advance) {
                return vcpu->advance();
            }

            return true;
        }
    }

    if (m_default_read_handler) {
        return m_default_read_handler(vcpu);
    }

    throw std::runtime_error(
        "ept_violation_handler: unhandled ept read violation"
    );
}

bool
ept_violation_handler::handle_write(vcpu *vcpu, info_t &info)
{
    for (const auto &d : m_write_handlers) {
        if (d(vcpu, info)) {

            if (!info.ignore_advance) {
                return vcpu->advance();
            }

            return true;
        }
    }

    if (m_default_write_handler) {
        return m_default_write_handler(vcpu);
    }

    throw std::runtime_error(
        "ept_violation_handler: unhandled ept write violation"
    );
}

bool
ept_violation_handler::handle_execute(vcpu *vcpu, info_t &info)
{
    for (const auto &d : m_execute_handlers) {
        if (d(vcpu, info)) {

            if (!info.ignore_advance) {
                return vcpu->advance();
            }

            return true;
        }
    }

    if (m_default_execute_handler) {
        return m_default_execute_handler(vcpu);
    }

    throw std::runtime_error(
        "ept_violation_handler: unhandled ept execute violation"
    );
}

}
