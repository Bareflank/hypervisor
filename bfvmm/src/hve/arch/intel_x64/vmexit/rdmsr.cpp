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

rdmsr_handler::rdmsr_handler(
    gsl::not_null<vcpu *> vcpu
) :
    m_vcpu{vcpu},
    m_msr_bitmap{vcpu->m_msr_bitmap.get(), ::x64::pt::page_size}
{
    using namespace vmcs_n;

    vcpu->add_handler(
        exit_reason::basic_exit_reason::rdmsr,
        ::handler_delegate_t::create<rdmsr_handler, &rdmsr_handler::handle>(this)
    );
}

// -----------------------------------------------------------------------------
// Add Handler / Enablers
// -----------------------------------------------------------------------------

void
rdmsr_handler::add_handler(
    vmcs_n::value_type msr, const handler_delegate_t &d)
{ m_handlers[msr].push_front(d); }

void
rdmsr_handler::emulate(vmcs_n::value_type msr)
{ m_emulate[msr] = true; }

void
rdmsr_handler::set_default_handler(
    const ::handler_delegate_t &d)
{ m_default_handler = d; }

// -----------------------------------------------------------------------------
// Enablers
// -----------------------------------------------------------------------------

void
rdmsr_handler::trap_on_access(vmcs_n::value_type msr)
{
    if (msr <= 0x00001FFFUL) {
        return set_bit(m_msr_bitmap, (msr - 0x00000000UL) + 0);
    }

    if (msr >= 0xC0000000UL && msr <= 0xC0001FFFUL) {
        return set_bit(m_msr_bitmap, (msr - 0xC0000000UL) + 0x2000);
    }

    throw std::runtime_error("invalid msr: " + std::to_string(msr));
}

void
rdmsr_handler::trap_on_all_accesses()
{ gsl::memset(m_msr_bitmap.subspan(0, m_msr_bitmap.size() >> 1), 0xFF); }

void
rdmsr_handler::pass_through_access(vmcs_n::value_type msr)
{
    if (msr <= 0x00001FFFUL) {
        return clear_bit(m_msr_bitmap, (msr - 0x00000000) + 0);
    }

    if (msr >= 0xC0000000UL && msr <= 0xC0001FFFUL) {
        return clear_bit(m_msr_bitmap, (msr - 0xC0000000UL) + 0x2000);
    }

    throw std::runtime_error("invalid msr: " + std::to_string(msr));
}

void
rdmsr_handler::pass_through_all_accesses()
{ gsl::memset(m_msr_bitmap.subspan(0, m_msr_bitmap.size() >> 1), 0x00); }

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

bool
rdmsr_handler::handle(gsl::not_null<vcpu_t *> vcpu)
{

    // TODO: IMPORTANT!!!
    //
    // We need to create a list of MSRs that are implemented and GP when the
    // MSR is not implemented. We also need to test to make sure the the hardware
    // is enforcing the privilege level of this instruction while the hypervisor
    // is loaded.
    //
    // To fire a GP, we need to add a Bareflank specific exception that can be
    // thrown. The base hypervisor can then trap on this type of exception and
    // have delegates that can be registered to handle the exeption type, which in
    // this case would be the interrupt code that would then inject a GP.
    //

    const auto &hdlrs =
        m_handlers.find(
            vcpu->rcx()
        );

    if (GSL_LIKELY(hdlrs != m_handlers.end())) {

        struct info_t info = {
            gsl::narrow_cast<uint32_t>(vcpu->rcx()),
            0,
            false,
            false
        };

        if (!m_emulate[vcpu->rcx()]) {
            info.val =
                emulate_rdmsr(
                    gsl::narrow_cast<::x64::msrs::field_type>(vcpu->rcx())
                );
        }

        for (const auto &d : hdlrs->second) {
            if (d(vcpu, info)) {

                if (!info.ignore_write) {
                    vcpu->set_rax(((info.val >> 0x00) & 0x00000000FFFFFFFF));
                    vcpu->set_rdx(((info.val >> 0x20) & 0x00000000FFFFFFFF));
                }

                if (!info.ignore_advance) {
                    return vcpu->advance();
                }

                return true;
            }
        }
    }

    if (m_default_handler.is_valid()) {
        return m_default_handler(vcpu);
    }

    return false;
}

}
