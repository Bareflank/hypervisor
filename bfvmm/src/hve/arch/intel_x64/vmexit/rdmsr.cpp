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

::x64::msrs::value_type
emulate_rdmsr(::x64::msrs::field_type msr)
{
    using namespace ::intel_x64::vmcs;

    switch (msr) {
        case ::intel_x64::msrs::ia32_debugctl::addr:
            return guest_ia32_debugctl::get();

        case ::x64::msrs::ia32_pat::addr:
            return guest_ia32_pat::get();

        case ::intel_x64::msrs::ia32_efer::addr:
            return guest_ia32_efer::get();

        case ::intel_x64::msrs::ia32_perf_global_ctrl::addr:
            return guest_ia32_perf_global_ctrl::get_if_exists();

        case ::intel_x64::msrs::ia32_sysenter_cs::addr:
            return guest_ia32_sysenter_cs::get();

        case ::intel_x64::msrs::ia32_sysenter_esp::addr:
            return guest_ia32_sysenter_esp::get();

        case ::intel_x64::msrs::ia32_sysenter_eip::addr:
            return guest_ia32_sysenter_eip::get();

        case ::intel_x64::msrs::ia32_fs_base::addr:
            return guest_fs_base::get();

        case ::intel_x64::msrs::ia32_gs_base::addr:
            return guest_gs_base::get();

        default:
            return ::intel_x64::msrs::get(msr);
    }
}

namespace bfvmm::intel_x64
{

rdmsr_handler::rdmsr_handler(
    gsl::not_null<vcpu *> vcpu
) :
    m_vcpu{vcpu},
    m_msr_bitmap{vcpu->msr_bitmap(), ::x64::pt::page_size}
{
    using namespace vmcs_n;

    vcpu->add_exit_handler_for_reason(
        exit_reason::basic_exit_reason::rdmsr,
    {&rdmsr_handler::handle, this}
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

    if (msr >= 0x40000000UL && msr <= 0x40001FFFUL) {
        return;
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
rdmsr_handler::handle(vcpu *vcpu)
{
    auto user_already_emulating = m_emulate[vcpu->rcx()];

    struct info_t info = {
        gsl::narrow_cast<uint32_t>(vcpu->rcx()),
        0,
        false,
        false
    };

    if (!user_already_emulating) {
        info.val = emulate_rdmsr(info.msr);
    }

    const auto &hdlrs =
        m_handlers.find(
            vcpu->rcx()
        );

    if (GSL_LIKELY(hdlrs != m_handlers.end())) {

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

    if (m_default_handler) {
        return m_default_handler(vcpu);
    }

    if (user_already_emulating) {
        return false;
    }

    vcpu->set_rax(((info.val >> 0x00) & 0x00000000FFFFFFFF));
    vcpu->set_rdx(((info.val >> 0x20) & 0x00000000FFFFFFFF));

    return vcpu->advance();
}

}
