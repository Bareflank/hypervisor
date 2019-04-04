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

void
emulate_wrmsr(::x64::msrs::field_type msr, ::x64::msrs::value_type val)
{
    using namespace ::intel_x64::vmcs;

    switch (msr) {
        case ::intel_x64::msrs::ia32_debugctl::addr:
            guest_ia32_debugctl::set(val);
            return;

        case ::x64::msrs::ia32_pat::addr:
            guest_ia32_pat::set(val);
            return;

        case ::intel_x64::msrs::ia32_efer::addr:
            guest_ia32_efer::set(val);
            return;

        case ::intel_x64::msrs::ia32_perf_global_ctrl::addr:
            guest_ia32_perf_global_ctrl::set_if_exists(val);
            return;

        case ::intel_x64::msrs::ia32_sysenter_cs::addr:
            guest_ia32_sysenter_cs::set(val);
            return;

        case ::intel_x64::msrs::ia32_sysenter_esp::addr:
            guest_ia32_sysenter_esp::set(val);
            return;

        case ::intel_x64::msrs::ia32_sysenter_eip::addr:
            guest_ia32_sysenter_eip::set(val);
            return;

        case ::intel_x64::msrs::ia32_fs_base::addr:
            guest_fs_base::set(val);
            return;

        case ::intel_x64::msrs::ia32_gs_base::addr:
            guest_gs_base::set(val);
            return;

        default:
            ::intel_x64::msrs::set(msr, val);
            return;
    }
}

namespace bfvmm::intel_x64
{

wrmsr_handler::wrmsr_handler(
    gsl::not_null<vcpu *> vcpu
) :
    m_vcpu{vcpu},
    m_msr_bitmap{vcpu->msr_bitmap(), ::x64::pt::page_size}
{
    using namespace vmcs_n;

    vcpu->add_exit_handler_for_reason(
        exit_reason::basic_exit_reason::wrmsr,
    {&wrmsr_handler::handle, this}
    );
}

// -----------------------------------------------------------------------------
// Add Handler
// -----------------------------------------------------------------------------

void
wrmsr_handler::add_handler(
    vmcs_n::value_type msr, const handler_delegate_t &d)
{ m_handlers[msr].push_front(d); }

void
wrmsr_handler::emulate(vmcs_n::value_type msr)
{ m_emulate[msr] = true; }

void
wrmsr_handler::set_default_handler(
    const ::handler_delegate_t &d)
{ m_default_handler = d; }

// -----------------------------------------------------------------------------
// Enablers
// -----------------------------------------------------------------------------

void
wrmsr_handler::trap_on_access(vmcs_n::value_type msr)
{
    if (msr <= 0x00001FFFUL) {
        return set_bit(m_msr_bitmap, (msr - 0x00000000UL) + 0x4000);
    }

    if (msr >= 0xC0000000UL && msr <= 0xC0001FFFUL) {
        return set_bit(m_msr_bitmap, (msr - 0xC0000000UL) + 0x6000);
    }

    if (msr >= 0x40000000UL && msr <= 0x40001FFFUL) {
        return;
    }

    throw std::runtime_error("invalid msr: " + std::to_string(msr));
}

void
wrmsr_handler::trap_on_all_accesses()
{ gsl::memset(m_msr_bitmap.subspan(2048, m_msr_bitmap.size() >> 1), 0xFF); }

void
wrmsr_handler::pass_through_access(vmcs_n::value_type msr)
{
    if (msr <= 0x00001FFFUL) {
        return clear_bit(m_msr_bitmap, (msr - 0x00000000UL) + 0x4000);
    }

    if (msr >= 0xC0000000UL && msr <= 0xC0001FFFUL) {
        return clear_bit(m_msr_bitmap, (msr - 0xC0000000UL) + 0x6000);
    }

    throw std::runtime_error("invalid msr: " + std::to_string(msr));
}

void
wrmsr_handler::pass_through_all_accesses()
{ gsl::memset(m_msr_bitmap.subspan(2048, m_msr_bitmap.size() >> 1), 0x00); }

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

bool
wrmsr_handler::handle(vcpu *vcpu)
{
    auto user_already_emulating = m_emulate[vcpu->rcx()];

    struct info_t info = {
        gsl::narrow_cast<::x64::msrs::field_type>(vcpu->rcx()),
        ((vcpu->rax() & 0x00000000FFFFFFFF) << 0) |
        ((vcpu->rdx() & 0x00000000FFFFFFFF) << 32),
        false,
        false
    };

    const auto &hdlrs =
        m_handlers.find(
            vcpu->rcx()
        );

    if (GSL_LIKELY(hdlrs != m_handlers.end())) {

        for (const auto &d : hdlrs->second) {
            if (d(vcpu, info)) {

                if (!info.ignore_write && !user_already_emulating) {
                    emulate_wrmsr(info.msr, info.val);
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

    emulate_wrmsr(info.msr, info.val);
    return vcpu->advance();
}

}
