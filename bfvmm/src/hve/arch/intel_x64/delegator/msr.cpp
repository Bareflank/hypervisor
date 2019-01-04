//
// Bareflank Hypervisor
// Copyright (C) 2018 Assured Information Security, Inc.
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

#include <vcpu/vcpu.h>
#include <hve/arch/intel_x64/delegator/msr.h>

namespace bfvmm::intel_x64::msr
{

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

void
emulate_wrgpr(gsl::not_null<bfvmm::intel_x64::vcpu *> vcpu, uintptr_t val)
{
    using namespace ::intel_x64::vmcs;
    using namespace exit_qualification::control_register_access;

    switch (general_purpose_register::get()) {
        case general_purpose_register::rax:
            vcpu->set_rax(val);
            return;

        case general_purpose_register::rbx:
            vcpu->set_rbx(val);
            return;

        case general_purpose_register::rcx:
            vcpu->set_rcx(val);
            return;

        case general_purpose_register::rdx:
            vcpu->set_rdx(val);
            return;

        case general_purpose_register::rsp:
            vcpu->set_rsp(val);
            return;

        case general_purpose_register::rbp:
            vcpu->set_rbp(val);
            return;

        case general_purpose_register::rsi:
            vcpu->set_rsi(val);
            return;

        case general_purpose_register::rdi:
            vcpu->set_rdi(val);
            return;

        case general_purpose_register::r8:
            vcpu->set_r08(val);
            return;

        case general_purpose_register::r9:
            vcpu->set_r09(val);
            return;

        case general_purpose_register::r10:
            vcpu->set_r10(val);
            return;

        case general_purpose_register::r11:
            vcpu->set_r11(val);
            return;

        case general_purpose_register::r12:
            vcpu->set_r12(val);
            return;

        case general_purpose_register::r13:
            vcpu->set_r13(val);
            return;

        case general_purpose_register::r14:
            vcpu->set_r14(val);
            return;

        default:
            vcpu->set_r15(val);
            return;
    }
}

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

        // QUIRK:
        //
        // The following is specifically for CPU-Z. For whatever reason, it is
        // reading the following undefined MSRs, which causes the system to
        // freeze since attempting to read these MSRs in the exit handler
        // will cause a GPF which is not being caught. The result is, the core
        // that runs RDMSR on these freezes, the other cores receive an
        // INIT signal to reset, and the system dies.
        //

        case 0x31:
        case 0x39:
        case 0x1ae:
        case 0x1af:
        case 0x602:
            return 0;
    }
}

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

// -----------------------------------------------------------------------------
// MSR Delegator Implementation
// -----------------------------------------------------------------------------

bool
delegator::handle_rdmsr(vcpu_t vcpu)
{
    auto val =
        emulate_rdmsr(
            gsl::narrow_cast<::x64::msrs::field_type>(vcpu->rcx())
        );

    vcpu->set_rax(((val >> 0x00) & 0x00000000FFFFFFFF));
    vcpu->set_rdx(((val >> 0x20) & 0x00000000FFFFFFFF));

    return vcpu->advance();
}

bool
delegator::handle_wrmsr(vcpu_t vcpu)
{
    auto val = 0ULL;

    val |= ((vcpu->rax() & 0x00000000FFFFFFFF) << 0x00);
    val |= ((vcpu->rdx() & 0x00000000FFFFFFFF) << 0x20);

    emulate_wrmsr(
        gsl::narrow_cast<::x64::msrs::field_type>(vcpu->rcx()),
        val
    );

    return vcpu->advance();
}

}
