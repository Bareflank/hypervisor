//
// Bareflank Hypervisor
// Copyright (C) 2015 Assured Information Security, Inc.
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

#ifndef VMCS_INTEL_X64_HOST_VM_STATE_H
#define VMCS_INTEL_X64_HOST_VM_STATE_H

#include <memory>

#include <bfdebug.h>
#include "vmcs_state.h"

// -----------------------------------------------------------------------------
// Exports
// -----------------------------------------------------------------------------

#include <bfexports.h>

#ifndef STATIC_HVE
#ifdef SHARED_HVE
#define EXPORT_HVE EXPORT_SYM
#else
#define EXPORT_HVE IMPORT_SYM
#endif
#else
#define EXPORT_HVE
#endif

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4251)
#endif

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

namespace bfvmm
{
namespace intel_x64
{

/// VMCS Host VM State
///
/// Define's the Host VM's CPU state. The Host VM runs the Host OS that
/// booted first (might be UEFI). This is different from a Guest VM where
/// the state is defined by Bareflank. With the Host VM, the state is defined
/// by the Host OS, so we have to get this information from the hardware.
///
class EXPORT_HVE vmcs_state_hvm : public vmcs_state
{
public:

    /// @cond

    vmcs_state_hvm();
    ~vmcs_state_hvm() override = default;

    ::x64::segment_register::value_type es() const override
    { return m_es; }
    ::x64::segment_register::value_type cs() const override
    { return m_cs; }
    ::x64::segment_register::value_type ss() const override
    { return m_ss; }
    ::x64::segment_register::value_type ds() const override
    { return m_ds; }
    ::x64::segment_register::value_type fs() const override
    { return m_fs; }
    ::x64::segment_register::value_type gs() const override
    { return m_gs; }
    ::x64::segment_register::value_type ldtr() const override
    { return m_ldtr; }
    ::x64::segment_register::value_type tr() const override
    { return m_tr; }

    ::intel_x64::cr0::value_type cr0() const override
    { return m_cr0; }
    ::intel_x64::cr3::value_type cr3() const override
    { return m_cr3; }
    ::intel_x64::cr4::value_type cr4() const override
    { return m_cr4; }
    ::intel_x64::dr7::value_type dr7() const override
    { return m_dr7; }

    ::x64::rflags::value_type rflags() const override
    { return m_rflags; }

    x64::gdt::integer_pointer gdt_base() const override
    { return m_gdt.base(); }
    x64::idt::integer_pointer idt_base() const override
    { return m_idt.base(); }

    x64::gdt::size_type gdt_limit() const override
    { return m_gdt.limit(); }
    x64::idt::size_type idt_limit() const override
    { return m_idt.limit(); }

    x64::gdt::limit_type es_limit() const override
    { return m_es_index != 0 ? m_gdt.limit(m_es_index) : 0; }
    x64::gdt::limit_type cs_limit() const override
    { return m_cs_index != 0 ? m_gdt.limit(m_cs_index) : 0; }
    x64::gdt::limit_type ss_limit() const override
    { return m_ss_index != 0 ? m_gdt.limit(m_ss_index) : 0; }
    x64::gdt::limit_type ds_limit() const override
    { return m_ds_index != 0 ? m_gdt.limit(m_ds_index) : 0; }
    x64::gdt::limit_type fs_limit() const override
    { return m_fs_index != 0 ? m_gdt.limit(m_fs_index) : 0; }
    x64::gdt::limit_type gs_limit() const override
    { return m_gs_index != 0 ? m_gdt.limit(m_gs_index) : 0; }
    x64::gdt::limit_type ldtr_limit() const override
    { return m_ldtr_index != 0 ? m_gdt.limit(m_ldtr_index) : 0; }
    x64::gdt::limit_type tr_limit() const override
    { return m_tr_index != 0 ? m_gdt.limit(m_tr_index) : 0; }

    x64::gdt::access_rights_type es_access_rights() const override
    { return m_es_index != 0 ? m_gdt.access_rights(m_es_index) : ::x64::access_rights::unusable; }
    x64::gdt::access_rights_type cs_access_rights() const override
    { return m_cs_index != 0 ? m_gdt.access_rights(m_cs_index) : ::x64::access_rights::unusable; }
    x64::gdt::access_rights_type ss_access_rights() const override
    { return m_ss_index != 0 ? m_gdt.access_rights(m_ss_index) : ::x64::access_rights::unusable; }
    x64::gdt::access_rights_type ds_access_rights() const override
    { return m_ds_index != 0 ? m_gdt.access_rights(m_ds_index) : ::x64::access_rights::unusable; }
    x64::gdt::access_rights_type fs_access_rights() const override
    { return m_fs_index != 0 ? m_gdt.access_rights(m_fs_index) : ::x64::access_rights::unusable; }
    x64::gdt::access_rights_type gs_access_rights() const override
    { return m_gs_index != 0 ? m_gdt.access_rights(m_gs_index) : ::x64::access_rights::unusable; }
    x64::gdt::access_rights_type ldtr_access_rights() const override
    { return m_ldtr_index != 0 ? m_gdt.access_rights(m_ldtr_index) : ::x64::access_rights::unusable; }
    x64::gdt::access_rights_type tr_access_rights() const override
    { return m_tr_index != 0 ? m_gdt.access_rights(m_tr_index) : ::x64::access_rights::unusable; }

    x64::gdt::base_type es_base() const override
    { return m_es_index != 0 ? m_gdt.base(m_es_index) : 0; }
    x64::gdt::base_type cs_base() const override
    { return m_cs_index != 0 ? m_gdt.base(m_cs_index) : 0; }
    x64::gdt::base_type ss_base() const override
    { return m_ss_index != 0 ? m_gdt.base(m_ss_index) : 0; }
    x64::gdt::base_type ds_base() const override
    { return m_ds_index != 0 ? m_gdt.base(m_ds_index) : 0; }
    x64::gdt::base_type fs_base() const override
    { return m_fs_index != 0 ? m_gdt.base(m_fs_index) : 0; }
    x64::gdt::base_type gs_base() const override
    { return m_gs_index != 0 ? m_gdt.base(m_gs_index) : 0; }
    x64::gdt::base_type ldtr_base() const override
    { return m_ldtr_index != 0 ? m_gdt.base(m_ldtr_index) : 0; }
    x64::gdt::base_type tr_base() const override
    { return m_tr_index != 0 ? m_gdt.base(m_tr_index) : 0; }

    ::intel_x64::msrs::value_type ia32_debugctl_msr() const override
    { return m_ia32_debugctl_msr; }
    ::intel_x64::msrs::value_type ia32_pat_msr() const override
    { return m_ia32_pat_msr; }
    ::intel_x64::msrs::value_type ia32_efer_msr() const override
    { return m_ia32_efer_msr; }
    ::intel_x64::msrs::value_type ia32_perf_global_ctrl_msr() const override
    { return m_ia32_perf_global_ctrl_msr; }
    ::intel_x64::msrs::value_type ia32_sysenter_cs_msr() const override
    { return m_ia32_sysenter_cs_msr; }
    ::intel_x64::msrs::value_type ia32_sysenter_esp_msr() const override
    { return m_ia32_sysenter_esp_msr; }
    ::intel_x64::msrs::value_type ia32_sysenter_eip_msr() const override
    { return m_ia32_sysenter_eip_msr; }
    ::intel_x64::msrs::value_type ia32_fs_base_msr() const override
    { return m_ia32_fs_base_msr; }
    ::intel_x64::msrs::value_type ia32_gs_base_msr() const override
    { return m_ia32_gs_base_msr; }

    void dump(int level = 0, std::string *msg = nullptr) const override
    {
        bferror_lnbr(level, msg);
        bferror_info(level, "vmcs_state_hvm", msg);
        bferror_brk1(level, msg);

        bfdebug_info(level, "segment selectors", msg);
        bfdebug_subnhex(level, "m_es", m_es, msg);
        bfdebug_subnhex(level, "m_cs", m_cs, msg);
        bfdebug_subnhex(level, "m_ss", m_ss, msg);
        bfdebug_subnhex(level, "m_ds", m_ds, msg);
        bfdebug_subnhex(level, "m_fs", m_fs, msg);
        bfdebug_subnhex(level, "m_gs", m_gs, msg);
        bfdebug_subnhex(level, "m_ldtr", m_ldtr, msg);
        bfdebug_subnhex(level, "m_tr", m_tr, msg);

        bfdebug_info(level, "segment base", msg);
        bfdebug_subnhex(level, "es_base()", es_base(), msg);
        bfdebug_subnhex(level, "cs_base()", cs_base(), msg);
        bfdebug_subnhex(level, "ss_base()", ss_base(), msg);
        bfdebug_subnhex(level, "ds_base()", ds_base(), msg);
        bfdebug_subnhex(level, "fs_base()", fs_base(), msg);
        bfdebug_subnhex(level, "gs_base()", gs_base(), msg);
        bfdebug_subnhex(level, "ldtr_base()", ldtr_base(), msg);
        bfdebug_subnhex(level, "tr_base()", tr_base(), msg);

        bfdebug_info(level, "segment limit", msg);
        bfdebug_subnhex(level, "es_limit()", es_limit(), msg);
        bfdebug_subnhex(level, "cs_limit()", cs_limit(), msg);
        bfdebug_subnhex(level, "ss_limit()", ss_limit(), msg);
        bfdebug_subnhex(level, "ds_limit()", ds_limit(), msg);
        bfdebug_subnhex(level, "fs_limit()", fs_limit(), msg);
        bfdebug_subnhex(level, "gs_limit()", gs_limit(), msg);
        bfdebug_subnhex(level, "ldtr_limit()", ldtr_limit(), msg);
        bfdebug_subnhex(level, "tr_limit()", tr_limit(), msg);

        bfdebug_info(level, "segment access rights", msg);
        bfdebug_subnhex(level, "es_access_rights()", es_access_rights(), msg);
        bfdebug_subnhex(level, "cs_access_rights()", cs_access_rights(), msg);
        bfdebug_subnhex(level, "ss_access_rights()", ss_access_rights(), msg);
        bfdebug_subnhex(level, "ds_access_rights()", ds_access_rights(), msg);
        bfdebug_subnhex(level, "fs_access_rights()", fs_access_rights(), msg);
        bfdebug_subnhex(level, "gs_access_rights()", gs_access_rights(), msg);
        bfdebug_subnhex(level, "ldtr_access_rights()", ldtr_access_rights(), msg);
        bfdebug_subnhex(level, "tr_access_rights()", tr_access_rights(), msg);

        bfdebug_info(level, "registers", msg);
        bfdebug_subnhex(level, "m_cr0", m_cr0, msg);
        bfdebug_subnhex(level, "m_cr3", m_cr3, msg);
        bfdebug_subnhex(level, "m_cr4", m_cr4, msg);
        bfdebug_subnhex(level, "m_dr7", m_dr7, msg);

        bfdebug_info(level, "flags", msg);
        bfdebug_subnhex(level, "m_rflags", m_rflags, msg);

        bfdebug_info(level, "gdt/idt", msg);
        bfdebug_subnhex(level, "m_gdt.base()", m_gdt.base(), msg);
        bfdebug_subnhex(level, "m_gdt.limit()", m_gdt.limit(), msg);
        bfdebug_subnhex(level, "m_idt.base()", m_idt.base(), msg);
        bfdebug_subnhex(level, "m_idt.limit()", m_idt.limit(), msg);

        bfdebug_info(level, "msrs", msg);
        bfdebug_subnhex(level, "m_ia32_debugctl_msr", m_ia32_debugctl_msr, msg);
        bfdebug_subnhex(level, "m_ia32_pat_msr", m_ia32_pat_msr, msg);
        bfdebug_subnhex(level, "m_ia32_efer_msr", m_ia32_efer_msr, msg);
        bfdebug_subnhex(level, "m_ia32_perf_global_ctrl_msr", m_ia32_perf_global_ctrl_msr, msg);
        bfdebug_subnhex(level, "m_ia32_sysenter_cs_msr", m_ia32_sysenter_cs_msr, msg);
        bfdebug_subnhex(level, "m_ia32_sysenter_esp_msr", m_ia32_sysenter_esp_msr, msg);
        bfdebug_subnhex(level, "m_ia32_sysenter_eip_msr", m_ia32_sysenter_eip_msr, msg);
        bfdebug_subnhex(level, "m_ia32_fs_base_msr", m_ia32_fs_base_msr, msg);
        bfdebug_subnhex(level, "m_ia32_gs_base_msr", m_ia32_gs_base_msr, msg);
    }

    /// @endcond

protected:

    /// @cond

    ::x64::segment_register::value_type m_es{0};
    ::x64::segment_register::value_type m_cs{0};
    ::x64::segment_register::value_type m_ss{0};
    ::x64::segment_register::value_type m_ds{0};
    ::x64::segment_register::value_type m_fs{0};
    ::x64::segment_register::value_type m_gs{0};
    ::x64::segment_register::value_type m_ldtr{0};
    ::x64::segment_register::value_type m_tr{0};

    ::x64::segment_register::value_type m_es_index{0};
    ::x64::segment_register::value_type m_cs_index{0};
    ::x64::segment_register::value_type m_ss_index{0};
    ::x64::segment_register::value_type m_ds_index{0};
    ::x64::segment_register::value_type m_fs_index{0};
    ::x64::segment_register::value_type m_gs_index{0};
    ::x64::segment_register::value_type m_ldtr_index{0};
    ::x64::segment_register::value_type m_tr_index{0};

    ::intel_x64::cr0::value_type m_cr0{0};
    ::intel_x64::cr3::value_type m_cr3{0};
    ::intel_x64::cr4::value_type m_cr4{0};
    ::intel_x64::dr7::value_type m_dr7{0};

    ::x64::rflags::value_type m_rflags{0};

    x64::gdt m_gdt;
    x64::idt m_idt;

    ::intel_x64::msrs::value_type m_ia32_debugctl_msr{0};
    ::intel_x64::msrs::value_type m_ia32_pat_msr{0};
    ::intel_x64::msrs::value_type m_ia32_efer_msr{0};
    ::intel_x64::msrs::value_type m_ia32_perf_global_ctrl_msr{0};
    ::intel_x64::msrs::value_type m_ia32_sysenter_cs_msr{0};
    ::intel_x64::msrs::value_type m_ia32_sysenter_esp_msr{0};
    ::intel_x64::msrs::value_type m_ia32_sysenter_eip_msr{0};
    ::intel_x64::msrs::value_type m_ia32_fs_base_msr{0};
    ::intel_x64::msrs::value_type m_ia32_gs_base_msr{0};

    /// @endcond

public:

    /// @cond

    vmcs_state_hvm(vmcs_state_hvm &&) noexcept = delete;
    vmcs_state_hvm &operator=(vmcs_state_hvm &&) noexcept = delete;

    vmcs_state_hvm(const vmcs_state_hvm &) = delete;
    vmcs_state_hvm &operator=(const vmcs_state_hvm &) = delete;

    /// @endcond
};

}
}

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#endif
