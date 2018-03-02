//
// Bareflank Hypervisor
//
// Copyright (C) 2015 Assured Information Security, Inc.
// Author: Rian Quinn        <quinnr@ainfosec.com>
// Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
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

#include <debug.h>
#include <vmcs/vmcs_intel_x64_state.h>

/// VMCS Host VM State
///
/// Define's the Host VM's CPU state. The Host VM runs the Host OS that
/// booted first (might be UEFI). This is different from a Guest VM where
/// the state is defined by Bareflank. With the Host VM, the state is defined
/// by the Host OS, so we have to get this information from the hardware.
///
class vmcs_intel_x64_host_vm_state : public vmcs_intel_x64_state
{
public:

    vmcs_intel_x64_host_vm_state();
    ~vmcs_intel_x64_host_vm_state() override = default;

    x64::segment_register::type es() const override
    { return m_es; }
    x64::segment_register::type cs() const override
    { return m_cs; }
    x64::segment_register::type ss() const override
    { return m_ss; }
    x64::segment_register::type ds() const override
    { return m_ds; }
    x64::segment_register::type fs() const override
    { return m_fs; }
    x64::segment_register::type gs() const override
    { return m_gs; }
    x64::segment_register::type ldtr() const override
    { return m_ldtr; }
    x64::segment_register::type tr() const override
    { return m_tr; }

    intel_x64::cr0::value_type cr0() const override
    { return m_cr0; }
    intel_x64::cr3::value_type cr3() const override
    { return m_cr3; }
    intel_x64::cr4::value_type cr4() const override
    { return m_cr4; }
    x64::dr7::value_type dr7() const override
    { return m_dr7; }

    x64::rflags::value_type rflags() const override
    { return m_rflags; }

    gdt_x64::integer_pointer gdt_base() const override
    { return m_gdt.base(); }
    idt_x64::integer_pointer idt_base() const override
    { return m_idt.base(); }

    gdt_x64::size_type gdt_limit() const override
    { return m_gdt.limit(); }
    idt_x64::size_type idt_limit() const override
    { return m_idt.limit(); }

    gdt_x64::limit_type es_limit() const override
    { return m_es_index != 0 ? m_gdt.limit(m_es_index) : 0; }
    gdt_x64::limit_type cs_limit() const override
    { return m_cs_index != 0 ? m_gdt.limit(m_cs_index) : 0; }
    gdt_x64::limit_type ss_limit() const override
    { return m_ss_index != 0 ? m_gdt.limit(m_ss_index) : 0; }
    gdt_x64::limit_type ds_limit() const override
    { return m_ds_index != 0 ? m_gdt.limit(m_ds_index) : 0; }
    gdt_x64::limit_type fs_limit() const override
    { return m_fs_index != 0 ? m_gdt.limit(m_fs_index) : 0; }
    gdt_x64::limit_type gs_limit() const override
    { return m_gs_index != 0 ? m_gdt.limit(m_gs_index) : 0; }
    gdt_x64::limit_type ldtr_limit() const override
    { return m_ldtr_index != 0 ? m_gdt.limit(m_ldtr_index) : 0; }
    gdt_x64::limit_type tr_limit() const override
    { return m_tr_index != 0 ? m_gdt.limit(m_tr_index) : 0; }

    gdt_x64::access_rights_type es_access_rights() const override
    { return m_es_index != 0 ? m_gdt.access_rights(m_es_index) : x64::access_rights::unusable; }
    gdt_x64::access_rights_type cs_access_rights() const override
    { return m_cs_index != 0 ? m_gdt.access_rights(m_cs_index) : x64::access_rights::unusable; }
    gdt_x64::access_rights_type ss_access_rights() const override
    { return m_ss_index != 0 ? m_gdt.access_rights(m_ss_index) : x64::access_rights::unusable; }
    gdt_x64::access_rights_type ds_access_rights() const override
    { return m_ds_index != 0 ? m_gdt.access_rights(m_ds_index) : x64::access_rights::unusable; }
    gdt_x64::access_rights_type fs_access_rights() const override
    { return m_fs_index != 0 ? m_gdt.access_rights(m_fs_index) : x64::access_rights::unusable; }
    gdt_x64::access_rights_type gs_access_rights() const override
    { return m_gs_index != 0 ? m_gdt.access_rights(m_gs_index) : x64::access_rights::unusable; }
    gdt_x64::access_rights_type ldtr_access_rights() const override
    { return m_ldtr_index != 0 ? m_gdt.access_rights(m_ldtr_index) : x64::access_rights::unusable; }
    gdt_x64::access_rights_type tr_access_rights() const override
    { return m_tr_index != 0 ? m_gdt.access_rights(m_tr_index) : x64::access_rights::unusable; }

    gdt_x64::base_type es_base() const override
    { return m_es_index != 0 ? m_gdt.base(m_es_index) : 0; }
    gdt_x64::base_type cs_base() const override
    { return m_cs_index != 0 ? m_gdt.base(m_cs_index) : 0; }
    gdt_x64::base_type ss_base() const override
    { return m_ss_index != 0 ? m_gdt.base(m_ss_index) : 0; }
    gdt_x64::base_type ds_base() const override
    { return m_ds_index != 0 ? m_gdt.base(m_ds_index) : 0; }
    gdt_x64::base_type fs_base() const override
    { return m_fs_index != 0 ? m_gdt.base(m_fs_index) : 0; }
    gdt_x64::base_type gs_base() const override
    { return m_gs_index != 0 ? m_gdt.base(m_gs_index) : 0; }
    gdt_x64::base_type ldtr_base() const override
    { return m_ldtr_index != 0 ? m_gdt.base(m_ldtr_index) : 0; }
    gdt_x64::base_type tr_base() const override
    { return m_tr_index != 0 ? m_gdt.base(m_tr_index) : 0; }

    intel_x64::msrs::value_type ia32_debugctl_msr() const override
    { return m_ia32_debugctl_msr; }
    intel_x64::msrs::value_type ia32_pat_msr() const override
    { return m_ia32_pat_msr; }
    intel_x64::msrs::value_type ia32_efer_msr() const override
    { return m_ia32_efer_msr; }
    intel_x64::msrs::value_type ia32_perf_global_ctrl_msr() const override
    { return m_ia32_perf_global_ctrl_msr; }
    intel_x64::msrs::value_type ia32_sysenter_cs_msr() const override
    { return m_ia32_sysenter_cs_msr; }
    intel_x64::msrs::value_type ia32_sysenter_esp_msr() const override
    { return m_ia32_sysenter_esp_msr; }
    intel_x64::msrs::value_type ia32_sysenter_eip_msr() const override
    { return m_ia32_sysenter_eip_msr; }
    intel_x64::msrs::value_type ia32_fs_base_msr() const override
    { return m_ia32_fs_base_msr; }
    intel_x64::msrs::value_type ia32_gs_base_msr() const override
    { return m_ia32_gs_base_msr; }

    void dump() const override
    {
        bfdebug << "----------------------------------------" << bfendl;
        bfdebug << "- vmcs_intel_x64_host_vm_state dump    -" << bfendl;
        bfdebug << "----------------------------------------" << bfendl;

        bfdebug << bfendl;
        bfdebug << "segment selectors:" << bfendl;
        bfdebug << "    - m_es: " << view_as_pointer(m_es) << bfendl;
        bfdebug << "    - m_cs: " << view_as_pointer(m_cs) << bfendl;
        bfdebug << "    - m_ss: " << view_as_pointer(m_ss) << bfendl;
        bfdebug << "    - m_ds: " << view_as_pointer(m_ds) << bfendl;
        bfdebug << "    - m_fs: " << view_as_pointer(m_fs) << bfendl;
        bfdebug << "    - m_gs: " << view_as_pointer(m_gs) << bfendl;
        bfdebug << "    - m_ldtr: " << view_as_pointer(m_ldtr) << bfendl;
        bfdebug << "    - m_tr: " << view_as_pointer(m_tr) << bfendl;

        bfdebug << bfendl;
        bfdebug << "segment base:" << bfendl;
        bfdebug << "    - es_base(): " << view_as_pointer(es_base()) << bfendl;
        bfdebug << "    - cs_base(): " << view_as_pointer(cs_base()) << bfendl;
        bfdebug << "    - ss_base(): " << view_as_pointer(ss_base()) << bfendl;
        bfdebug << "    - ds_base(): " << view_as_pointer(ds_base()) << bfendl;
        bfdebug << "    - fs_base(): " << view_as_pointer(fs_base()) << bfendl;
        bfdebug << "    - gs_base(): " << view_as_pointer(gs_base()) << bfendl;
        bfdebug << "    - ldtr_base(): " << view_as_pointer(ldtr_base()) << bfendl;
        bfdebug << "    - tr_base(): " << view_as_pointer(tr_base()) << bfendl;

        bfdebug << bfendl;
        bfdebug << "segment limit:" << bfendl;
        bfdebug << "    - es_limit(): " << view_as_pointer(es_limit()) << bfendl;
        bfdebug << "    - cs_limit(): " << view_as_pointer(cs_limit()) << bfendl;
        bfdebug << "    - ss_limit(): " << view_as_pointer(ss_limit()) << bfendl;
        bfdebug << "    - ds_limit(): " << view_as_pointer(ds_limit()) << bfendl;
        bfdebug << "    - fs_limit(): " << view_as_pointer(fs_limit()) << bfendl;
        bfdebug << "    - gs_limit(): " << view_as_pointer(gs_limit()) << bfendl;
        bfdebug << "    - ldtr_limit(): " << view_as_pointer(ldtr_limit()) << bfendl;
        bfdebug << "    - tr_limit(): " << view_as_pointer(tr_limit()) << bfendl;

        bfdebug << bfendl;
        bfdebug << "segment acess rights:" << bfendl;
        bfdebug << "    - es_access_rights(): " << view_as_pointer(es_access_rights()) << bfendl;
        bfdebug << "    - cs_access_rights(): " << view_as_pointer(cs_access_rights()) << bfendl;
        bfdebug << "    - ss_access_rights(): " << view_as_pointer(ss_access_rights()) << bfendl;
        bfdebug << "    - ds_access_rights(): " << view_as_pointer(ds_access_rights()) << bfendl;
        bfdebug << "    - fs_access_rights(): " << view_as_pointer(fs_access_rights()) << bfendl;
        bfdebug << "    - gs_access_rights(): " << view_as_pointer(gs_access_rights()) << bfendl;
        bfdebug << "    - ldtr_access_rights(): " << view_as_pointer(ldtr_access_rights()) << bfendl;
        bfdebug << "    - tr_access_rights(): " << view_as_pointer(tr_access_rights()) << bfendl;

        bfdebug << bfendl;
        bfdebug << "registers:" << bfendl;
        bfdebug << "    - m_cr0: " << view_as_pointer(m_cr0) << bfendl;
        bfdebug << "    - m_cr3: " << view_as_pointer(m_cr3) << bfendl;
        bfdebug << "    - m_cr4: " << view_as_pointer(m_cr4) << bfendl;
        bfdebug << "    - m_dr7: " << view_as_pointer(m_dr7) << bfendl;

        bfdebug << bfendl;
        bfdebug << "flags:" << bfendl;
        bfdebug << "    - m_rflags: " << view_as_pointer(m_rflags) << bfendl;

        bfdebug << bfendl;
        bfdebug << "gdt/idt:" << bfendl;
        bfdebug << "    - m_gdt.base(): " << view_as_pointer(m_gdt.base()) << bfendl;
        bfdebug << "    - m_gdt.limit(): " << view_as_pointer(m_gdt.limit()) << bfendl;
        bfdebug << "    - m_idt.base(): " << view_as_pointer(m_idt.base()) << bfendl;
        bfdebug << "    - m_idt.limit(): " << view_as_pointer(m_idt.limit()) << bfendl;

        bfdebug << bfendl;
        bfdebug << "model specific registers:" << bfendl;
        bfdebug << "    - m_ia32_debugctl_msr: " << view_as_pointer(m_ia32_debugctl_msr) << bfendl;
        bfdebug << "    - m_ia32_pat_msr: " << view_as_pointer(m_ia32_pat_msr) << bfendl;
        bfdebug << "    - m_ia32_efer_msr: " << view_as_pointer(m_ia32_efer_msr) << bfendl;
        bfdebug << "    - m_ia32_perf_global_ctrl_msr: " << view_as_pointer(m_ia32_perf_global_ctrl_msr) << bfendl;
        bfdebug << "    - m_ia32_sysenter_cs_msr: " << view_as_pointer(m_ia32_sysenter_cs_msr) << bfendl;
        bfdebug << "    - m_ia32_sysenter_esp_msr: " << view_as_pointer(m_ia32_sysenter_esp_msr) << bfendl;
        bfdebug << "    - m_ia32_sysenter_eip_msr: " << view_as_pointer(m_ia32_sysenter_eip_msr) << bfendl;
        bfdebug << "    - m_ia32_fs_base_msr: " << view_as_pointer(m_ia32_fs_base_msr) << bfendl;
        bfdebug << "    - m_ia32_gs_base_msr: " << view_as_pointer(m_ia32_gs_base_msr) << bfendl;

        bfdebug << bfendl;
    }

private:

    x64::segment_register::type m_es;
    x64::segment_register::type m_cs;
    x64::segment_register::type m_ss;
    x64::segment_register::type m_ds;
    x64::segment_register::type m_fs;
    x64::segment_register::type m_gs;
    x64::segment_register::type m_ldtr;
    x64::segment_register::type m_tr;

    x64::segment_register::type m_es_index;
    x64::segment_register::type m_cs_index;
    x64::segment_register::type m_ss_index;
    x64::segment_register::type m_ds_index;
    x64::segment_register::type m_fs_index;
    x64::segment_register::type m_gs_index;
    x64::segment_register::type m_ldtr_index;
    x64::segment_register::type m_tr_index;

    intel_x64::cr0::value_type m_cr0;
    intel_x64::cr3::value_type m_cr3;
    intel_x64::cr4::value_type m_cr4;
    x64::dr7::value_type m_dr7;

    x64::rflags::value_type m_rflags;

    gdt_x64 m_gdt;
    idt_x64 m_idt;

    intel_x64::msrs::value_type m_ia32_debugctl_msr;
    intel_x64::msrs::value_type m_ia32_pat_msr;
    intel_x64::msrs::value_type m_ia32_efer_msr;
    intel_x64::msrs::value_type m_ia32_perf_global_ctrl_msr;
    intel_x64::msrs::value_type m_ia32_sysenter_cs_msr;
    intel_x64::msrs::value_type m_ia32_sysenter_esp_msr;
    intel_x64::msrs::value_type m_ia32_sysenter_eip_msr;
    intel_x64::msrs::value_type m_ia32_fs_base_msr;
    intel_x64::msrs::value_type m_ia32_gs_base_msr;
};

#endif
