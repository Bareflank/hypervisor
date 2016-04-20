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

#ifndef VMCS_STATE_INTEL_X64_H
#define VMCS_STATE_INTEL_X64_H

#include <memory>

#include <debug.h>
#include <intrinsics/intrinsics_intel_x64.h>

#define PRINT_STATE(a) \
    bfdebug << std::left << std::setw(35) << #a \
            << std::hex << "0x" << m_##a << std::dec << bfendl;

/// VMCS State
///
/// Generic class that stores the CPU state that is intended when setting up
/// a VMCS. Note that two of these are needed for each VMCS; one for the
/// guest and one for the host.
///
class vmcs_intel_x64_state
{
public:

    vmcs_intel_x64_state() :
        m_es(0),
        m_cs(0),
        m_ss(0),
        m_ds(0),
        m_fs(0),
        m_gs(0),
        m_tr(0),
        m_cr0(0),
        m_cr3(0),
        m_cr4(0),
        m_dr7(0),
        m_rflags(0),
        m_gdt_reg{0, 0},
        m_idt_reg{0, 0},
        m_es_limit(0),
        m_cs_limit(0),
        m_ss_limit(0),
        m_ds_limit(0),
        m_fs_limit(0),
        m_gs_limit(0),
        m_tr_limit(0),
        m_es_access(0),
        m_cs_access(0),
        m_ss_access(0),
        m_ds_access(0),
        m_fs_access(0),
        m_gs_access(0),
        m_tr_access(0),
        m_es_base(0),
        m_cs_base(0),
        m_ss_base(0),
        m_ds_base(0),
        m_fs_base(0),
        m_gs_base(0),
        m_tr_base(0),
        m_ia32_debugctl_msr(0),
        m_ia32_pat_msr(0),
        m_ia32_efer_msr(0),
        m_ia32_vmx_pinbased_ctls_msr(0),
        m_ia32_vmx_procbased_ctls_msr(0),
        m_ia32_vmx_exit_ctls_msr(0),
        m_ia32_vmx_entry_ctls_msr(0),
        m_ia32_sysenter_cs_msr(0),
        m_ia32_sysenter_esp_msr(0),
        m_ia32_sysenter_eip_msr(0),
        m_ia32_fs_base_msr(0),
        m_ia32_gs_base_msr(0)
    {}

    vmcs_intel_x64_state(const std::shared_ptr<intrinsics_intel_x64> &intrinsics) :
        m_es(0),
        m_cs(0),
        m_ss(0),
        m_ds(0),
        m_fs(0),
        m_gs(0),
        m_tr(0),
        m_cr0(0),
        m_cr3(0),
        m_cr4(0),
        m_dr7(0),
        m_rflags(0),
        m_gdt_reg{0, 0},
        m_idt_reg{0, 0},
        m_es_limit(0),
        m_cs_limit(0),
        m_ss_limit(0),
        m_ds_limit(0),
        m_fs_limit(0),
        m_gs_limit(0),
        m_tr_limit(0),
        m_es_access(0),
        m_cs_access(0),
        m_ss_access(0),
        m_ds_access(0),
        m_fs_access(0),
        m_gs_access(0),
        m_tr_access(0),
        m_es_base(0),
        m_cs_base(0),
        m_ss_base(0),
        m_ds_base(0),
        m_fs_base(0),
        m_gs_base(0),
        m_tr_base(0),
        m_ia32_debugctl_msr(0),
        m_ia32_pat_msr(0),
        m_ia32_efer_msr(0),
        m_ia32_vmx_pinbased_ctls_msr(0),
        m_ia32_vmx_procbased_ctls_msr(0),
        m_ia32_vmx_exit_ctls_msr(0),
        m_ia32_vmx_entry_ctls_msr(0),
        m_ia32_sysenter_cs_msr(0),
        m_ia32_sysenter_esp_msr(0),
        m_ia32_sysenter_eip_msr(0),
        m_ia32_fs_base_msr(0),
        m_ia32_gs_base_msr(0)
    {
        if (!intrinsics)
            return;

        m_es = intrinsics->read_es();
        m_cs = intrinsics->read_cs();
        m_ss = intrinsics->read_ss();
        m_ds = intrinsics->read_ds();
        m_fs = intrinsics->read_fs();
        m_gs = intrinsics->read_gs();
        m_tr = intrinsics->read_tr();

        m_cr0 = intrinsics->read_cr0();
        m_cr3 = intrinsics->read_cr3();
        m_cr4 = intrinsics->read_cr4();
        m_dr7 = intrinsics->read_dr7();

        m_rflags = intrinsics->read_rflags();

        intrinsics->read_gdt(&m_gdt_reg);
        intrinsics->read_idt(&m_idt_reg);

        m_es_limit = intrinsics->segment_descriptor_limit(m_es);
        m_cs_limit = intrinsics->segment_descriptor_limit(m_cs);
        m_ss_limit = intrinsics->segment_descriptor_limit(m_ss);
        m_ds_limit = intrinsics->segment_descriptor_limit(m_ds);
        m_fs_limit = intrinsics->segment_descriptor_limit(m_fs);
        m_gs_limit = intrinsics->segment_descriptor_limit(m_gs);
        m_tr_limit = intrinsics->segment_descriptor_limit(m_tr);

        m_es_access = intrinsics->segment_descriptor_access(m_es);
        m_cs_access = intrinsics->segment_descriptor_access(m_cs);
        m_ss_access = intrinsics->segment_descriptor_access(m_ss);
        m_ds_access = intrinsics->segment_descriptor_access(m_ds);
        m_fs_access = intrinsics->segment_descriptor_access(m_fs);
        m_gs_access = intrinsics->segment_descriptor_access(m_gs);
        m_tr_access = intrinsics->segment_descriptor_access(m_tr);

        m_es_base = intrinsics->segment_descriptor_base(m_es);
        m_cs_base = intrinsics->segment_descriptor_base(m_cs);
        m_ss_base = intrinsics->segment_descriptor_base(m_ss);
        m_ds_base = intrinsics->segment_descriptor_base(m_ds);
        m_fs_base = intrinsics->segment_descriptor_base(m_fs);
        m_gs_base = intrinsics->segment_descriptor_base(m_gs);
        m_tr_base = intrinsics->segment_descriptor_base(m_tr);

        m_ia32_debugctl_msr = intrinsics->read_msr(IA32_DEBUGCTL_MSR);
        m_ia32_pat_msr = intrinsics->read_msr(IA32_PAT_MSR);
        m_ia32_efer_msr = intrinsics->read_msr(IA32_EFER_MSR);
        m_ia32_sysenter_cs_msr = intrinsics->read_msr(IA32_SYSENTER_CS_MSR);
        m_ia32_sysenter_esp_msr = intrinsics->read_msr(IA32_SYSENTER_ESP_MSR);
        m_ia32_sysenter_eip_msr = intrinsics->read_msr(IA32_SYSENTER_EIP_MSR);
        m_ia32_fs_base_msr = intrinsics->read_msr(IA32_FS_BASE_MSR);
        m_ia32_gs_base_msr = intrinsics->read_msr(IA32_GS_BASE_MSR);
    }

    ~vmcs_intel_x64_state() {}

    uint16_t es() const
    { return m_es; }

    uint16_t cs() const
    { return m_cs; }

    uint16_t ss() const
    { return m_ss; }

    uint16_t ds() const
    { return m_ds; }

    uint16_t fs() const
    { return m_fs; }

    uint16_t gs() const
    { return m_gs; }

    uint16_t tr() const
    { return m_tr; }

    void set_es(uint16_t val)
    { m_es = val; }

    void set_cs(uint16_t val)
    { m_cs = val; }

    void set_ss(uint16_t val)
    { m_ss = val; }

    void set_ds(uint16_t val)
    { m_ds = val; }

    void set_fs(uint16_t val)
    { m_fs = val; }

    void set_gs(uint16_t val)
    { m_gs = val; }

    void set_tr(uint16_t val)
    { m_tr = val; }

    uint64_t cr0() const
    { return m_cr0; }

    uint64_t cr3() const
    { return m_cr3; }

    uint64_t cr4() const
    { return m_cr4; }

    uint64_t dr7() const
    { return m_dr7; }

    void set_cr0(uint64_t val)
    { m_cr0 = val; }

    void set_cr3(uint64_t val)
    { m_cr3 = val; }

    void set_cr4(uint64_t val)
    { m_cr4 = val; }

    void set_dr7(uint64_t val)
    { m_dr7 = val; }

    uint64_t rflags() const
    { return m_rflags; }

    void set_rflags(uint64_t val)
    { m_rflags = val; }

    gdt_t gdt() const
    { return m_gdt_reg; }

    idt_t idt() const
    { return m_idt_reg; }

    void set_gdt(gdt_t val)
    { m_gdt_reg = val; }

    void set_idt(idt_t val)
    { m_idt_reg = val; }

    uint32_t es_limit() const
    { return m_es_limit; }

    uint32_t cs_limit() const
    { return m_cs_limit; }

    uint32_t ss_limit() const
    { return m_ss_limit; }

    uint32_t ds_limit() const
    { return m_ds_limit; }

    uint32_t fs_limit() const
    { return m_fs_limit; }

    uint32_t gs_limit() const
    { return m_gs_limit; }

    uint32_t tr_limit() const
    { return m_tr_limit; }

    void set_es_limit(uint32_t val)
    { m_es_limit = val; }

    void set_cs_limit(uint32_t val)
    { m_cs_limit = val; }

    void set_ss_limit(uint32_t val)
    { m_ss_limit = val; }

    void set_ds_limit(uint32_t val)
    { m_ds_limit = val; }

    void set_fs_limit(uint32_t val)
    { m_fs_limit = val; }

    void set_gs_limit(uint32_t val)
    { m_gs_limit = val; }

    void set_tr_limit(uint32_t val)
    { m_tr_limit = val; }

    uint32_t es_access() const
    { return m_es_access; }

    uint32_t cs_access() const
    { return m_cs_access; }

    uint32_t ss_access() const
    { return m_ss_access; }

    uint32_t ds_access() const
    { return m_ds_access; }

    uint32_t fs_access() const
    { return m_fs_access; }

    uint32_t gs_access() const
    { return m_gs_access; }

    uint32_t tr_access() const
    { return m_tr_access; }

    void set_es_access(uint32_t val)
    { m_es_access = val; }

    void set_cs_access(uint32_t val)
    { m_cs_access = val; }

    void set_ss_access(uint32_t val)
    { m_ss_access = val; }

    void set_ds_access(uint32_t val)
    { m_ds_access = val; }

    void set_fs_access(uint32_t val)
    { m_fs_access = val; }

    void set_gs_access(uint32_t val)
    { m_gs_access = val; }

    void set_tr_access(uint32_t val)
    { m_tr_access = val; }

    uint64_t es_base() const
    { return m_es_base; }

    uint64_t cs_base() const
    { return m_cs_base; }

    uint64_t ss_base() const
    { return m_ss_base; }

    uint64_t ds_base() const
    { return m_ds_base; }

    uint64_t fs_base() const
    { return m_fs_base; }

    uint64_t gs_base() const
    { return m_gs_base; }

    uint64_t tr_base() const
    { return m_tr_base; }

    void set_es_base(uint64_t val)
    { m_es_base = val; }

    void set_cs_base(uint64_t val)
    { m_cs_base = val; }

    void set_ss_base(uint64_t val)
    { m_ss_base = val; }

    void set_ds_base(uint64_t val)
    { m_ds_base = val; }

    void set_fs_base(uint64_t val)
    { m_fs_base = val; }

    void set_gs_base(uint64_t val)
    { m_gs_base = val; }

    void set_tr_base(uint64_t val)
    { m_tr_base = val; }

    uint64_t ia32_debugctl_msr() const
    { return m_ia32_debugctl_msr; }

    uint64_t ia32_pat_msr() const
    { return m_ia32_pat_msr; }

    uint64_t ia32_efer_msr() const
    { return m_ia32_efer_msr; }

    uint64_t ia32_vmx_pinbased_ctls_msr() const
    { return m_ia32_vmx_pinbased_ctls_msr; }

    uint64_t ia32_vmx_procbased_ctls_msr() const
    { return m_ia32_vmx_procbased_ctls_msr; }

    uint64_t ia32_vmx_exit_ctls_msr() const
    { return m_ia32_vmx_exit_ctls_msr; }

    uint64_t ia32_vmx_entry_ctls_msr() const
    { return m_ia32_vmx_entry_ctls_msr; }

    uint64_t ia32_sysenter_cs_msr() const
    { return m_ia32_sysenter_cs_msr; }

    uint64_t ia32_sysenter_esp_msr() const
    { return m_ia32_sysenter_esp_msr; }

    uint64_t ia32_sysenter_eip_msr() const
    { return m_ia32_sysenter_eip_msr; }

    uint64_t ia32_fs_base_msr() const
    { return m_ia32_fs_base_msr; }

    uint64_t ia32_gs_base_msr() const
    { return m_ia32_gs_base_msr; }

    void set_ia32_debugctl_msr(uint64_t val)
    { m_ia32_debugctl_msr = val; }

    void set_ia32_pat_msr(uint64_t val)
    { m_ia32_pat_msr = val; }

    void set_ia32_efer_msr(uint64_t val)
    { m_ia32_efer_msr = val; }

    void set_ia32_vmx_pinbased_ctls_msr(uint64_t val)
    { m_ia32_vmx_pinbased_ctls_msr = val; }

    void set_ia32_vmx_procbased_ctls_msr(uint64_t val)
    { m_ia32_vmx_procbased_ctls_msr = val; }

    void set_ia32_vmx_exit_ctls_msr(uint64_t val)
    { m_ia32_vmx_exit_ctls_msr = val; }

    void set_ia32_vmx_entry_ctls_msr(uint64_t val)
    { m_ia32_vmx_entry_ctls_msr = val; }

    void set_ia32_sysenter_cs_msr(uint64_t val)
    { m_ia32_sysenter_cs_msr = val; }

    void set_ia32_sysenter_esp_msr(uint64_t val)
    { m_ia32_sysenter_esp_msr = val; }

    void set_ia32_sysenter_eip_msr(uint64_t val)
    { m_ia32_sysenter_eip_msr = val; }

    void set_ia32_fs_base_msr(uint64_t val)
    { m_ia32_fs_base_msr = val; }

    void set_ia32_gs_base_msr(uint64_t val)
    { m_ia32_gs_base_msr = val; }

    void dump(const std::string &name) const
    {
        bfdebug << "----------------------------------------" << bfendl;
        bfdebug << "- State Dump: " << name << bfendl;
        bfdebug << "----------------------------------------" << bfendl;

        bfdebug << bfendl;
        bfdebug << "Segment Selectors:" << bfendl;
        PRINT_STATE(es);
        PRINT_STATE(cs);
        PRINT_STATE(ss);
        PRINT_STATE(ds);
        PRINT_STATE(fs);
        PRINT_STATE(gs);
        PRINT_STATE(tr);

        bfdebug << bfendl;
        bfdebug << "Registers:" << bfendl;
        PRINT_STATE(cr0);
        PRINT_STATE(cr3);
        PRINT_STATE(cr4);
        PRINT_STATE(dr7);

        bfdebug << bfendl;
        bfdebug << "Flags:" << bfendl;
        PRINT_STATE(rflags);

        bfdebug << bfendl;
        bfdebug << "GDT/IDT:" << bfendl;
        PRINT_STATE(gdt_reg.limit);
        PRINT_STATE(gdt_reg.base);
        PRINT_STATE(idt_reg.limit);
        PRINT_STATE(idt_reg.base);

        bfdebug << bfendl;
        bfdebug << "Segment Limit:" << bfendl;
        PRINT_STATE(es_limit);
        PRINT_STATE(cs_limit);
        PRINT_STATE(ss_limit);
        PRINT_STATE(ds_limit);
        PRINT_STATE(fs_limit);
        PRINT_STATE(gs_limit);
        PRINT_STATE(tr_limit);

        bfdebug << bfendl;
        bfdebug << "Segment Access:" << bfendl;
        PRINT_STATE(es_access);
        PRINT_STATE(cs_access);
        PRINT_STATE(ss_access);
        PRINT_STATE(ds_access);
        PRINT_STATE(fs_access);
        PRINT_STATE(gs_access);
        PRINT_STATE(tr_access);

        bfdebug << bfendl;
        bfdebug << "Segment Base:" << bfendl;
        PRINT_STATE(es_base);
        PRINT_STATE(cs_base);
        PRINT_STATE(ss_base);
        PRINT_STATE(ds_base);
        PRINT_STATE(fs_base);
        PRINT_STATE(gs_base);
        PRINT_STATE(tr_base);

        bfdebug << bfendl;
        bfdebug << "MSRs:" << bfendl;
        PRINT_STATE(ia32_debugctl_msr);
        PRINT_STATE(ia32_pat_msr);
        PRINT_STATE(ia32_efer_msr);
        PRINT_STATE(ia32_vmx_pinbased_ctls_msr);
        PRINT_STATE(ia32_vmx_procbased_ctls_msr);
        PRINT_STATE(ia32_vmx_exit_ctls_msr);
        PRINT_STATE(ia32_vmx_entry_ctls_msr);
        PRINT_STATE(ia32_sysenter_cs_msr);
        PRINT_STATE(ia32_sysenter_esp_msr);
        PRINT_STATE(ia32_sysenter_eip_msr);
        PRINT_STATE(ia32_fs_base_msr);
        PRINT_STATE(ia32_gs_base_msr);

        bfdebug << bfendl;
    }

private:

    uint16_t m_es;
    uint16_t m_cs;
    uint16_t m_ss;
    uint16_t m_ds;
    uint16_t m_fs;
    uint16_t m_gs;
    uint16_t m_tr;

    uint64_t m_cr0;
    uint64_t m_cr3;
    uint64_t m_cr4;
    uint64_t m_dr7;

    uint64_t m_rflags;

    gdt_t m_gdt_reg;
    idt_t m_idt_reg;

    uint32_t m_es_limit;
    uint32_t m_cs_limit;
    uint32_t m_ss_limit;
    uint32_t m_ds_limit;
    uint32_t m_fs_limit;
    uint32_t m_gs_limit;
    uint32_t m_tr_limit;

    uint32_t m_es_access;
    uint32_t m_cs_access;
    uint32_t m_ss_access;
    uint32_t m_ds_access;
    uint32_t m_fs_access;
    uint32_t m_gs_access;
    uint32_t m_tr_access;

    uint64_t m_es_base;
    uint64_t m_cs_base;
    uint64_t m_ss_base;
    uint64_t m_ds_base;
    uint64_t m_fs_base;
    uint64_t m_gs_base;
    uint64_t m_tr_base;

    uint64_t m_ia32_debugctl_msr;
    uint64_t m_ia32_pat_msr;
    uint64_t m_ia32_efer_msr;
    uint64_t m_ia32_vmx_pinbased_ctls_msr;
    uint64_t m_ia32_vmx_procbased_ctls_msr;
    uint64_t m_ia32_vmx_exit_ctls_msr;
    uint64_t m_ia32_vmx_entry_ctls_msr;
    uint64_t m_ia32_sysenter_cs_msr;
    uint64_t m_ia32_sysenter_esp_msr;
    uint64_t m_ia32_sysenter_eip_msr;
    uint64_t m_ia32_fs_base_msr;
    uint64_t m_ia32_gs_base_msr;
};

#endif
