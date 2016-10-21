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
#include <vmcs/vmcs_intel_x64_state.h>

#include <intrinsics/gdt_x64.h>
#include <intrinsics/idt_x64.h>

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

    uint16_t es() const override { return m_es; }
    uint16_t cs() const override { return m_cs; }
    uint16_t ss() const override { return m_ss; }
    uint16_t ds() const override { return m_ds; }
    uint16_t fs() const override { return m_fs; }
    uint16_t gs() const override { return m_gs; }
    uint16_t ldtr() const override { return m_ldtr; }
    uint16_t tr() const override { return m_tr; }

    uint64_t cr0() const override { return m_cr0; }
    uint64_t cr3() const override { return m_cr3; }
    uint64_t cr4() const override { return m_cr4; }
    uint64_t dr7() const override { return m_dr7; }

    uint64_t rflags() const override { return m_rflags; }

    uint64_t gdt_base() const override { return m_gdt.base(); }
    uint64_t idt_base() const override { return m_idt.base(); }

    uint16_t gdt_limit() const override { return m_gdt.limit(); }
    uint16_t idt_limit() const override { return m_idt.limit(); }

    uint32_t es_limit() const override { return m_gdt.limit(m_es_index); }
    uint32_t cs_limit() const override { return m_gdt.limit(m_cs_index); }
    uint32_t ss_limit() const override { return m_gdt.limit(m_ss_index); }
    uint32_t ds_limit() const override { return m_gdt.limit(m_ds_index); }
    uint32_t fs_limit() const override { return m_gdt.limit(m_fs_index); }
    uint32_t gs_limit() const override { return m_gdt.limit(m_gs_index); }
    uint32_t ldtr_limit() const override { return m_gdt.limit(m_ldtr_index); }
    uint32_t tr_limit() const override { return m_gdt.limit(m_tr_index); }

    uint32_t es_access_rights() const override { return m_gdt.access_rights(m_es_index); }
    uint32_t cs_access_rights() const override { return m_gdt.access_rights(m_cs_index); }
    uint32_t ss_access_rights() const override { return m_gdt.access_rights(m_ss_index); }
    uint32_t ds_access_rights() const override { return m_gdt.access_rights(m_ds_index); }
    uint32_t fs_access_rights() const override { return m_gdt.access_rights(m_fs_index); }
    uint32_t gs_access_rights() const override { return m_gdt.access_rights(m_gs_index); }
    uint32_t ldtr_access_rights() const override { return m_gdt.access_rights(m_ldtr_index); }
    uint32_t tr_access_rights() const override { return m_gdt.access_rights(m_tr_index); }

    uint64_t es_base() const override { return m_gdt.base(m_es_index); }
    uint64_t cs_base() const override { return m_gdt.base(m_cs_index); }
    uint64_t ss_base() const override { return m_gdt.base(m_ss_index); }
    uint64_t ds_base() const override { return m_gdt.base(m_ds_index); }
    uint64_t fs_base() const override { return m_gdt.base(m_fs_index); }
    uint64_t gs_base() const override { return m_gdt.base(m_gs_index); }
    uint64_t ldtr_base() const override { return m_gdt.base(m_ldtr_index); }
    uint64_t tr_base() const override { return m_gdt.base(m_tr_index); }

    uint64_t ia32_debugctl_msr() const override { return m_ia32_debugctl_msr; }
    uint64_t ia32_pat_msr() const override { return m_ia32_pat_msr; }
    uint64_t ia32_efer_msr() const override { return m_ia32_efer_msr; }
    uint64_t ia32_perf_global_ctrl_msr() const override { return m_ia32_perf_global_ctrl_msr; }
    uint64_t ia32_sysenter_cs_msr() const override { return m_ia32_sysenter_cs_msr; }
    uint64_t ia32_sysenter_esp_msr() const override { return m_ia32_sysenter_esp_msr; }
    uint64_t ia32_sysenter_eip_msr() const override { return m_ia32_sysenter_eip_msr; }
    uint64_t ia32_fs_base_msr() const override { return m_ia32_fs_base_msr; }
    uint64_t ia32_gs_base_msr() const override { return m_ia32_gs_base_msr; }

    void dump() const override
    {
        bfdebug << "----------------------------------------" << bfendl;
        bfdebug << "- vmcs_intel_x64_host_vm_state dump    -" << bfendl;
        bfdebug << "----------------------------------------" << bfendl;

        bfdebug << bfendl;
        bfdebug << "segment selectors:" << bfendl;
        PRINT_STATE(m_es);
        PRINT_STATE(m_cs);
        PRINT_STATE(m_ss);
        PRINT_STATE(m_ds);
        PRINT_STATE(m_fs);
        PRINT_STATE(m_gs);
        PRINT_STATE(m_ldtr);
        PRINT_STATE(m_tr);

        bfdebug << bfendl;
        bfdebug << "segment base:" << bfendl;
        PRINT_STATE(es_base());
        PRINT_STATE(cs_base());
        PRINT_STATE(ss_base());
        PRINT_STATE(ds_base());
        PRINT_STATE(fs_base());
        PRINT_STATE(gs_base());
        PRINT_STATE(ldtr_base());
        PRINT_STATE(tr_base());

        bfdebug << bfendl;
        bfdebug << "segment limit:" << bfendl;
        PRINT_STATE(es_limit());
        PRINT_STATE(cs_limit());
        PRINT_STATE(ss_limit());
        PRINT_STATE(ds_limit());
        PRINT_STATE(fs_limit());
        PRINT_STATE(gs_limit());
        PRINT_STATE(ldtr_limit());
        PRINT_STATE(tr_limit());

        bfdebug << bfendl;
        bfdebug << "segment acess rights:" << bfendl;
        PRINT_STATE(es_access_rights());
        PRINT_STATE(cs_access_rights());
        PRINT_STATE(ss_access_rights());
        PRINT_STATE(ds_access_rights());
        PRINT_STATE(fs_access_rights());
        PRINT_STATE(gs_access_rights());
        PRINT_STATE(ldtr_access_rights());
        PRINT_STATE(tr_access_rights());

        bfdebug << bfendl;
        bfdebug << "registers:" << bfendl;
        PRINT_STATE(m_cr0);
        PRINT_STATE(m_cr3);
        PRINT_STATE(m_cr4);
        PRINT_STATE(m_dr7);

        bfdebug << bfendl;
        bfdebug << "flags:" << bfendl;
        PRINT_STATE(m_rflags);

        bfdebug << bfendl;
        bfdebug << "gdt/idt:" << bfendl;
        PRINT_STATE(m_gdt.base());
        PRINT_STATE(m_gdt.limit());
        PRINT_STATE(m_idt.base());
        PRINT_STATE(m_idt.limit());

        bfdebug << bfendl;
        bfdebug << "model specific registers:" << bfendl;
        PRINT_STATE(m_ia32_debugctl_msr);
        PRINT_STATE(m_ia32_pat_msr);
        PRINT_STATE(m_ia32_efer_msr);
        PRINT_STATE(m_ia32_perf_global_ctrl_msr);
        PRINT_STATE(m_ia32_sysenter_cs_msr);
        PRINT_STATE(m_ia32_sysenter_esp_msr);
        PRINT_STATE(m_ia32_sysenter_eip_msr);
        PRINT_STATE(m_ia32_fs_base_msr);
        PRINT_STATE(m_ia32_gs_base_msr);

        bfdebug << bfendl;
    }

private:

    uint16_t m_es;
    uint16_t m_cs;
    uint16_t m_ss;
    uint16_t m_ds;
    uint16_t m_fs;
    uint16_t m_gs;
    uint16_t m_ldtr;
    uint16_t m_tr;

    uint16_t m_es_index;
    uint16_t m_cs_index;
    uint16_t m_ss_index;
    uint16_t m_ds_index;
    uint16_t m_fs_index;
    uint16_t m_gs_index;
    uint16_t m_ldtr_index;
    uint16_t m_tr_index;

    uint64_t m_cr0;
    uint64_t m_cr3;
    uint64_t m_cr4;
    uint64_t m_dr7;

    uint64_t m_rflags;

    gdt_x64 m_gdt;
    idt_x64 m_idt;

    uint64_t m_ia32_debugctl_msr;
    uint64_t m_ia32_pat_msr;
    uint64_t m_ia32_efer_msr;
    uint64_t m_ia32_perf_global_ctrl_msr;
    uint64_t m_ia32_sysenter_cs_msr;
    uint64_t m_ia32_sysenter_esp_msr;
    uint64_t m_ia32_sysenter_eip_msr;
    uint64_t m_ia32_fs_base_msr;
    uint64_t m_ia32_gs_base_msr;
};

#endif
