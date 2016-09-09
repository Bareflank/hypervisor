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

#ifndef VMCS_INTEL_X64_VMM_STATE_H
#define VMCS_INTEL_X64_VMM_STATE_H

#include <memory>

#include <debug.h>
#include <vmcs/vmcs_intel_x64_state.h>

#include <intrinsics/gdt_x64.h>
#include <intrinsics/idt_x64.h>
#include <intrinsics/tss_x64.h>

/// VMCS VMM State
///
/// Defines the VMM's CPU state. Note that the Intel Manual calls this the
/// host state, but in our case, "host" is really reserved for the host OS
/// which is the OS that boots first (with an actual OS, or UEFI). So the
/// naming can be a little confusing. For Bareflank, the hypervisor is the
/// entire repo, so like Xen, it's a collection of everything including the
/// so called "ring -1" code, but also the drivers and user space code that
/// supports the VMM. The VMM is the code that manages
/// all of the virtual machines, which can run in both the context of the
/// host OS, but also "ring -1" which is why it needs it's own state. Short
/// answer here is, when you see "host" in the VMCS, it's really the VMM, and
/// when you see "guest", it could either be the host VM or a guest VM.
///
class vmcs_intel_x64_vmm_state : public vmcs_intel_x64_state
{
public:

    vmcs_intel_x64_vmm_state();
    ~vmcs_intel_x64_vmm_state() override = default;

    uint16_t cs() const override { return m_cs; }
    uint16_t ss() const override { return m_ss; }
    uint16_t fs() const override { return m_fs; }
    uint16_t gs() const override { return m_gs; }
    uint16_t tr() const override { return m_tr; }

    uint64_t cr0() const override { return m_cr0; }
    uint64_t cr3() const override { return m_cr3; }
    uint64_t cr4() const override { return m_cr4; }

    uint64_t rflags() const override { return m_rflags; }

    uint64_t gdt_base() const override { return m_gdt.base(); }
    uint64_t idt_base() const override { return m_idt.base(); }

    uint16_t gdt_limit() const override { return m_gdt.limit(); }
    uint16_t idt_limit() const override { return m_idt.limit(); }

    uint32_t cs_limit() const override { return m_gdt.limit(m_cs_index); }
    uint32_t ss_limit() const override { return m_gdt.limit(m_ss_index); }
    uint32_t fs_limit() const override { return m_gdt.limit(m_fs_index); }
    uint32_t gs_limit() const override { return m_gdt.limit(m_gs_index); }
    uint32_t tr_limit() const override { return m_gdt.limit(m_tr_index); }

    uint32_t cs_access_rights() const override { return m_gdt.access_rights(m_cs_index); }
    uint32_t ss_access_rights() const override { return m_gdt.access_rights(m_ss_index); }
    uint32_t fs_access_rights() const override { return m_gdt.access_rights(m_fs_index); }
    uint32_t gs_access_rights() const override { return m_gdt.access_rights(m_gs_index); }
    uint32_t tr_access_rights() const override { return m_gdt.access_rights(m_tr_index); }

    uint64_t cs_base() const override { return m_gdt.base(m_cs_index); }
    uint64_t ss_base() const override { return m_gdt.base(m_ss_index); }
    uint64_t fs_base() const override { return m_gdt.base(m_fs_index); }
    uint64_t gs_base() const override { return m_gdt.base(m_gs_index); }
    uint64_t tr_base() const override { return m_gdt.base(m_tr_index); }

    uint64_t ia32_efer_msr() const override { return m_ia32_efer_msr; }

    void dump() const override
    {
        bfdebug << "----------------------------------------" << bfendl;
        bfdebug << "- vmcs_intel_x64_vmm_state dump        -" << bfendl;
        bfdebug << "----------------------------------------" << bfendl;

        bfdebug << bfendl;
        bfdebug << "segment selectors:" << bfendl;
        bfdebug << std::setw(35) << view_as_pointer(m_cs) << bfendl;
        bfdebug << std::setw(35) << view_as_pointer(m_ss) << bfendl;
        bfdebug << std::setw(35) << view_as_pointer(m_fs) << bfendl;
        bfdebug << std::setw(35) << view_as_pointer(m_gs) << bfendl;
        bfdebug << std::setw(35) << view_as_pointer(m_tr) << bfendl;

        bfdebug << bfendl;
        bfdebug << "segment base:" << bfendl;
        bfdebug << std::setw(35) << view_as_pointer(cs_base()) << bfendl;
        bfdebug << std::setw(35) << view_as_pointer(ss_base()) << bfendl;
        bfdebug << std::setw(35) << view_as_pointer(fs_base()) << bfendl;
        bfdebug << std::setw(35) << view_as_pointer(gs_base()) << bfendl;
        bfdebug << std::setw(35) << view_as_pointer(tr_base()) << bfendl;

        bfdebug << bfendl;
        bfdebug << "segment limit:" << bfendl;
        bfdebug << std::setw(35) << view_as_pointer(cs_limit()) << bfendl;
        bfdebug << std::setw(35) << view_as_pointer(ss_limit()) << bfendl;
        bfdebug << std::setw(35) << view_as_pointer(fs_limit()) << bfendl;
        bfdebug << std::setw(35) << view_as_pointer(gs_limit()) << bfendl;
        bfdebug << std::setw(35) << view_as_pointer(tr_limit()) << bfendl;

        bfdebug << bfendl;
        bfdebug << "segment acess rights:" << bfendl;
        bfdebug << std::setw(35) << view_as_pointer(cs_access_rights()) << bfendl;
        bfdebug << std::setw(35) << view_as_pointer(ss_access_rights()) << bfendl;
        bfdebug << std::setw(35) << view_as_pointer(fs_access_rights()) << bfendl;
        bfdebug << std::setw(35) << view_as_pointer(gs_access_rights()) << bfendl;
        bfdebug << std::setw(35) << view_as_pointer(tr_access_rights()) << bfendl;

        bfdebug << bfendl;
        bfdebug << "registers:" << bfendl;
        bfdebug << std::setw(35) << view_as_pointer(m_cr0) << bfendl;
        bfdebug << std::setw(35) << view_as_pointer(m_cr3) << bfendl;
        bfdebug << std::setw(35) << view_as_pointer(m_cr4) << bfendl;

        bfdebug << bfendl;
        bfdebug << "flags:" << bfendl;
        bfdebug << std::setw(35) << view_as_pointer(m_rflags) << bfendl;

        bfdebug << bfendl;
        bfdebug << "gdt/idt:" << bfendl;
        bfdebug << std::setw(35) << view_as_pointer(m_gdt.base()) << bfendl;
        bfdebug << std::setw(35) << view_as_pointer(m_gdt.limit()) << bfendl;
        bfdebug << std::setw(35) << view_as_pointer(m_idt.base()) << bfendl;
        bfdebug << std::setw(35) << view_as_pointer(m_idt.limit()) << bfendl;

        bfdebug << bfendl;
        bfdebug << "model specific registers:" << bfendl;
        bfdebug << std::setw(35) << view_as_pointer(m_ia32_efer_msr) << bfendl;

        bfdebug << bfendl;
    }

private:

    uint16_t m_cs;
    uint16_t m_ss;
    uint16_t m_fs;
    uint16_t m_gs;
    uint16_t m_tr;

    uint16_t m_cs_index;
    uint16_t m_ss_index;
    uint16_t m_fs_index;
    uint16_t m_gs_index;
    uint16_t m_tr_index;

    uint64_t m_cr0;
    uint64_t m_cr3;
    uint64_t m_cr4;

    uint64_t m_rflags;

    tss_x64 m_tss;
    gdt_x64 m_gdt;
    idt_x64 m_idt;

    uint64_t m_ia32_efer_msr;
};

#endif
