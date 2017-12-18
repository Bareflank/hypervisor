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

#ifndef VMCS_INTEL_X64_VMM_STATE_H
#define VMCS_INTEL_X64_VMM_STATE_H

#include <memory>

#include <bfdebug.h>
#include <hve/arch/intel_x64/vmcs/vmcs_state.h>

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
class EXPORT_HVE vmcs_intel_x64_vmm_state : public vmcs_intel_x64_state
{
public:

    /// @cond

    vmcs_intel_x64_vmm_state();
    ~vmcs_intel_x64_vmm_state() override = default;

    x64::segment_register::value_type cs() const override
    { return m_cs; }
    x64::segment_register::value_type ss() const override
    { return m_ss; }
    x64::segment_register::value_type fs() const override
    { return m_fs; }
    x64::segment_register::value_type gs() const override
    { return m_gs; }
    x64::segment_register::value_type tr() const override
    { return m_tr; }

    intel_x64::cr0::value_type cr0() const override
    { return m_cr0; }
    intel_x64::cr3::value_type cr3() const override
    { return m_cr3; }
    intel_x64::cr4::value_type cr4() const override
    { return m_cr4; }

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

    gdt_x64::limit_type cs_limit() const override
    { return m_gdt.limit(m_cs_index); }
    gdt_x64::limit_type ss_limit() const override
    { return m_gdt.limit(m_ss_index); }
    gdt_x64::limit_type fs_limit() const override
    { return m_gdt.limit(m_fs_index); }
    gdt_x64::limit_type gs_limit() const override
    { return m_gdt.limit(m_gs_index); }
    gdt_x64::limit_type tr_limit() const override
    { return m_gdt.limit(m_tr_index); }

    gdt_x64::access_rights_type cs_access_rights() const override
    { return m_gdt.access_rights(m_cs_index); }
    gdt_x64::access_rights_type ss_access_rights() const override
    { return m_gdt.access_rights(m_ss_index); }
    gdt_x64::access_rights_type fs_access_rights() const override
    { return m_gdt.access_rights(m_fs_index); }
    gdt_x64::access_rights_type gs_access_rights() const override
    { return m_gdt.access_rights(m_gs_index); }
    gdt_x64::access_rights_type tr_access_rights() const override
    { return m_gdt.access_rights(m_tr_index); }

    gdt_x64::base_type cs_base() const override
    { return m_gdt.base(m_cs_index); }
    gdt_x64::base_type ss_base() const override
    { return m_gdt.base(m_ss_index); }
    gdt_x64::base_type fs_base() const override
    { return m_gdt.base(m_fs_index); }
    gdt_x64::base_type gs_base() const override
    { return m_gdt.base(m_gs_index); }
    gdt_x64::base_type tr_base() const override
    { return m_gdt.base(m_tr_index); }

    intel_x64::msrs::value_type ia32_pat_msr() const override
    { return m_ia32_pat_msr; }
    intel_x64::msrs::value_type ia32_efer_msr() const override
    { return m_ia32_efer_msr; }

    void dump(int level = 0, std::string *msg = nullptr) const override
    {
        bferror_lnbr(level, msg);
        bferror_info(level, "vmcs_intel_x64_vmm_state", msg);
        bferror_brk1(level, msg);

        bfdebug_info(level, "segment selectors", msg);
        bfdebug_subnhex(level, "m_cs", m_cs, msg);
        bfdebug_subnhex(level, "m_ss", m_ss, msg);
        bfdebug_subnhex(level, "m_fs", m_fs, msg);
        bfdebug_subnhex(level, "m_gs", m_gs, msg);
        bfdebug_subnhex(level, "m_tr", m_tr, msg);

        bfdebug_info(level, "segment base", msg);
        bfdebug_subnhex(level, "cs_base()", cs_base(), msg);
        bfdebug_subnhex(level, "ss_base()", ss_base(), msg);
        bfdebug_subnhex(level, "fs_base()", fs_base(), msg);
        bfdebug_subnhex(level, "gs_base()", gs_base(), msg);
        bfdebug_subnhex(level, "tr_base()", tr_base(), msg);

        bfdebug_info(level, "segment limit", msg);
        bfdebug_subnhex(level, "cs_limit()", cs_limit(), msg);
        bfdebug_subnhex(level, "ss_limit()", ss_limit(), msg);
        bfdebug_subnhex(level, "fs_limit()", fs_limit(), msg);
        bfdebug_subnhex(level, "gs_limit()", gs_limit(), msg);
        bfdebug_subnhex(level, "tr_limit()", tr_limit(), msg);

        bfdebug_info(level, "segment access rights", msg);
        bfdebug_subnhex(level, "cs_access_rights()", cs_access_rights(), msg);
        bfdebug_subnhex(level, "ss_access_rights()", ss_access_rights(), msg);
        bfdebug_subnhex(level, "fs_access_rights()", fs_access_rights(), msg);
        bfdebug_subnhex(level, "gs_access_rights()", gs_access_rights(), msg);
        bfdebug_subnhex(level, "tr_access_rights()", tr_access_rights(), msg);

        bfdebug_info(level, "registers", msg);
        bfdebug_subnhex(level, "m_cr0", m_cr0, msg);
        bfdebug_subnhex(level, "m_cr3", m_cr3, msg);
        bfdebug_subnhex(level, "m_cr4", m_cr4, msg);

        bfdebug_info(level, "flags", msg);
        bfdebug_subnhex(level, "m_rflags", m_rflags, msg);

        bfdebug_info(level, "gdt/idt", msg);
        bfdebug_subnhex(level, "m_gdt.base()", m_gdt.base(), msg);
        bfdebug_subnhex(level, "m_gdt.limit()", m_gdt.limit(), msg);
        bfdebug_subnhex(level, "m_idt.base()", m_idt.base(), msg);
        bfdebug_subnhex(level, "m_idt.limit()", m_idt.limit(), msg);

        bfdebug_info(level, "msrs", msg);
        bfdebug_subnhex(level, "m_ia32_pat_msr", m_ia32_pat_msr, msg);
        bfdebug_subnhex(level, "m_ia32_efer_msr", m_ia32_efer_msr, msg);
    }

    /// @endcond

protected:

    /// @cond

    x64::segment_register::value_type m_cs{0};
    x64::segment_register::value_type m_ss{0};
    x64::segment_register::value_type m_fs{0};
    x64::segment_register::value_type m_gs{0};
    x64::segment_register::value_type m_tr{0};

    x64::segment_register::value_type m_cs_index{0};
    x64::segment_register::value_type m_ss_index{0};
    x64::segment_register::value_type m_fs_index{0};
    x64::segment_register::value_type m_gs_index{0};
    x64::segment_register::value_type m_tr_index{0};

    intel_x64::cr0::value_type m_cr0{0};
    intel_x64::cr3::value_type m_cr3{0};
    intel_x64::cr4::value_type m_cr4{0};

    x64::rflags::value_type m_rflags{0};

    intel_x64::msrs::value_type m_ia32_pat_msr{0};
    intel_x64::msrs::value_type m_ia32_efer_msr{0};

    tss_x64 m_tss{};
    std::unique_ptr<gsl::byte[]> m_ist1;

    gdt_x64 m_gdt{512};
    idt_x64 m_idt{256};

    /// @endcond

public:

    /// @cond

    vmcs_intel_x64_vmm_state(vmcs_intel_x64_vmm_state &&) noexcept = delete;
    vmcs_intel_x64_vmm_state &operator=(vmcs_intel_x64_vmm_state &&) noexcept = delete;

    vmcs_intel_x64_vmm_state(const vmcs_intel_x64_vmm_state &) = delete;
    vmcs_intel_x64_vmm_state &operator=(const vmcs_intel_x64_vmm_state &) = delete;

    /// @endcond
};

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#endif
