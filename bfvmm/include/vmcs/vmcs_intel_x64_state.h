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

#ifndef VMCS_INTEL_X64_STATE_H
#define VMCS_INTEL_X64_STATE_H

#include <intrinsics/x64.h>
#include <intrinsics/gdt_x64.h>
#include <intrinsics/idt_x64.h>
#include <intrinsics/tss_x64.h>
#include <intrinsics/srs_x64.h>
#include <intrinsics/debug_x64.h>
#include <intrinsics/rflags_x64.h>
#include <intrinsics/crs_intel_x64.h>
#include <intrinsics/msrs_intel_x64.h>

/// VMCS State
///
/// This is a base class that other classes inherit to define the state
/// needed for a VMCS. Think of a VMCS has a collection of two different
/// sets of state, a VMM state, and a VM state. This class is used to define
/// either one. For example, to setup the Host VM (the VM that is running
/// the Host OS, or in other words, the OS that was running prior to the
/// hypervisor, which in some cases might be UEFI) you will need two different
/// VMCS state classes: one for the VMM to define the environment for the
/// exit handler, and one for the host OS, which defines the current state
/// of the host.
///
/// Another way to look at this class is, each one defines 1/2 of the VMCS
/// which allows us to mix and match different inheritted versions of this
/// class to create different VMCSs (like a Host VM, or a Guest VM).
///
/// Note that this class should not be used directly as it's all 0's, but
/// when you inherit this class, you do not need to implement all of the
/// functions. If you intended for a value to be 0 (or unusable), use
/// the defaults that this class provides.
///
class vmcs_intel_x64_state
{
public:

    vmcs_intel_x64_state() = default;
    virtual ~vmcs_intel_x64_state() = default;

    virtual x64::segment_register::type es() const
    { return 0; }
    virtual x64::segment_register::type cs() const
    { return 0; }
    virtual x64::segment_register::type ss() const
    { return 0; }
    virtual x64::segment_register::type ds() const
    { return 0; }
    virtual x64::segment_register::type fs() const
    { return 0; }
    virtual x64::segment_register::type gs() const
    { return 0; }
    virtual x64::segment_register::type ldtr() const
    { return 0; }
    virtual x64::segment_register::type tr() const
    { return 0; }

    virtual void set_es(x64::segment_register::type val)
    { (void) val; }
    virtual void set_cs(x64::segment_register::type val)
    { (void) val; }
    virtual void set_ss(x64::segment_register::type val)
    { (void) val; }
    virtual void set_ds(x64::segment_register::type val)
    { (void) val; }
    virtual void set_fs(x64::segment_register::type val)
    { (void) val; }
    virtual void set_gs(x64::segment_register::type val)
    { (void) val; }
    virtual void set_ldtr(x64::segment_register::type val)
    { (void) val; }
    virtual void set_tr(x64::segment_register::type val)
    { (void) val; }

    virtual intel_x64::cr0::value_type cr0() const
    { return 0; }
    virtual intel_x64::cr3::value_type cr3() const
    { return 0; }
    virtual intel_x64::cr4::value_type cr4() const
    { return 0; }
    virtual x64::dr7::value_type dr7() const
    { return 0; }

    virtual void set_cr0(intel_x64::cr0::value_type val)
    { (void) val; }
    virtual void set_cr3(intel_x64::cr3::value_type val)
    { (void) val; }
    virtual void set_cr4(intel_x64::cr4::value_type val)
    { (void) val; }
    virtual void set_dr7(x64::dr7::value_type val)
    { (void) val; }

    virtual x64::rflags::value_type rflags() const
    { return 0; }
    virtual void set_rflags(x64::rflags::value_type val)
    { (void) val; }

    virtual gdt_x64::integer_pointer gdt_base() const
    { return 0; }
    virtual idt_x64::integer_pointer idt_base() const
    { return 0; }

    virtual void set_gdt_base(gdt_x64::integer_pointer val)
    { (void) val; }
    virtual void set_idt_base(idt_x64::integer_pointer val)
    { (void) val; }

    virtual gdt_x64::size_type gdt_limit() const
    { return 0; }
    virtual idt_x64::size_type idt_limit() const
    { return 0; }

    virtual void set_gdt_limit(gdt_x64::size_type val)
    { (void) val; }
    virtual void set_idt_limit(idt_x64::size_type val)
    { (void) val; }

    virtual gdt_x64::limit_type es_limit() const
    { return 0; }
    virtual gdt_x64::limit_type cs_limit() const
    { return 0; }
    virtual gdt_x64::limit_type ss_limit() const
    { return 0; }
    virtual gdt_x64::limit_type ds_limit() const
    { return 0; }
    virtual gdt_x64::limit_type fs_limit() const
    { return 0; }
    virtual gdt_x64::limit_type gs_limit() const
    { return 0; }
    virtual gdt_x64::limit_type ldtr_limit() const
    { return 0; }
    virtual gdt_x64::limit_type tr_limit() const
    { return 0; }

    virtual void set_es_limit(gdt_x64::limit_type val)
    { (void) val; }
    virtual void set_cs_limit(gdt_x64::limit_type val)
    { (void) val; }
    virtual void set_ss_limit(gdt_x64::limit_type val)
    { (void) val; }
    virtual void set_ds_limit(gdt_x64::limit_type val)
    { (void) val; }
    virtual void set_fs_limit(gdt_x64::limit_type val)
    { (void) val; }
    virtual void set_gs_limit(gdt_x64::limit_type val)
    { (void) val; }
    virtual void set_ldtr_limit(gdt_x64::limit_type val)
    { (void) val; }
    virtual void set_tr_limit(gdt_x64::limit_type val)
    { (void) val; }

    virtual gdt_x64::access_rights_type es_access_rights() const
    { return x64::access_rights::unusable; }
    virtual gdt_x64::access_rights_type cs_access_rights() const
    { return x64::access_rights::unusable; }
    virtual gdt_x64::access_rights_type ss_access_rights() const
    { return x64::access_rights::unusable; }
    virtual gdt_x64::access_rights_type ds_access_rights() const
    { return x64::access_rights::unusable; }
    virtual gdt_x64::access_rights_type fs_access_rights() const
    { return x64::access_rights::unusable; }
    virtual gdt_x64::access_rights_type gs_access_rights() const
    { return x64::access_rights::unusable; }
    virtual gdt_x64::access_rights_type ldtr_access_rights() const
    { return x64::access_rights::unusable; }
    virtual gdt_x64::access_rights_type tr_access_rights() const
    { return x64::access_rights::unusable; }

    virtual void set_es_access_rights(gdt_x64::access_rights_type val)
    { (void) val; }
    virtual void set_cs_access_rights(gdt_x64::access_rights_type val)
    { (void) val; }
    virtual void set_ss_access_rights(gdt_x64::access_rights_type val)
    { (void) val; }
    virtual void set_ds_access_rights(gdt_x64::access_rights_type val)
    { (void) val; }
    virtual void set_fs_access_rights(gdt_x64::access_rights_type val)
    { (void) val; }
    virtual void set_gs_access_rights(gdt_x64::access_rights_type val)
    { (void) val; }
    virtual void set_ldtr_access_rights(gdt_x64::access_rights_type val)
    { (void) val; }
    virtual void set_tr_access_rights(gdt_x64::access_rights_type val)
    { (void) val; }

    virtual gdt_x64::base_type es_base() const
    { return 0; }
    virtual gdt_x64::base_type cs_base() const
    { return 0; }
    virtual gdt_x64::base_type ss_base() const
    { return 0; }
    virtual gdt_x64::base_type ds_base() const
    { return 0; }
    virtual gdt_x64::base_type fs_base() const
    { return 0; }
    virtual gdt_x64::base_type gs_base() const
    { return 0; }
    virtual gdt_x64::base_type ldtr_base() const
    { return 0; }
    virtual gdt_x64::base_type tr_base() const
    { return 0; }

    virtual void set_es_base(gdt_x64::base_type val)
    { (void) val; }
    virtual void set_cs_base(gdt_x64::base_type val)
    { (void) val; }
    virtual void set_ss_base(gdt_x64::base_type val)
    { (void) val; }
    virtual void set_ds_base(gdt_x64::base_type val)
    { (void) val; }
    virtual void set_fs_base(gdt_x64::base_type val)
    { (void) val; }
    virtual void set_gs_base(gdt_x64::base_type val)
    { (void) val; }
    virtual void set_ldtr_base(gdt_x64::base_type val)
    { (void) val; }
    virtual void set_tr_base(gdt_x64::base_type val)
    { (void) val; }

    virtual intel_x64::msrs::value_type ia32_debugctl_msr() const
    { return 0; }
    virtual intel_x64::msrs::value_type ia32_pat_msr() const
    { return 0; }
    virtual intel_x64::msrs::value_type ia32_efer_msr() const
    { return 0; }
    virtual intel_x64::msrs::value_type ia32_perf_global_ctrl_msr() const
    { return 0; }
    virtual intel_x64::msrs::value_type ia32_sysenter_cs_msr() const
    { return 0; }
    virtual intel_x64::msrs::value_type ia32_sysenter_esp_msr() const
    { return 0; }
    virtual intel_x64::msrs::value_type ia32_sysenter_eip_msr() const
    { return 0; }
    virtual intel_x64::msrs::value_type ia32_fs_base_msr() const
    { return 0; }
    virtual intel_x64::msrs::value_type ia32_gs_base_msr() const
    { return 0; }

    virtual void set_ia32_debugctl_msr(intel_x64::msrs::value_type val)
    { (void) val; }
    virtual void set_ia32_pat_msr(intel_x64::msrs::value_type val)
    { (void) val; }
    virtual void set_ia32_efer_msr(intel_x64::msrs::value_type val)
    { (void) val; }
    virtual void set_ia32_perf_global_ctrl_msr(intel_x64::msrs::value_type val)
    { (void) val; }
    virtual void set_ia32_sysenter_cs_msr(intel_x64::msrs::value_type val)
    { (void) val; }
    virtual void set_ia32_sysenter_esp_msr(intel_x64::msrs::value_type val)
    { (void) val; }
    virtual void set_ia32_sysenter_eip_msr(intel_x64::msrs::value_type val)
    { (void) val; }
    virtual void set_ia32_fs_base_msr(intel_x64::msrs::value_type val)
    { (void) val; }
    virtual void set_ia32_gs_base_msr(intel_x64::msrs::value_type val)
    { (void) val; }

    virtual void dump() const {}
};

#endif
