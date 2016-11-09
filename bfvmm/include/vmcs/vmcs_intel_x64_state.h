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

    virtual uint16_t es() const { return 0; }
    virtual uint16_t cs() const { return 0; }
    virtual uint16_t ss() const { return 0; }
    virtual uint16_t ds() const { return 0; }
    virtual uint16_t fs() const { return 0; }
    virtual uint16_t gs() const { return 0; }
    virtual uint16_t ldtr() const { return 0; }
    virtual uint16_t tr() const { return 0; }

    virtual void set_es(uint16_t val) { (void) val; }
    virtual void set_cs(uint16_t val) { (void) val; }
    virtual void set_ss(uint16_t val) { (void) val; }
    virtual void set_ds(uint16_t val) { (void) val; }
    virtual void set_fs(uint16_t val) { (void) val; }
    virtual void set_gs(uint16_t val) { (void) val; }
    virtual void set_ldtr(uint16_t val) { (void) val; }
    virtual void set_tr(uint16_t val) { (void) val; }

    virtual uint64_t cr0() const { return 0; }
    virtual uint64_t cr3() const { return 0; }
    virtual uint64_t cr4() const { return 0; }
    virtual uint64_t dr7() const { return 0; }

    virtual void set_cr0(uint64_t val) { (void) val; }
    virtual void set_cr3(uint64_t val) { (void) val; }
    virtual void set_cr4(uint64_t val) { (void) val; }
    virtual void set_dr7(uint64_t val) { (void) val; }

    virtual uint64_t rflags() const { return 0; }
    virtual void set_rflags(uint64_t val) { (void) val; }

    virtual uint64_t gdt_base() const { return 0; }
    virtual uint64_t idt_base() const { return 0; }

    virtual void set_gdt_base(uint64_t val) { (void) val; }
    virtual void set_idt_base(uint64_t val) { (void) val; }

    virtual uint16_t gdt_limit() const { return 0; }
    virtual uint16_t idt_limit() const { return 0; }

    virtual void set_gdt_limit(uint16_t val) { (void) val; }
    virtual void set_idt_limit(uint16_t val) { (void) val; }

    virtual uint32_t es_limit() const { return 0; }
    virtual uint32_t cs_limit() const { return 0; }
    virtual uint32_t ss_limit() const { return 0; }
    virtual uint32_t ds_limit() const { return 0; }
    virtual uint32_t fs_limit() const { return 0; }
    virtual uint32_t gs_limit() const { return 0; }
    virtual uint32_t ldtr_limit() const { return 0; }
    virtual uint32_t tr_limit() const { return 0; }

    virtual void set_es_limit(uint32_t val) { (void) val; }
    virtual void set_cs_limit(uint32_t val) { (void) val; }
    virtual void set_ss_limit(uint32_t val) { (void) val; }
    virtual void set_ds_limit(uint32_t val) { (void) val; }
    virtual void set_fs_limit(uint32_t val) { (void) val; }
    virtual void set_gs_limit(uint32_t val) { (void) val; }
    virtual void set_ldtr_limit(uint32_t val) { (void) val; }
    virtual void set_tr_limit(uint32_t val) { (void) val; }

    virtual uint32_t es_access_rights() const { return x64::access_rights::unusable; }
    virtual uint32_t cs_access_rights() const { return x64::access_rights::unusable; }
    virtual uint32_t ss_access_rights() const { return x64::access_rights::unusable; }
    virtual uint32_t ds_access_rights() const { return x64::access_rights::unusable; }
    virtual uint32_t fs_access_rights() const { return x64::access_rights::unusable; }
    virtual uint32_t gs_access_rights() const { return x64::access_rights::unusable; }
    virtual uint32_t ldtr_access_rights() const { return x64::access_rights::unusable; }
    virtual uint32_t tr_access_rights() const { return x64::access_rights::unusable; }

    virtual void set_es_access_rights(uint32_t val) { (void) val; }
    virtual void set_cs_access_rights(uint32_t val) { (void) val; }
    virtual void set_ss_access_rights(uint32_t val) { (void) val; }
    virtual void set_ds_access_rights(uint32_t val) { (void) val; }
    virtual void set_fs_access_rights(uint32_t val) { (void) val; }
    virtual void set_gs_access_rights(uint32_t val) { (void) val; }
    virtual void set_ldtr_access_rights(uint32_t val) { (void) val; }
    virtual void set_tr_access_rights(uint32_t val) { (void) val; }

    virtual uint64_t es_base() const { return 0; }
    virtual uint64_t cs_base() const { return 0; }
    virtual uint64_t ss_base() const { return 0; }
    virtual uint64_t ds_base() const { return 0; }
    virtual uint64_t fs_base() const { return 0; }
    virtual uint64_t gs_base() const { return 0; }
    virtual uint64_t ldtr_base() const { return 0; }
    virtual uint64_t tr_base() const { return 0; }

    virtual void set_es_base(uint64_t val) { (void) val; }
    virtual void set_cs_base(uint64_t val) { (void) val; }
    virtual void set_ss_base(uint64_t val) { (void) val; }
    virtual void set_ds_base(uint64_t val) { (void) val; }
    virtual void set_fs_base(uint64_t val) { (void) val; }
    virtual void set_gs_base(uint64_t val) { (void) val; }
    virtual void set_ldtr_base(uint64_t val) { (void) val; }
    virtual void set_tr_base(uint64_t val) { (void) val; }

    virtual uint64_t ia32_debugctl_msr() const { return 0; }
    virtual uint64_t ia32_pat_msr() const { return 0; }
    virtual uint64_t ia32_efer_msr() const { return 0; }
    virtual uint64_t ia32_perf_global_ctrl_msr() const { return 0; }
    virtual uint64_t ia32_sysenter_cs_msr() const { return 0; }
    virtual uint64_t ia32_sysenter_esp_msr() const { return 0; }
    virtual uint64_t ia32_sysenter_eip_msr() const { return 0; }
    virtual uint64_t ia32_fs_base_msr() const { return 0; }
    virtual uint64_t ia32_gs_base_msr() const { return 0; }

    virtual void set_ia32_debugctl_msr(uint64_t val) { (void) val; }
    virtual void set_ia32_pat_msr(uint64_t val) { (void) val; }
    virtual void set_ia32_efer_msr(uint64_t val) { (void) val; }
    virtual void set_ia32_perf_global_ctrl_msr(uint64_t val) { (void) val; }
    virtual void set_ia32_sysenter_cs_msr(uint64_t val) { (void) val; }
    virtual void set_ia32_sysenter_esp_msr(uint64_t val) { (void) val; }
    virtual void set_ia32_sysenter_eip_msr(uint64_t val) { (void) val; }
    virtual void set_ia32_fs_base_msr(uint64_t val) { (void) val; }
    virtual void set_ia32_gs_base_msr(uint64_t val) { (void) val; }

    virtual void dump() const {}
};

#endif
