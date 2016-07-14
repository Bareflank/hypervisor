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

#include <debug.h>

#define PRINT_STATE(a) \
    bfdebug << std::left << std::setw(35) << #a \
            << std::hex << "0x" << a << std::dec << bfendl;

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

    vmcs_intel_x64_state() {}
    virtual ~vmcs_intel_x64_state() {}

    virtual uint16_t es() const { return 0; }
    virtual uint16_t cs() const { return 0; }
    virtual uint16_t ss() const { return 0; }
    virtual uint16_t ds() const { return 0; }
    virtual uint16_t fs() const { return 0; }
    virtual uint16_t gs() const { return 0; }
    virtual uint16_t tr() const { return 0; }

    virtual uint64_t cr0() const { return 0; }
    virtual uint64_t cr3() const { return 0; }
    virtual uint64_t cr4() const { return 0; }
    virtual uint64_t dr7() const { return 0; }

    virtual uint64_t rflags() const { return 0; }

    virtual uint64_t gdt_base() const { return 0; }
    virtual uint64_t idt_base() const { return 0; }

    virtual uint16_t gdt_limit() const { return 0; }
    virtual uint16_t idt_limit() const { return 0; }

    virtual uint32_t es_limit() const { return 0; }
    virtual uint32_t cs_limit() const { return 0; }
    virtual uint32_t ss_limit() const { return 0; }
    virtual uint32_t ds_limit() const { return 0; }
    virtual uint32_t fs_limit() const { return 0; }
    virtual uint32_t gs_limit() const { return 0; }
    virtual uint32_t tr_limit() const { return 0; }

    virtual uint32_t es_access_rights() const { return 0x10000; }
    virtual uint32_t cs_access_rights() const { return 0x10000; }
    virtual uint32_t ss_access_rights() const { return 0x10000; }
    virtual uint32_t ds_access_rights() const { return 0x10000; }
    virtual uint32_t fs_access_rights() const { return 0x10000; }
    virtual uint32_t gs_access_rights() const { return 0x10000; }
    virtual uint32_t tr_access_rights() const { return 0x10000; }

    virtual uint64_t es_base() const { return 0; }
    virtual uint64_t cs_base() const { return 0; }
    virtual uint64_t ss_base() const { return 0; }
    virtual uint64_t ds_base() const { return 0; }
    virtual uint64_t fs_base() const { return 0; }
    virtual uint64_t gs_base() const { return 0; }
    virtual uint64_t tr_base() const { return 0; }

    virtual uint64_t ia32_debugctl_msr() const { return 0; }
    virtual uint64_t ia32_pat_msr() const { return 0; }
    virtual uint64_t ia32_efer_msr() const { return 0; }
    virtual uint64_t ia32_perf_global_ctrl_msr() const { return 0; }
    virtual uint64_t ia32_sysenter_cs_msr() const { return 0; }
    virtual uint64_t ia32_sysenter_esp_msr() const { return 0; }
    virtual uint64_t ia32_sysenter_eip_msr() const { return 0; }
    virtual uint64_t ia32_fs_base_msr() const { return 0; }
    virtual uint64_t ia32_gs_base_msr() const { return 0; }

    virtual void dump() const {}
};

#endif
