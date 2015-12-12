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

#ifndef VMCS_INTEL_X64_H
#define VMCS_INTEL_X64_H

#include <vmcs/vmcs.h>
#include <intrinsics/intrinsics_intel_x64.h>

class vmcs_intel_x64 : public vmcs
{
public:

    /// Default Constructor
    ///
    vmcs_intel_x64();

    /// Destructor
    ///
    ~vmcs_intel_x64() {}

    /// Init VMCS
    ///
    /// Initializes the VMCS. One of the goals of this function is to decouple
    /// the intrinsics and memory manager from the VMCS so that the VMCS can
    /// be tested.
    ///
    /// @param intrinsics the intrinsics class that this VMCS will use
    /// @param memory_manager the memory manager class that this VMCS will use
    /// @return success on success, failure otherwise
    ///
    vmcs_error::type init(intrinsics *intrinsics,
                          memory_manager *memory_manager) override;

    /// Launch VMM
    ///
    vmcs_error::type launch() override;

private:

    vmcs_error::type launch_vmcs();
    vmcs_error::type resume_vmcs();

    vmcs_error::type save_state();

    vmcs_error::type create_vmcs_region();
    vmcs_error::type release_vmxon_region();

    vmcs_error::type clear_vmcs_region();
    vmcs_error::type load_vmcs_region();

    uint64_t vmcs_region_size();

    vmcs_error::type write_16bit_control_fields();
    vmcs_error::type write_16bit_guest_state_fields();
    vmcs_error::type write_16bit_host_state_fields();
    vmcs_error::type write_64bit_control_fields();
    vmcs_error::type write_64bit_guest_state_fields();
    vmcs_error::type write_64bit_host_state_fields();
    vmcs_error::type write_32bit_control_fields();
    vmcs_error::type write_32bit_guest_state_fields();
    vmcs_error::type write_32bit_host_state_fields();
    vmcs_error::type write_natural_width_control_fields();
    vmcs_error::type write_natural_width_guest_state_fields();
    vmcs_error::type write_natural_width_host_state_fields();

private:

    uint16_t m_es;
    uint16_t m_cs;
    uint16_t m_ss;
    uint16_t m_ds;
    uint16_t m_fs;
    uint16_t m_gs;
    uint16_t m_tr;
    uint16_t m_ldtr;

    uint64_t m_cr0;
    uint64_t m_cr3;
    uint64_t m_cr4;
    uint64_t m_rsp;
    uint64_t m_rflags;

    gdt_t m_gdt_reg;
    idt_t m_idt_reg;

    segment_descriptor_t *m_gdt;

    segment_descriptor_t m_es_sd;
    segment_descriptor_t m_cs_sd;
    segment_descriptor_t m_ss_sd;
    segment_descriptor_t m_ds_sd;
    segment_descriptor_t m_fs_sd;
    segment_descriptor_t m_gs_sd;
    segment_descriptor_t m_ldtr_sd;
    segment_descriptor_t m_tr_sd;

    uint64_t m_es_limit;
    uint64_t m_cs_limit;
    uint64_t m_ss_limit;
    uint64_t m_ds_limit;
    uint64_t m_fs_limit;
    uint64_t m_gs_limit;
    uint64_t m_ldtr_limit;
    uint64_t m_tr_limit;

    uint64_t m_es_access;
    uint64_t m_cs_access;
    uint64_t m_ss_access;
    uint64_t m_ds_access;
    uint64_t m_fs_access;
    uint64_t m_gs_access;
    uint64_t m_ldtr_access;
    uint64_t m_tr_access;

    uint64_t m_es_base;
    uint64_t m_cs_base;
    uint64_t m_ss_base;
    uint64_t m_ds_base;
    uint64_t m_fs_base;
    uint64_t m_gs_base;
    uint64_t m_ldtr_base;
    uint64_t m_tr_base;

    memory_manager *m_mm;
    intrinsics_intel_x64 *m_i;

    page m_vmcs_region;
};

#endif
