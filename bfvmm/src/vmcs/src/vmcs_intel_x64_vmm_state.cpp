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

#include <vmcs/vmcs_intel_x64_vmm_state.h>
#include <memory_manager/root_page_table_x64.h>

#include <intrinsics/crs_intel_x64.h>
#include <intrinsics/msrs_intel_x64.h>

using namespace x64;
using namespace intel_x64;

vmcs_intel_x64_vmm_state::vmcs_intel_x64_vmm_state() :
    m_gdt{7},
    m_idt{256}
{
    m_gdt.set_access_rights(0, 0);
    m_gdt.set_access_rights(1, access_rights::ring0_cs_descriptor);
    m_gdt.set_access_rights(2, access_rights::ring0_ss_descriptor);
    m_gdt.set_access_rights(3, access_rights::ring0_fs_descriptor);
    m_gdt.set_access_rights(4, access_rights::ring0_gs_descriptor);
    m_gdt.set_access_rights(5, access_rights::ring0_tr_descriptor);

    m_gdt.set_base(0, 0);
    m_gdt.set_base(1, 0);
    m_gdt.set_base(2, 0);
    m_gdt.set_base(3, 0);
    m_gdt.set_base(4, 0);
    m_gdt.set_base(5, reinterpret_cast<uint64_t>(&m_tss));

    m_gdt.set_limit(0, 0);
    m_gdt.set_limit(1, 0xFFFFFFFF);
    m_gdt.set_limit(2, 0xFFFFFFFF);
    m_gdt.set_limit(3, 0xFFFFFFFF);
    m_gdt.set_limit(4, 0xFFFFFFFF);
    m_gdt.set_limit(5, sizeof(m_tss));

    m_cs_index = 1;
    m_ss_index = 2;
    m_fs_index = 3;
    m_gs_index = 4;
    m_tr_index = 5;

    m_cs = gsl::narrow_cast<uint16_t>(m_cs_index << 3);
    m_ss = gsl::narrow_cast<uint16_t>(m_ss_index << 3);
    m_fs = gsl::narrow_cast<uint16_t>(m_fs_index << 3);
    m_gs = gsl::narrow_cast<uint16_t>(m_gs_index << 3);
    m_tr = gsl::narrow_cast<uint16_t>(m_tr_index << 3);

    m_cr0 = 0;
    m_cr0 |= cr0::protection_enable::mask;
    m_cr0 |= cr0::monitor_coprocessor::mask;
    m_cr0 |= cr0::extension_type::mask;
    m_cr0 |= cr0::numeric_error::mask;
    m_cr0 |= cr0::write_protect::mask;
    m_cr0 |= cr0::paging::mask;

    m_cr3 = g_pt->phys_addr();

    m_cr4 = 0;
    m_cr4 |= cr4::physical_address_extensions::mask;
    m_cr4 |= cr4::page_global_enable::mask;
    m_cr4 |= cr4::vmx_enable_bit::mask;
    m_cr4 |= cr4::osfxsr::mask;
    m_cr4 |= cr4::osxsave::mask;

    m_rflags = 0;

    m_ia32_efer_msr = 0;
    m_ia32_efer_msr |= msrs::ia32_efer::lme::mask;
    m_ia32_efer_msr |= msrs::ia32_efer::lma::mask;
    m_ia32_efer_msr |= msrs::ia32_efer::nxe::mask;
}
