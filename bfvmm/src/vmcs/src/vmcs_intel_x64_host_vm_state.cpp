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

#include <vmcs/vmcs_intel_x64_host_vm_state.h>

using namespace x64;
using namespace intel_x64;

vmcs_intel_x64_host_vm_state::vmcs_intel_x64_host_vm_state() :
    m_gdt{},
    m_idt{}
{
    m_es = segment_register::es::get();
    m_cs = segment_register::cs::get();
    m_ss = segment_register::ss::get();
    m_ds = segment_register::ds::get();
    m_fs = segment_register::fs::get();
    m_gs = segment_register::gs::get();
    m_ldtr = segment_register::ldtr::get();
    m_tr = segment_register::tr::get();

    m_es_index = segment_register::es::index::get();
    m_cs_index = segment_register::cs::index::get();
    m_ss_index = segment_register::ss::index::get();
    m_ds_index = segment_register::ds::index::get();
    m_fs_index = segment_register::fs::index::get();
    m_gs_index = segment_register::gs::index::get();
    m_ldtr_index = segment_register::ldtr::index::get();
    m_tr_index = segment_register::tr::index::get();

    m_cr0 = cr0::get();
    m_cr3 = cr3::get();
    m_cr4 = cr4::get() | cr4::vmx_enable_bit::mask;
    m_dr7 = dr7::get();

    m_rflags = rflags::get();

    m_ia32_debugctl_msr = msrs::ia32_debugctl::get();
    m_ia32_pat_msr = msrs::ia32_pat::get();
    m_ia32_efer_msr = msrs::ia32_efer::get();
    m_ia32_perf_global_ctrl_msr = msrs::ia32_perf_global_ctrl::get();
    m_ia32_sysenter_cs_msr = msrs::ia32_sysenter_cs::get();
    m_ia32_sysenter_esp_msr = msrs::ia32_sysenter_esp::get();
    m_ia32_sysenter_eip_msr = msrs::ia32_sysenter_eip::get();
    m_ia32_fs_base_msr = msrs::ia32_fs_base::get();
    m_ia32_gs_base_msr = msrs::ia32_gs_base::get();
}
