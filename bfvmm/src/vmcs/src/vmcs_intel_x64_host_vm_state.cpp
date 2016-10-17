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

using namespace intel_x64;

vmcs_intel_x64_host_vm_state::vmcs_intel_x64_host_vm_state(const std::shared_ptr<intrinsics_intel_x64> &intrinsics)
{
    if (!intrinsics)
        throw std::invalid_argument("intrinsics == nullptr");

    m_es = intrinsics->read_es();
    m_cs = intrinsics->read_cs();
    m_ss = intrinsics->read_ss();
    m_ds = intrinsics->read_ds();
    m_fs = intrinsics->read_fs();
    m_gs = intrinsics->read_gs();
    m_ldtr = intrinsics->read_ldtr();
    m_tr = intrinsics->read_tr();

    // REMOVE ME: The bit shift should go into the namespace logic. When you
    // do this, make sure the VMCS logic also has this as it could be useful
    // there too
    m_es_index = static_cast<uint16_t>(m_es >> 3);
    m_cs_index = static_cast<uint16_t>(m_cs >> 3);
    m_ss_index = static_cast<uint16_t>(m_ss >> 3);
    m_ds_index = static_cast<uint16_t>(m_ds >> 3);
    m_fs_index = static_cast<uint16_t>(m_fs >> 3);
    m_gs_index = static_cast<uint16_t>(m_gs >> 3);
    m_ldtr_index = static_cast<uint16_t>(m_ldtr >> 3);
    m_tr_index = static_cast<uint16_t>(m_tr >> 3);

    m_cr0 = cr0::get();
    m_cr3 = cr3::get();
    m_cr4 = cr4::get() | cr4::vmx_enable_bit::mask;
    m_dr7 = intrinsics->read_dr7();

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
