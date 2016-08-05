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

vmcs_intel_x64_host_vm_state::vmcs_intel_x64_host_vm_state(const std::shared_ptr<intrinsics_intel_x64> &intrinsics) :
    m_gdt(std::static_pointer_cast<intrinsics_x64>(intrinsics)),
    m_idt(std::static_pointer_cast<intrinsics_x64>(intrinsics))
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

    m_es_index = m_es >> 3;
    m_cs_index = m_cs >> 3;
    m_ss_index = m_ss >> 3;
    m_ds_index = m_ds >> 3;
    m_fs_index = m_fs >> 3;
    m_gs_index = m_gs >> 3;
    m_ldtr_index = m_ldtr >> 3;
    m_tr_index = m_tr >> 3;

    m_cr0 = intrinsics->read_cr0();
    m_cr3 = intrinsics->read_cr3();
    m_cr4 = intrinsics->read_cr4();
    m_dr7 = intrinsics->read_dr7();

    m_cr4 |= CR4_VMXE_VMX_ENABLE_BIT;

    m_rflags = intrinsics->read_rflags();

    m_ia32_debugctl_msr = intrinsics->read_msr(IA32_DEBUGCTL_MSR);
    m_ia32_pat_msr = intrinsics->read_msr(IA32_PAT_MSR);
    m_ia32_efer_msr = intrinsics->read_msr(IA32_EFER_MSR);
    m_ia32_perf_global_ctrl_msr = intrinsics->read_msr(IA32_PERF_GLOBAL_CTRL_MSR);
    m_ia32_sysenter_cs_msr = intrinsics->read_msr(IA32_SYSENTER_CS_MSR);
    m_ia32_sysenter_esp_msr = intrinsics->read_msr(IA32_SYSENTER_ESP_MSR);
    m_ia32_sysenter_eip_msr = intrinsics->read_msr(IA32_SYSENTER_EIP_MSR);
    m_ia32_fs_base_msr = intrinsics->read_msr(IA32_FS_BASE_MSR);
    m_ia32_gs_base_msr = intrinsics->read_msr(IA32_GS_BASE_MSR);
}
