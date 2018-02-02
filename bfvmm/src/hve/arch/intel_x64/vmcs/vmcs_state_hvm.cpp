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

#include <intrinsics.h>
#include <hve/arch/intel_x64/vmcs/vmcs_state_hvm.h>

namespace bfvmm
{
namespace intel_x64
{

vmcs_state_hvm::vmcs_state_hvm()
{
    m_es = ::x64::segment_register::es::get();
    m_cs = ::x64::segment_register::cs::get();
    m_ss = ::x64::segment_register::ss::get();
    m_ds = ::x64::segment_register::ds::get();
    m_fs = ::x64::segment_register::fs::get();
    m_gs = ::x64::segment_register::gs::get();
    m_ldtr = ::x64::segment_register::ldtr::get();
    m_tr = ::x64::segment_register::tr::get();

    m_es_index = ::x64::segment_register::es::index::get();
    m_cs_index = ::x64::segment_register::cs::index::get();
    m_ss_index = ::x64::segment_register::ss::index::get();
    m_ds_index = ::x64::segment_register::ds::index::get();
    m_fs_index = ::x64::segment_register::fs::index::get();
    m_gs_index = ::x64::segment_register::gs::index::get();
    m_ldtr_index = ::x64::segment_register::ldtr::index::get();
    m_tr_index = ::x64::segment_register::tr::index::get();

    m_cr0 = ::intel_x64::cr0::get();
    m_cr3 = ::intel_x64::cr3::get();
    m_cr4 = ::intel_x64::cr4::get() | ::intel_x64::cr4::vmx_enable_bit::mask;
    m_dr7 = ::intel_x64::dr7::get();

    m_rflags = ::x64::rflags::get();

    m_ia32_debugctl_msr = ::intel_x64::msrs::ia32_debugctl::get();
    m_ia32_pat_msr = ::x64::msrs::ia32_pat::get();
    m_ia32_efer_msr = ::intel_x64::msrs::ia32_efer::get();

    if (::intel_x64::cpuid::arch_perf_monitoring::eax::version_id::get() >= 2) {
        m_ia32_perf_global_ctrl_msr = ::intel_x64::msrs::ia32_perf_global_ctrl::get();
    }

    m_ia32_sysenter_cs_msr = ::intel_x64::msrs::ia32_sysenter_cs::get();
    m_ia32_sysenter_esp_msr = ::intel_x64::msrs::ia32_sysenter_esp::get();
    m_ia32_sysenter_eip_msr = ::intel_x64::msrs::ia32_sysenter_eip::get();
    m_ia32_fs_base_msr = ::intel_x64::msrs::ia32_fs_base::get();
    m_ia32_gs_base_msr = ::intel_x64::msrs::ia32_gs_base::get();
}

}
}
