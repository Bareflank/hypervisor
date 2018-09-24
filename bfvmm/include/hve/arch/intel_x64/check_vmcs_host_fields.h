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

#ifndef VMCS_INTEL_X64_CHECK_HOST_H
#define VMCS_INTEL_X64_CHECK_HOST_H

/// Intel x86_64 VMCS Check Host
///
/// This namespace implements the host checks found in
/// section 26.2.2, Vol. 3 of the SDM.
///

namespace bfvmm
{
namespace intel_x64
{
namespace check
{

void host_cr0_for_unsupported_bits();
void host_cr4_for_unsupported_bits();
void host_cr3_for_unsupported_bits();
void host_ia32_sysenter_esp_canonical_address();
void host_ia32_sysenter_eip_canonical_address();
void host_verify_load_ia32_perf_global_ctrl();
void host_verify_load_ia32_pat();
void host_verify_load_ia32_efer();
void host_es_selector_rpl_ti_equal_zero();
void host_cs_selector_rpl_ti_equal_zero();
void host_ss_selector_rpl_ti_equal_zero();
void host_ds_selector_rpl_ti_equal_zero();
void host_fs_selector_rpl_ti_equal_zero();
void host_gs_selector_rpl_ti_equal_zero();
void host_tr_selector_rpl_ti_equal_zero();
void host_cs_not_equal_zero();
void host_tr_not_equal_zero();
void host_ss_not_equal_zero();
void host_fs_canonical_base_address();
void host_gs_canonical_base_address();
void host_gdtr_canonical_base_address();
void host_idtr_canonical_base_address();
void host_tr_canonical_base_address();
void host_if_outside_ia32e_mode();
void host_address_space_size_exit_ctl_is_set();
void host_address_space_disabled();
void host_address_space_enabled();

}
}
}

#endif
