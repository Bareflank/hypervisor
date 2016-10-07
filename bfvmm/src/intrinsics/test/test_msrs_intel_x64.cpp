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

#include <test.h>
#include <intrinsics/msrs_intel_x64.h>

using namespace intel_x64;

std::map<uint32_t, uint64_t> g_msrs;

extern "C" uint64_t
__read_msr(uint32_t msr) noexcept
{
    return g_msrs[msr];
}

void
intrinsics_ut::test_ia32_feature_control()
{
    g_msrs[msrs::ia32_feature_control::addr] = 100UL;
    this->expect_true(msrs::ia32_feature_control::get() == 100UL);
}

void
intrinsics_ut::test_ia32_feature_control_lock_bit()
{
    auto mask = msrs::ia32_feature_control::lock_bit::mask;
    auto from = msrs::ia32_feature_control::lock_bit::from;

    g_msrs[msrs::ia32_feature_control::addr] = mask;
    this->expect_true(msrs::ia32_feature_control::lock_bit::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_feature_control_enable_vmx_inside_smx()
{
    auto mask = msrs::ia32_feature_control::enable_vmx_inside_smx::mask;
    auto from = msrs::ia32_feature_control::enable_vmx_inside_smx::from;

    g_msrs[msrs::ia32_feature_control::addr] = mask;
    this->expect_true(msrs::ia32_feature_control::enable_vmx_inside_smx::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_feature_control_enable_vmx_outside_smx()
{
    auto mask = msrs::ia32_feature_control::enable_vmx_outside_smx::mask;
    auto from = msrs::ia32_feature_control::enable_vmx_outside_smx::from;

    g_msrs[msrs::ia32_feature_control::addr] = mask;
    this->expect_true(msrs::ia32_feature_control::enable_vmx_outside_smx::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_basic()
{
    g_msrs[msrs::ia32_vmx_basic::addr] = 100UL;
    this->expect_true(msrs::ia32_vmx_basic::get() == 100UL);
}

void
intrinsics_ut::test_ia32_vmx_basic_revision_id()
{
    auto mask = msrs::ia32_vmx_basic::revision_id::mask;
    auto from = msrs::ia32_vmx_basic::revision_id::from;

    g_msrs[msrs::ia32_vmx_basic::addr] = mask;
    this->expect_true(msrs::ia32_vmx_basic::revision_id::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_basic_vmxon_vmcs_region_size()
{
    auto mask = msrs::ia32_vmx_basic::vmxon_vmcs_region_size::mask;
    auto from = msrs::ia32_vmx_basic::vmxon_vmcs_region_size::from;

    g_msrs[msrs::ia32_vmx_basic::addr] = mask;
    this->expect_true(msrs::ia32_vmx_basic::vmxon_vmcs_region_size::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_basic_physical_address_width()
{
    auto mask = msrs::ia32_vmx_basic::physical_address_width::mask;
    auto from = msrs::ia32_vmx_basic::physical_address_width::from;

    g_msrs[msrs::ia32_vmx_basic::addr] = mask;
    this->expect_true(msrs::ia32_vmx_basic::physical_address_width::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_basic_dual_monitor_mode_support()
{
    auto mask = msrs::ia32_vmx_basic::dual_monitor_mode_support::mask;
    auto from = msrs::ia32_vmx_basic::dual_monitor_mode_support::from;

    g_msrs[msrs::ia32_vmx_basic::addr] = mask;
    this->expect_true(msrs::ia32_vmx_basic::dual_monitor_mode_support::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_basic_memory_type()
{
    auto mask = msrs::ia32_vmx_basic::memory_type::mask;
    auto from = msrs::ia32_vmx_basic::memory_type::from;

    g_msrs[msrs::ia32_vmx_basic::addr] = mask;
    this->expect_true(msrs::ia32_vmx_basic::memory_type::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_basic_ins_outs_exit_information()
{
    auto mask = msrs::ia32_vmx_basic::ins_outs_exit_information::mask;
    auto from = msrs::ia32_vmx_basic::ins_outs_exit_information::from;

    g_msrs[msrs::ia32_vmx_basic::addr] = mask;
    this->expect_true(msrs::ia32_vmx_basic::ins_outs_exit_information::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_basic_true_based_controls()
{
    auto mask = msrs::ia32_vmx_basic::true_based_controls::mask;
    auto from = msrs::ia32_vmx_basic::true_based_controls::from;

    g_msrs[msrs::ia32_vmx_basic::addr] = mask;
    this->expect_true(msrs::ia32_vmx_basic::true_based_controls::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_misc()
{
    g_msrs[msrs::ia32_vmx_misc::addr] = 100UL;
    this->expect_true(msrs::ia32_vmx_misc::get() == 100UL);
}

void
intrinsics_ut::test_ia32_vmx_misc_preemption_timer_decrement()
{
    auto mask = msrs::ia32_vmx_misc::preemption_timer_decrement::mask;
    auto from = msrs::ia32_vmx_misc::preemption_timer_decrement::from;

    g_msrs[msrs::ia32_vmx_misc::addr] = mask;
    this->expect_true(msrs::ia32_vmx_misc::preemption_timer_decrement::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_misc_store_efer_lma_on_vm_exit()
{
    auto mask = msrs::ia32_vmx_misc::store_efer_lma_on_vm_exit::mask;
    auto from = msrs::ia32_vmx_misc::store_efer_lma_on_vm_exit::from;

    g_msrs[msrs::ia32_vmx_misc::addr] = mask;
    this->expect_true(msrs::ia32_vmx_misc::store_efer_lma_on_vm_exit::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_misc_activity_state_hlt_support()
{
    auto mask = msrs::ia32_vmx_misc::activity_state_hlt_support::mask;
    auto from = msrs::ia32_vmx_misc::activity_state_hlt_support::from;

    g_msrs[msrs::ia32_vmx_misc::addr] = mask;
    this->expect_true(msrs::ia32_vmx_misc::activity_state_hlt_support::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_misc_activity_state_shutdown_support()
{
    auto mask = msrs::ia32_vmx_misc::activity_state_shutdown_support::mask;
    auto from = msrs::ia32_vmx_misc::activity_state_shutdown_support::from;

    g_msrs[msrs::ia32_vmx_misc::addr] = mask;
    this->expect_true(msrs::ia32_vmx_misc::activity_state_shutdown_support::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_misc_activity_state_wait_for_sipi_support()
{
    auto mask = msrs::ia32_vmx_misc::activity_state_wait_for_sipi_support::mask;
    auto from = msrs::ia32_vmx_misc::activity_state_wait_for_sipi_support::from;

    g_msrs[msrs::ia32_vmx_misc::addr] = mask;
    this->expect_true(msrs::ia32_vmx_misc::activity_state_wait_for_sipi_support::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_misc_processor_trace_support()
{
    auto mask = msrs::ia32_vmx_misc::processor_trace_support::mask;
    auto from = msrs::ia32_vmx_misc::processor_trace_support::from;

    g_msrs[msrs::ia32_vmx_misc::addr] = mask;
    this->expect_true(msrs::ia32_vmx_misc::processor_trace_support::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_misc_rdmsr_in_smm_support()
{
    auto mask = msrs::ia32_vmx_misc::rdmsr_in_smm_support::mask;
    auto from = msrs::ia32_vmx_misc::rdmsr_in_smm_support::from;

    g_msrs[msrs::ia32_vmx_misc::addr] = mask;
    this->expect_true(msrs::ia32_vmx_misc::rdmsr_in_smm_support::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_misc_cr3_targets()
{
    auto mask = msrs::ia32_vmx_misc::cr3_targets::mask;
    auto from = msrs::ia32_vmx_misc::cr3_targets::from;

    g_msrs[msrs::ia32_vmx_misc::addr] = mask;
    this->expect_true(msrs::ia32_vmx_misc::cr3_targets::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_misc_max_num_msr_load_store_on_exit()
{
    auto mask = msrs::ia32_vmx_misc::max_num_msr_load_store_on_exit::mask;
    auto from = msrs::ia32_vmx_misc::max_num_msr_load_store_on_exit::from;

    g_msrs[msrs::ia32_vmx_misc::addr] = mask;
    this->expect_true(msrs::ia32_vmx_misc::max_num_msr_load_store_on_exit::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_misc_vmxoff_blocked_smi_support()
{
    auto mask = msrs::ia32_vmx_misc::vmxoff_blocked_smi_support::mask;
    auto from = msrs::ia32_vmx_misc::vmxoff_blocked_smi_support::from;

    g_msrs[msrs::ia32_vmx_misc::addr] = mask;
    this->expect_true(msrs::ia32_vmx_misc::vmxoff_blocked_smi_support::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_misc_vmwrite_all_fields_support()
{
    auto mask = msrs::ia32_vmx_misc::vmwrite_all_fields_support::mask;
    auto from = msrs::ia32_vmx_misc::vmwrite_all_fields_support::from;

    g_msrs[msrs::ia32_vmx_misc::addr] = mask;
    this->expect_true(msrs::ia32_vmx_misc::vmwrite_all_fields_support::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_misc_injection_with_instruction_length_of_zero()
{
    auto mask = msrs::ia32_vmx_misc::injection_with_instruction_length_of_zero::mask;
    auto from = msrs::ia32_vmx_misc::injection_with_instruction_length_of_zero::from;

    g_msrs[msrs::ia32_vmx_misc::addr] = mask;
    this->expect_true(msrs::ia32_vmx_misc::injection_with_instruction_length_of_zero::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_cr0_fixed0()
{
    g_msrs[msrs::ia32_vmx_cr0_fixed0::addr] = 100UL;
    this->expect_true(msrs::ia32_vmx_cr0_fixed0::get() == 100UL);
}

void
intrinsics_ut::test_ia32_vmx_cr0_fixed1()
{
    g_msrs[msrs::ia32_vmx_cr0_fixed1::addr] = 100UL;
    this->expect_true(msrs::ia32_vmx_cr0_fixed1::get() == 100UL);
}

void
intrinsics_ut::test_ia32_vmx_cr4_fixed0()
{
    g_msrs[msrs::ia32_vmx_cr4_fixed0::addr] = 100UL;
    this->expect_true(msrs::ia32_vmx_cr4_fixed0::get() == 100UL);
}

void
intrinsics_ut::test_ia32_vmx_cr4_fixed1()
{
    g_msrs[msrs::ia32_vmx_cr4_fixed1::addr] = 100UL;
    this->expect_true(msrs::ia32_vmx_cr4_fixed1::get() == 100UL);
}

void
intrinsics_ut::test_ia32_vmx_procbased_ctls2()
{
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 100UL;
    this->expect_true(msrs::ia32_vmx_procbased_ctls2::get() == 100UL);
}

void
intrinsics_ut::test_ia32_vmx_procbased_ctls2_virtualize_apic_accesses()
{
    auto mask = msrs::ia32_vmx_procbased_ctls2::virtualize_apic_accesses::mask;
    auto from = msrs::ia32_vmx_procbased_ctls2::virtualize_apic_accesses::from;

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = mask;
    this->expect_true(msrs::ia32_vmx_procbased_ctls2::virtualize_apic_accesses::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_procbased_ctls2_enable_ept()
{
    auto mask = msrs::ia32_vmx_procbased_ctls2::enable_ept::mask;
    auto from = msrs::ia32_vmx_procbased_ctls2::enable_ept::from;

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = mask;
    this->expect_true(msrs::ia32_vmx_procbased_ctls2::enable_ept::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_procbased_ctls2_descriptor_table_exiting()
{
    auto mask = msrs::ia32_vmx_procbased_ctls2::descriptor_table_exiting::mask;
    auto from = msrs::ia32_vmx_procbased_ctls2::descriptor_table_exiting::from;

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = mask;
    this->expect_true(msrs::ia32_vmx_procbased_ctls2::descriptor_table_exiting::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_procbased_ctls2_enable_rdtscp()
{
    auto mask = msrs::ia32_vmx_procbased_ctls2::enable_rdtscp::mask;
    auto from = msrs::ia32_vmx_procbased_ctls2::enable_rdtscp::from;

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = mask;
    this->expect_true(msrs::ia32_vmx_procbased_ctls2::enable_rdtscp::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_procbased_ctls2_virtualize_x2apic_mode()
{
    auto mask = msrs::ia32_vmx_procbased_ctls2::virtualize_x2apic_mode::mask;
    auto from = msrs::ia32_vmx_procbased_ctls2::virtualize_x2apic_mode::from;

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = mask;
    this->expect_true(msrs::ia32_vmx_procbased_ctls2::virtualize_x2apic_mode::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_procbased_ctls2_enable_vpid()
{
    auto mask = msrs::ia32_vmx_procbased_ctls2::enable_vpid::mask;
    auto from = msrs::ia32_vmx_procbased_ctls2::enable_vpid::from;

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = mask;
    this->expect_true(msrs::ia32_vmx_procbased_ctls2::enable_vpid::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_procbased_ctls2_wbinvd_exiting()
{
    auto mask = msrs::ia32_vmx_procbased_ctls2::wbinvd_exiting::mask;
    auto from = msrs::ia32_vmx_procbased_ctls2::wbinvd_exiting::from;

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = mask;
    this->expect_true(msrs::ia32_vmx_procbased_ctls2::wbinvd_exiting::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_procbased_ctls2_unrestricted_guest()
{
    auto mask = msrs::ia32_vmx_procbased_ctls2::unrestricted_guest::mask;
    auto from = msrs::ia32_vmx_procbased_ctls2::unrestricted_guest::from;

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = mask;
    this->expect_true(msrs::ia32_vmx_procbased_ctls2::unrestricted_guest::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_procbased_ctls2_apic_register_virtualization()
{
    auto mask = msrs::ia32_vmx_procbased_ctls2::apic_register_virtualization::mask;
    auto from = msrs::ia32_vmx_procbased_ctls2::apic_register_virtualization::from;

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = mask;
    this->expect_true(msrs::ia32_vmx_procbased_ctls2::apic_register_virtualization::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_procbased_ctls2_virtual_interrupt_delivery()
{
    auto mask = msrs::ia32_vmx_procbased_ctls2::virtual_interrupt_delivery::mask;
    auto from = msrs::ia32_vmx_procbased_ctls2::virtual_interrupt_delivery::from;

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = mask;
    this->expect_true(msrs::ia32_vmx_procbased_ctls2::virtual_interrupt_delivery::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_procbased_ctls2_pause_loop_exiting()
{
    auto mask = msrs::ia32_vmx_procbased_ctls2::pause_loop_exiting::mask;
    auto from = msrs::ia32_vmx_procbased_ctls2::pause_loop_exiting::from;

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = mask;
    this->expect_true(msrs::ia32_vmx_procbased_ctls2::pause_loop_exiting::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_procbased_ctls2_rdrand_exiting()
{
    auto mask = msrs::ia32_vmx_procbased_ctls2::rdrand_exiting::mask;
    auto from = msrs::ia32_vmx_procbased_ctls2::rdrand_exiting::from;

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = mask;
    this->expect_true(msrs::ia32_vmx_procbased_ctls2::rdrand_exiting::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_procbased_ctls2_enable_invpcid()
{
    auto mask = msrs::ia32_vmx_procbased_ctls2::enable_invpcid::mask;
    auto from = msrs::ia32_vmx_procbased_ctls2::enable_invpcid::from;

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = mask;
    this->expect_true(msrs::ia32_vmx_procbased_ctls2::enable_invpcid::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_procbased_ctls2_enable_vm_functions()
{
    auto mask = msrs::ia32_vmx_procbased_ctls2::enable_vm_functions::mask;
    auto from = msrs::ia32_vmx_procbased_ctls2::enable_vm_functions::from;

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = mask;
    this->expect_true(msrs::ia32_vmx_procbased_ctls2::enable_vm_functions::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_procbased_ctls2_vmcs_shadowing()
{
    auto mask = msrs::ia32_vmx_procbased_ctls2::vmcs_shadowing::mask;
    auto from = msrs::ia32_vmx_procbased_ctls2::vmcs_shadowing::from;

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = mask;
    this->expect_true(msrs::ia32_vmx_procbased_ctls2::vmcs_shadowing::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_procbased_ctls2_rdseed_exiting()
{
    auto mask = msrs::ia32_vmx_procbased_ctls2::rdseed_exiting::mask;
    auto from = msrs::ia32_vmx_procbased_ctls2::rdseed_exiting::from;

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = mask;
    this->expect_true(msrs::ia32_vmx_procbased_ctls2::rdseed_exiting::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_procbased_ctls2_enable_pml()
{
    auto mask = msrs::ia32_vmx_procbased_ctls2::enable_pml::mask;
    auto from = msrs::ia32_vmx_procbased_ctls2::enable_pml::from;

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = mask;
    this->expect_true(msrs::ia32_vmx_procbased_ctls2::enable_pml::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_procbased_ctls2_ept_violation_ve()
{
    auto mask = msrs::ia32_vmx_procbased_ctls2::ept_violation_ve::mask;
    auto from = msrs::ia32_vmx_procbased_ctls2::ept_violation_ve::from;

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = mask;
    this->expect_true(msrs::ia32_vmx_procbased_ctls2::ept_violation_ve::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_procbased_ctls2_enable_xsaves_xrstors()
{
    auto mask = msrs::ia32_vmx_procbased_ctls2::enable_xsaves_xrstors::mask;
    auto from = msrs::ia32_vmx_procbased_ctls2::enable_xsaves_xrstors::from;

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = mask;
    this->expect_true(msrs::ia32_vmx_procbased_ctls2::enable_xsaves_xrstors::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_ept_vpid_cap()
{
    g_msrs[msrs::ia32_vmx_ept_vpid_cap::addr] = 100UL;
    this->expect_true(msrs::ia32_vmx_ept_vpid_cap::get() == 100UL);
}

void
intrinsics_ut::test_ia32_vmx_ept_vpid_cap_execute_only_translation()
{
    auto mask = msrs::ia32_vmx_ept_vpid_cap::execute_only_translation::mask;
    auto from = msrs::ia32_vmx_ept_vpid_cap::execute_only_translation::from;

    g_msrs[msrs::ia32_vmx_ept_vpid_cap::addr] = mask;
    this->expect_true(msrs::ia32_vmx_ept_vpid_cap::execute_only_translation::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_ept_vpid_cap_page_walk_length_of_4()
{
    auto mask = msrs::ia32_vmx_ept_vpid_cap::page_walk_length_of_4::mask;
    auto from = msrs::ia32_vmx_ept_vpid_cap::page_walk_length_of_4::from;

    g_msrs[msrs::ia32_vmx_ept_vpid_cap::addr] = mask;
    this->expect_true(msrs::ia32_vmx_ept_vpid_cap::page_walk_length_of_4::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_ept_vpid_cap_memory_type_uncacheable_supported()
{
    auto mask = msrs::ia32_vmx_ept_vpid_cap::memory_type_uncacheable_supported::mask;
    auto from = msrs::ia32_vmx_ept_vpid_cap::memory_type_uncacheable_supported::from;

    g_msrs[msrs::ia32_vmx_ept_vpid_cap::addr] = mask;
    this->expect_true(msrs::ia32_vmx_ept_vpid_cap::memory_type_uncacheable_supported::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_ept_vpid_cap_memory_type_write_back_supported()
{
    auto mask = msrs::ia32_vmx_ept_vpid_cap::memory_type_write_back_supported::mask;
    auto from = msrs::ia32_vmx_ept_vpid_cap::memory_type_write_back_supported::from;

    g_msrs[msrs::ia32_vmx_ept_vpid_cap::addr] = mask;
    this->expect_true(msrs::ia32_vmx_ept_vpid_cap::memory_type_write_back_supported::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_ept_vpid_cap_pde_2mb_support()
{
    auto mask = msrs::ia32_vmx_ept_vpid_cap::pde_2mb_support::mask;
    auto from = msrs::ia32_vmx_ept_vpid_cap::pde_2mb_support::from;

    g_msrs[msrs::ia32_vmx_ept_vpid_cap::addr] = mask;
    this->expect_true(msrs::ia32_vmx_ept_vpid_cap::pde_2mb_support::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_ept_vpid_cap_pdpte_1mb_support()
{
    auto mask = msrs::ia32_vmx_ept_vpid_cap::pdpte_1mb_support::mask;
    auto from = msrs::ia32_vmx_ept_vpid_cap::pdpte_1mb_support::from;

    g_msrs[msrs::ia32_vmx_ept_vpid_cap::addr] = mask;
    this->expect_true(msrs::ia32_vmx_ept_vpid_cap::pdpte_1mb_support::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_ept_vpid_cap_invept_support()
{
    auto mask = msrs::ia32_vmx_ept_vpid_cap::invept_support::mask;
    auto from = msrs::ia32_vmx_ept_vpid_cap::invept_support::from;

    g_msrs[msrs::ia32_vmx_ept_vpid_cap::addr] = mask;
    this->expect_true(msrs::ia32_vmx_ept_vpid_cap::invept_support::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_ept_vpid_cap_accessed_dirty_support()
{
    auto mask = msrs::ia32_vmx_ept_vpid_cap::accessed_dirty_support::mask;
    auto from = msrs::ia32_vmx_ept_vpid_cap::accessed_dirty_support::from;

    g_msrs[msrs::ia32_vmx_ept_vpid_cap::addr] = mask;
    this->expect_true(msrs::ia32_vmx_ept_vpid_cap::accessed_dirty_support::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_ept_vpid_cap_invept_single_context_support()
{
    auto mask = msrs::ia32_vmx_ept_vpid_cap::invept_single_context_support::mask;
    auto from = msrs::ia32_vmx_ept_vpid_cap::invept_single_context_support::from;

    g_msrs[msrs::ia32_vmx_ept_vpid_cap::addr] = mask;
    this->expect_true(msrs::ia32_vmx_ept_vpid_cap::invept_single_context_support::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_ept_vpid_cap_invept_all_context_support()
{
    auto mask = msrs::ia32_vmx_ept_vpid_cap::invept_all_context_support::mask;
    auto from = msrs::ia32_vmx_ept_vpid_cap::invept_all_context_support::from;

    g_msrs[msrs::ia32_vmx_ept_vpid_cap::addr] = mask;
    this->expect_true(msrs::ia32_vmx_ept_vpid_cap::invept_all_context_support::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_ept_vpid_cap_invvpid_support()
{
    auto mask = msrs::ia32_vmx_ept_vpid_cap::invvpid_support::mask;
    auto from = msrs::ia32_vmx_ept_vpid_cap::invvpid_support::from;

    g_msrs[msrs::ia32_vmx_ept_vpid_cap::addr] = mask;
    this->expect_true(msrs::ia32_vmx_ept_vpid_cap::invvpid_support::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_ept_vpid_cap_invvpid_individual_address_support()
{
    auto mask = msrs::ia32_vmx_ept_vpid_cap::invvpid_individual_address_support::mask;
    auto from = msrs::ia32_vmx_ept_vpid_cap::invvpid_individual_address_support::from;

    g_msrs[msrs::ia32_vmx_ept_vpid_cap::addr] = mask;
    this->expect_true(msrs::ia32_vmx_ept_vpid_cap::invvpid_individual_address_support::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_ept_vpid_cap_invvpid_single_context_support()
{
    auto mask = msrs::ia32_vmx_ept_vpid_cap::invvpid_single_context_support::mask;
    auto from = msrs::ia32_vmx_ept_vpid_cap::invvpid_single_context_support::from;

    g_msrs[msrs::ia32_vmx_ept_vpid_cap::addr] = mask;
    this->expect_true(msrs::ia32_vmx_ept_vpid_cap::invvpid_single_context_support::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_ept_vpid_cap_invvpid_all_context_support()
{
    auto mask = msrs::ia32_vmx_ept_vpid_cap::invvpid_all_context_support::mask;
    auto from = msrs::ia32_vmx_ept_vpid_cap::invvpid_all_context_support::from;

    g_msrs[msrs::ia32_vmx_ept_vpid_cap::addr] = mask;
    this->expect_true(msrs::ia32_vmx_ept_vpid_cap::invvpid_all_context_support::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_ept_vpid_cap_invvpid_single_context_retaining_globals_support()
{
    auto mask = msrs::ia32_vmx_ept_vpid_cap::invvpid_single_context_retaining_globals_support::mask;
    auto from = msrs::ia32_vmx_ept_vpid_cap::invvpid_single_context_retaining_globals_support::from;

    g_msrs[msrs::ia32_vmx_ept_vpid_cap::addr] = mask;
    this->expect_true(msrs::ia32_vmx_ept_vpid_cap::invvpid_single_context_retaining_globals_support::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_true_pinbased_ctls()
{
    g_msrs[msrs::ia32_vmx_true_pinbased_ctls::addr] = 100UL;
    this->expect_true(msrs::ia32_vmx_true_pinbased_ctls::get() == 100UL);
}

void
intrinsics_ut::test_ia32_vmx_true_pinbased_ctls_external_interrupt_exiting()
{
    auto mask = msrs::ia32_vmx_true_pinbased_ctls::external_interrupt_exiting::mask;
    auto from = msrs::ia32_vmx_true_pinbased_ctls::external_interrupt_exiting::from;

    g_msrs[msrs::ia32_vmx_true_pinbased_ctls::addr] = mask;
    this->expect_true(msrs::ia32_vmx_true_pinbased_ctls::external_interrupt_exiting::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_true_pinbased_ctls_nmi_exiting()
{
    auto mask = msrs::ia32_vmx_true_pinbased_ctls::nmi_exiting::mask;
    auto from = msrs::ia32_vmx_true_pinbased_ctls::nmi_exiting::from;

    g_msrs[msrs::ia32_vmx_true_pinbased_ctls::addr] = mask;
    this->expect_true(msrs::ia32_vmx_true_pinbased_ctls::nmi_exiting::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_true_pinbased_ctls_virtual_nmis()
{
    auto mask = msrs::ia32_vmx_true_pinbased_ctls::virtual_nmis::mask;
    auto from = msrs::ia32_vmx_true_pinbased_ctls::virtual_nmis::from;

    g_msrs[msrs::ia32_vmx_true_pinbased_ctls::addr] = mask;
    this->expect_true(msrs::ia32_vmx_true_pinbased_ctls::virtual_nmis::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_true_pinbased_ctls_activate_vmx_preemption_timer()
{
    auto mask = msrs::ia32_vmx_true_pinbased_ctls::activate_vmx_preemption_timer::mask;
    auto from = msrs::ia32_vmx_true_pinbased_ctls::activate_vmx_preemption_timer::from;

    g_msrs[msrs::ia32_vmx_true_pinbased_ctls::addr] = mask;
    this->expect_true(msrs::ia32_vmx_true_pinbased_ctls::activate_vmx_preemption_timer::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_true_pinbased_ctls_process_posted_interrupts()
{
    auto mask = msrs::ia32_vmx_true_pinbased_ctls::process_posted_interrupts::mask;
    auto from = msrs::ia32_vmx_true_pinbased_ctls::process_posted_interrupts::from;

    g_msrs[msrs::ia32_vmx_true_pinbased_ctls::addr] = mask;
    this->expect_true(msrs::ia32_vmx_true_pinbased_ctls::process_posted_interrupts::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_true_procbased_ctls()
{
    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 100UL;
    this->expect_true(msrs::ia32_vmx_true_procbased_ctls::get() == 100UL);
}

void
intrinsics_ut::test_ia32_vmx_true_procbased_ctls_interrupt_window_exiting()
{
    auto mask = msrs::ia32_vmx_true_procbased_ctls::interrupt_window_exiting::mask;
    auto from = msrs::ia32_vmx_true_procbased_ctls::interrupt_window_exiting::from;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = mask;
    this->expect_true(msrs::ia32_vmx_true_procbased_ctls::interrupt_window_exiting::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_true_procbased_ctls_use_tsc_offsetting()
{
    auto mask = msrs::ia32_vmx_true_procbased_ctls::use_tsc_offsetting::mask;
    auto from = msrs::ia32_vmx_true_procbased_ctls::use_tsc_offsetting::from;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = mask;
    this->expect_true(msrs::ia32_vmx_true_procbased_ctls::use_tsc_offsetting::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_true_procbased_ctls_hlt_exiting()
{
    auto mask = msrs::ia32_vmx_true_procbased_ctls::hlt_exiting::mask;
    auto from = msrs::ia32_vmx_true_procbased_ctls::hlt_exiting::from;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = mask;
    this->expect_true(msrs::ia32_vmx_true_procbased_ctls::hlt_exiting::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_true_procbased_ctls_invlpg_exiting()
{
    auto mask = msrs::ia32_vmx_true_procbased_ctls::invlpg_exiting::mask;
    auto from = msrs::ia32_vmx_true_procbased_ctls::invlpg_exiting::from;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = mask;
    this->expect_true(msrs::ia32_vmx_true_procbased_ctls::invlpg_exiting::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_true_procbased_ctls_mwait_exiting()
{
    auto mask = msrs::ia32_vmx_true_procbased_ctls::mwait_exiting::mask;
    auto from = msrs::ia32_vmx_true_procbased_ctls::mwait_exiting::from;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = mask;
    this->expect_true(msrs::ia32_vmx_true_procbased_ctls::mwait_exiting::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_true_procbased_ctls_rdpmc_exiting()
{
    auto mask = msrs::ia32_vmx_true_procbased_ctls::rdpmc_exiting::mask;
    auto from = msrs::ia32_vmx_true_procbased_ctls::rdpmc_exiting::from;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = mask;
    this->expect_true(msrs::ia32_vmx_true_procbased_ctls::rdpmc_exiting::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_true_procbased_ctls_rdtsc_exiting()
{
    auto mask = msrs::ia32_vmx_true_procbased_ctls::rdtsc_exiting::mask;
    auto from = msrs::ia32_vmx_true_procbased_ctls::rdtsc_exiting::from;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = mask;
    this->expect_true(msrs::ia32_vmx_true_procbased_ctls::rdtsc_exiting::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_true_procbased_ctls_cr3_load_exiting()
{
    auto mask = msrs::ia32_vmx_true_procbased_ctls::cr3_load_exiting::mask;
    auto from = msrs::ia32_vmx_true_procbased_ctls::cr3_load_exiting::from;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = mask;
    this->expect_true(msrs::ia32_vmx_true_procbased_ctls::cr3_load_exiting::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_true_procbased_ctls_cr3_store_exiting()
{
    auto mask = msrs::ia32_vmx_true_procbased_ctls::cr3_store_exiting::mask;
    auto from = msrs::ia32_vmx_true_procbased_ctls::cr3_store_exiting::from;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = mask;
    this->expect_true(msrs::ia32_vmx_true_procbased_ctls::cr3_store_exiting::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_true_procbased_ctls_cr8_load_exiting()
{
    auto mask = msrs::ia32_vmx_true_procbased_ctls::cr8_load_exiting::mask;
    auto from = msrs::ia32_vmx_true_procbased_ctls::cr8_load_exiting::from;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = mask;
    this->expect_true(msrs::ia32_vmx_true_procbased_ctls::cr8_load_exiting::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_true_procbased_ctls_cr8_store_exiting()
{
    auto mask = msrs::ia32_vmx_true_procbased_ctls::cr8_store_exiting::mask;
    auto from = msrs::ia32_vmx_true_procbased_ctls::cr8_store_exiting::from;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = mask;
    this->expect_true(msrs::ia32_vmx_true_procbased_ctls::cr8_store_exiting::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_true_procbased_ctls_use_tpr_shadow()
{
    auto mask = msrs::ia32_vmx_true_procbased_ctls::use_tpr_shadow::mask;
    auto from = msrs::ia32_vmx_true_procbased_ctls::use_tpr_shadow::from;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = mask;
    this->expect_true(msrs::ia32_vmx_true_procbased_ctls::use_tpr_shadow::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_true_procbased_ctls_nmi_window_exiting()
{
    auto mask = msrs::ia32_vmx_true_procbased_ctls::nmi_window_exiting::mask;
    auto from = msrs::ia32_vmx_true_procbased_ctls::nmi_window_exiting::from;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = mask;
    this->expect_true(msrs::ia32_vmx_true_procbased_ctls::nmi_window_exiting::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_true_procbased_ctls_mov_dr_exiting()
{
    auto mask = msrs::ia32_vmx_true_procbased_ctls::mov_dr_exiting::mask;
    auto from = msrs::ia32_vmx_true_procbased_ctls::mov_dr_exiting::from;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = mask;
    this->expect_true(msrs::ia32_vmx_true_procbased_ctls::mov_dr_exiting::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_true_procbased_ctls_unconditional_io_exiting()
{
    auto mask = msrs::ia32_vmx_true_procbased_ctls::unconditional_io_exiting::mask;
    auto from = msrs::ia32_vmx_true_procbased_ctls::unconditional_io_exiting::from;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = mask;
    this->expect_true(msrs::ia32_vmx_true_procbased_ctls::unconditional_io_exiting::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_true_procbased_ctls_use_io_bitmaps()
{
    auto mask = msrs::ia32_vmx_true_procbased_ctls::use_io_bitmaps::mask;
    auto from = msrs::ia32_vmx_true_procbased_ctls::use_io_bitmaps::from;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = mask;
    this->expect_true(msrs::ia32_vmx_true_procbased_ctls::use_io_bitmaps::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_true_procbased_ctls_monitor_trap_flag()
{
    auto mask = msrs::ia32_vmx_true_procbased_ctls::monitor_trap_flag::mask;
    auto from = msrs::ia32_vmx_true_procbased_ctls::monitor_trap_flag::from;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = mask;
    this->expect_true(msrs::ia32_vmx_true_procbased_ctls::monitor_trap_flag::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_true_procbased_ctls_use_msr_bitmaps()
{
    auto mask = msrs::ia32_vmx_true_procbased_ctls::use_msr_bitmaps::mask;
    auto from = msrs::ia32_vmx_true_procbased_ctls::use_msr_bitmaps::from;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = mask;
    this->expect_true(msrs::ia32_vmx_true_procbased_ctls::use_msr_bitmaps::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_true_procbased_ctls_monitor_exiting()
{
    auto mask = msrs::ia32_vmx_true_procbased_ctls::monitor_exiting::mask;
    auto from = msrs::ia32_vmx_true_procbased_ctls::monitor_exiting::from;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = mask;
    this->expect_true(msrs::ia32_vmx_true_procbased_ctls::monitor_exiting::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_true_procbased_ctls_pause_exiting()
{
    auto mask = msrs::ia32_vmx_true_procbased_ctls::pause_exiting::mask;
    auto from = msrs::ia32_vmx_true_procbased_ctls::pause_exiting::from;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = mask;
    this->expect_true(msrs::ia32_vmx_true_procbased_ctls::pause_exiting::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_true_procbased_ctls_activate_secondary_controls()
{
    auto mask = msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask;
    auto from = msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::from;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = mask;
    this->expect_true(msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_true_exit_ctls()
{
    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] = 100UL;
    this->expect_true(msrs::ia32_vmx_true_exit_ctls::get() == 100UL);
}

void
intrinsics_ut::test_ia32_vmx_true_exit_ctls_save_debug_controls()
{
    auto mask = msrs::ia32_vmx_true_exit_ctls::save_debug_controls::mask;
    auto from = msrs::ia32_vmx_true_exit_ctls::save_debug_controls::from;

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] = mask;
    this->expect_true(msrs::ia32_vmx_true_exit_ctls::save_debug_controls::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_true_exit_ctls_host_address_space_size()
{
    auto mask = msrs::ia32_vmx_true_exit_ctls::host_address_space_size::mask;
    auto from = msrs::ia32_vmx_true_exit_ctls::host_address_space_size::from;

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] = mask;
    this->expect_true(msrs::ia32_vmx_true_exit_ctls::host_address_space_size::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_true_exit_ctls_load_ia32_perf_global_ctrl()
{
    auto mask = msrs::ia32_vmx_true_exit_ctls::load_ia32_perf_global_ctrl::mask;
    auto from = msrs::ia32_vmx_true_exit_ctls::load_ia32_perf_global_ctrl::from;

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] = mask;
    this->expect_true(msrs::ia32_vmx_true_exit_ctls::load_ia32_perf_global_ctrl::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_true_exit_ctls_acknowledge_interrupt_on_exit()
{
    auto mask = msrs::ia32_vmx_true_exit_ctls::acknowledge_interrupt_on_exit::mask;
    auto from = msrs::ia32_vmx_true_exit_ctls::acknowledge_interrupt_on_exit::from;

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] = mask;
    this->expect_true(msrs::ia32_vmx_true_exit_ctls::acknowledge_interrupt_on_exit::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_true_exit_ctls_save_ia32_pat()
{
    auto mask = msrs::ia32_vmx_true_exit_ctls::save_ia32_pat::mask;
    auto from = msrs::ia32_vmx_true_exit_ctls::save_ia32_pat::from;

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] = mask;
    this->expect_true(msrs::ia32_vmx_true_exit_ctls::save_ia32_pat::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_true_exit_ctls_load_ia32_pat()
{
    auto mask = msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::mask;
    auto from = msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::from;

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] = mask;
    this->expect_true(msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_true_exit_ctls_save_ia32_efer()
{
    auto mask = msrs::ia32_vmx_true_exit_ctls::save_ia32_efer::mask;
    auto from = msrs::ia32_vmx_true_exit_ctls::save_ia32_efer::from;

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] = mask;
    this->expect_true(msrs::ia32_vmx_true_exit_ctls::save_ia32_efer::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_true_exit_ctls_load_ia32_efer()
{
    auto mask = msrs::ia32_vmx_true_exit_ctls::load_ia32_efer::mask;
    auto from = msrs::ia32_vmx_true_exit_ctls::load_ia32_efer::from;

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] = mask;
    this->expect_true(msrs::ia32_vmx_true_exit_ctls::load_ia32_efer::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_true_exit_ctls_save_vmx_preemption_timer_value()
{
    auto mask = msrs::ia32_vmx_true_exit_ctls::save_vmx_preemption_timer_value::mask;
    auto from = msrs::ia32_vmx_true_exit_ctls::save_vmx_preemption_timer_value::from;

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] = mask;
    this->expect_true(msrs::ia32_vmx_true_exit_ctls::save_vmx_preemption_timer_value::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_true_entry_ctls()
{
    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] = 100UL;
    this->expect_true(msrs::ia32_vmx_true_entry_ctls::get() == 100UL);
}

void
intrinsics_ut::test_ia32_vmx_true_entry_ctls_load_debug_controls()
{
    auto mask = msrs::ia32_vmx_true_entry_ctls::load_debug_controls::mask;
    auto from = msrs::ia32_vmx_true_entry_ctls::load_debug_controls::from;

    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] = mask;
    this->expect_true(msrs::ia32_vmx_true_entry_ctls::load_debug_controls::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_true_entry_ctls_ia_32e_mode_guest()
{
    auto mask = msrs::ia32_vmx_true_entry_ctls::ia_32e_mode_guest::mask;
    auto from = msrs::ia32_vmx_true_entry_ctls::ia_32e_mode_guest::from;

    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] = mask;
    this->expect_true(msrs::ia32_vmx_true_entry_ctls::ia_32e_mode_guest::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_true_entry_ctls_entry_to_smm()
{
    auto mask = msrs::ia32_vmx_true_entry_ctls::entry_to_smm::mask;
    auto from = msrs::ia32_vmx_true_entry_ctls::entry_to_smm::from;

    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] = mask;
    this->expect_true(msrs::ia32_vmx_true_entry_ctls::entry_to_smm::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_true_entry_ctls_deactivate_dual_monitor_treatment()
{
    auto mask = msrs::ia32_vmx_true_entry_ctls::deactivate_dual_monitor_treatment::mask;
    auto from = msrs::ia32_vmx_true_entry_ctls::deactivate_dual_monitor_treatment::from;

    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] = mask;
    this->expect_true(msrs::ia32_vmx_true_entry_ctls::deactivate_dual_monitor_treatment::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_true_entry_ctls_load_ia32_perf_global_ctrl()
{
    auto mask = msrs::ia32_vmx_true_entry_ctls::load_ia32_perf_global_ctrl::mask;
    auto from = msrs::ia32_vmx_true_entry_ctls::load_ia32_perf_global_ctrl::from;

    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] = mask;
    this->expect_true(msrs::ia32_vmx_true_entry_ctls::load_ia32_perf_global_ctrl::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_true_entry_ctls_load_ia32_pat()
{
    auto mask = msrs::ia32_vmx_true_entry_ctls::load_ia32_pat::mask;
    auto from = msrs::ia32_vmx_true_entry_ctls::load_ia32_pat::from;

    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] = mask;
    this->expect_true(msrs::ia32_vmx_true_entry_ctls::load_ia32_pat::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_true_entry_ctls_load_ia32_efer()
{
    auto mask = msrs::ia32_vmx_true_entry_ctls::load_ia32_efer::mask;
    auto from = msrs::ia32_vmx_true_entry_ctls::load_ia32_efer::from;

    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] = mask;
    this->expect_true(msrs::ia32_vmx_true_entry_ctls::load_ia32_efer::get() == mask >> from);
}

void
intrinsics_ut::test_ia32_vmx_vmfunc()
{
    g_msrs[msrs::ia32_vmx_vmfunc::addr] = 100UL;
    this->expect_true(msrs::ia32_vmx_vmfunc::get() == 100UL);
}
