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
__read_msr(uint32_t addr) noexcept
{ return g_msrs[addr]; }

extern "C" void
__write_msr(uint32_t addr, uint64_t val) noexcept
{ g_msrs[addr] = val; }

void
intrinsics_ut::test_general_msr_access()
{
    msrs::set(0x1, 100UL);
    this->expect_true(msrs::get(0x1) == 100UL);
}

void
intrinsics_ut::test_ia32_feature_control()
{
    msrs::ia32_feature_control::set(0xFFFFFFFFFFFFFFFFUL);
    this->expect_true(msrs::ia32_feature_control::get() == 0xFFFFFFFFFFFFFFFFUL);

    msrs::ia32_feature_control::dump();

    msrs::ia32_feature_control::set(0x0U);
    this->expect_true(msrs::ia32_feature_control::get() == 0x0U);
}

void
intrinsics_ut::test_ia32_feature_control_lock_bit()
{
    msrs::ia32_feature_control::lock_bit::set(true);
    this->expect_true(msrs::ia32_feature_control::lock_bit::get());

    msrs::ia32_feature_control::lock_bit::set(false);
    this->expect_false(msrs::ia32_feature_control::lock_bit::get());
}

void
intrinsics_ut::test_ia32_feature_control_enable_vmx_inside_smx()
{
    msrs::ia32_feature_control::enable_vmx_inside_smx::set(true);
    this->expect_true(msrs::ia32_feature_control::enable_vmx_inside_smx::get());

    msrs::ia32_feature_control::enable_vmx_inside_smx::set(false);
    this->expect_false(msrs::ia32_feature_control::enable_vmx_inside_smx::get());
}

void
intrinsics_ut::test_ia32_feature_control_enable_vmx_outside_smx()
{
    msrs::ia32_feature_control::enable_vmx_outside_smx::set(true);
    this->expect_true(msrs::ia32_feature_control::enable_vmx_outside_smx::get());

    msrs::ia32_feature_control::enable_vmx_outside_smx::set(false);
    this->expect_false(msrs::ia32_feature_control::enable_vmx_outside_smx::get());
}

void
intrinsics_ut::test_ia32_feature_control_senter_local_function_enables()
{
    msrs::ia32_feature_control::senter_local_function_enables::set(6UL);
    this->expect_true(msrs::ia32_feature_control::senter_local_function_enables::get() == 6UL);

    msrs::ia32_feature_control::senter_local_function_enables::set(4UL);
    this->expect_true(msrs::ia32_feature_control::senter_local_function_enables::get() == 4UL);
}

void
intrinsics_ut::test_ia32_feature_control_senter_gloabl_function_enable()
{
    msrs::ia32_feature_control::senter_gloabl_function_enable::set(true);
    this->expect_true(msrs::ia32_feature_control::senter_gloabl_function_enable::get());

    msrs::ia32_feature_control::senter_gloabl_function_enable::set(false);
    this->expect_false(msrs::ia32_feature_control::senter_gloabl_function_enable::get());
}

void
intrinsics_ut::test_ia32_feature_control_sgx_launch_control_enable()
{
    msrs::ia32_feature_control::sgx_launch_control_enable::set(true);
    this->expect_true(msrs::ia32_feature_control::sgx_launch_control_enable::get());

    msrs::ia32_feature_control::sgx_launch_control_enable::set(false);
    this->expect_false(msrs::ia32_feature_control::sgx_launch_control_enable::get());
}

void
intrinsics_ut::test_ia32_feature_control_sgx_global_enable()
{
    msrs::ia32_feature_control::sgx_global_enable::set(true);
    this->expect_true(msrs::ia32_feature_control::sgx_global_enable::get());

    msrs::ia32_feature_control::sgx_global_enable::set(false);
    this->expect_false(msrs::ia32_feature_control::sgx_global_enable::get());
}

void
intrinsics_ut::test_ia32_feature_control_lmce()
{
    msrs::ia32_feature_control::lmce::set(true);
    this->expect_true(msrs::ia32_feature_control::lmce::get());

    msrs::ia32_feature_control::lmce::set(false);
    this->expect_false(msrs::ia32_feature_control::lmce::get());
}

void
intrinsics_ut::test_ia32_sysenter_cs()
{
    msrs::ia32_sysenter_cs::set(100UL);
    this->expect_true(msrs::ia32_sysenter_cs::get() == 100UL);
}

void
intrinsics_ut::test_ia32_sysenter_esp()
{
    msrs::ia32_sysenter_esp::set(100UL);
    this->expect_true(msrs::ia32_sysenter_esp::get() == 100UL);
}

void
intrinsics_ut::test_ia32_sysenter_eip()
{
    msrs::ia32_sysenter_eip::set(100UL);
    this->expect_true(msrs::ia32_sysenter_eip::get() == 100UL);
}

void
intrinsics_ut::test_ia32_debugctl()
{
    msrs::ia32_debugctl::set(0xFFFFFFFFFFFFFFFFUL);
    this->expect_true(msrs::ia32_debugctl::get() == 0xFFFFFFFFFFFFFFFFUL);

    msrs::ia32_debugctl::dump();

    msrs::ia32_debugctl::set(0x0U);
    this->expect_true(msrs::ia32_debugctl::get() == 0x0U);
}

void
intrinsics_ut::test_ia32_debugctl_lbr()
{
    msrs::ia32_debugctl::lbr::set(true);
    this->expect_true(msrs::ia32_debugctl::lbr::get());

    msrs::ia32_debugctl::lbr::set(false);
    this->expect_false(msrs::ia32_debugctl::lbr::get());
}

void
intrinsics_ut::test_ia32_debugctl_btf()
{
    msrs::ia32_debugctl::btf::set(true);
    this->expect_true(msrs::ia32_debugctl::btf::get());

    msrs::ia32_debugctl::btf::set(false);
    this->expect_false(msrs::ia32_debugctl::btf::get());
}

void
intrinsics_ut::test_ia32_debugctl_tr()
{
    msrs::ia32_debugctl::tr::set(true);
    this->expect_true(msrs::ia32_debugctl::tr::get());

    msrs::ia32_debugctl::tr::set(false);
    this->expect_false(msrs::ia32_debugctl::tr::get());
}

void
intrinsics_ut::test_ia32_debugctl_bts()
{
    msrs::ia32_debugctl::bts::set(true);
    this->expect_true(msrs::ia32_debugctl::bts::get());

    msrs::ia32_debugctl::bts::set(false);
    this->expect_false(msrs::ia32_debugctl::bts::get());
}

void
intrinsics_ut::test_ia32_debugctl_btint()
{
    msrs::ia32_debugctl::btint::set(true);
    this->expect_true(msrs::ia32_debugctl::btint::get());

    msrs::ia32_debugctl::btint::set(false);
    this->expect_false(msrs::ia32_debugctl::btint::get());
}

void
intrinsics_ut::test_ia32_debugctl_bt_off_os()
{
    msrs::ia32_debugctl::bt_off_os::set(true);
    this->expect_true(msrs::ia32_debugctl::bt_off_os::get());

    msrs::ia32_debugctl::bt_off_os::set(false);
    this->expect_false(msrs::ia32_debugctl::bt_off_os::get());
}

void
intrinsics_ut::test_ia32_debugctl_bt_off_user()
{
    msrs::ia32_debugctl::bt_off_user::set(true);
    this->expect_true(msrs::ia32_debugctl::bt_off_user::get());

    msrs::ia32_debugctl::bt_off_user::set(false);
    this->expect_false(msrs::ia32_debugctl::bt_off_user::get());
}

void
intrinsics_ut::test_ia32_debugctl_freeze_lbrs_on_pmi()
{
    msrs::ia32_debugctl::freeze_lbrs_on_pmi::set(true);
    this->expect_true(msrs::ia32_debugctl::freeze_lbrs_on_pmi::get());

    msrs::ia32_debugctl::freeze_lbrs_on_pmi::set(false);
    this->expect_false(msrs::ia32_debugctl::freeze_lbrs_on_pmi::get());
}

void
intrinsics_ut::test_ia32_debugctl_freeze_perfmon_on_pmi()
{
    msrs::ia32_debugctl::freeze_perfmon_on_pmi::set(true);
    this->expect_true(msrs::ia32_debugctl::freeze_perfmon_on_pmi::get());

    msrs::ia32_debugctl::freeze_perfmon_on_pmi::set(false);
    this->expect_false(msrs::ia32_debugctl::freeze_perfmon_on_pmi::get());
}

void
intrinsics_ut::test_ia32_debugctl_enable_uncore_pmi()
{
    msrs::ia32_debugctl::enable_uncore_pmi::set(true);
    this->expect_true(msrs::ia32_debugctl::enable_uncore_pmi::get());

    msrs::ia32_debugctl::enable_uncore_pmi::set(false);
    this->expect_false(msrs::ia32_debugctl::enable_uncore_pmi::get());
}

void
intrinsics_ut::test_ia32_debugctl_freeze_while_smm()
{
    msrs::ia32_debugctl::freeze_while_smm::set(true);
    this->expect_true(msrs::ia32_debugctl::freeze_while_smm::get());

    msrs::ia32_debugctl::freeze_while_smm::set(false);
    this->expect_false(msrs::ia32_debugctl::freeze_while_smm::get());
}

void
intrinsics_ut::test_ia32_debugctl_rtm_debug()
{
    msrs::ia32_debugctl::rtm_debug::set(true);
    this->expect_true(msrs::ia32_debugctl::rtm_debug::get());

    msrs::ia32_debugctl::rtm_debug::set(false);
    this->expect_false(msrs::ia32_debugctl::rtm_debug::get());
}

void
intrinsics_ut::test_ia32_debugctl_reserved()
{
    msrs::ia32_debugctl::reserved::set(0x100000000UL);
    this->expect_true(msrs::ia32_debugctl::reserved::get() == 0x100000000UL);
}

void
intrinsics_ut::test_ia32_pat()
{
    msrs::ia32_pat::set(0xFFFFFFFFFFFFFFFFUL);
    this->expect_true(msrs::ia32_pat::get() == 0xFFFFFFFFFFFFFFFFUL);

    msrs::ia32_pat::dump();

    msrs::ia32_pat::set(0x0U);
    this->expect_true(msrs::ia32_pat::get() == 0x0U);
}

void
intrinsics_ut::test_ia32_pat_pa0()
{
    msrs::ia32_pat::pa0::set(6UL);
    this->expect_true(msrs::ia32_pat::pa0::get() == 6UL);

    msrs::ia32_pat::pa0::set(4UL);
    this->expect_true(msrs::ia32_pat::pa0::get() == 4UL);
}

void
intrinsics_ut::test_ia32_pat_pa1()
{
    msrs::ia32_pat::pa1::set(6UL);
    this->expect_true(msrs::ia32_pat::pa1::get() == 6UL);

    msrs::ia32_pat::pa1::set(4UL);
    this->expect_true(msrs::ia32_pat::pa1::get() == 4UL);
}

void
intrinsics_ut::test_ia32_pat_pa2()
{
    msrs::ia32_pat::pa2::set(6UL);
    this->expect_true(msrs::ia32_pat::pa2::get() == 6UL);

    msrs::ia32_pat::pa2::set(4UL);
    this->expect_true(msrs::ia32_pat::pa2::get() == 4UL);
}

void
intrinsics_ut::test_ia32_pat_pa3()
{
    msrs::ia32_pat::pa3::set(6UL);
    this->expect_true(msrs::ia32_pat::pa3::get() == 6UL);

    msrs::ia32_pat::pa3::set(4UL);
    this->expect_true(msrs::ia32_pat::pa3::get() == 4UL);
}

void
intrinsics_ut::test_ia32_pat_pa4()
{
    msrs::ia32_pat::pa4::set(6UL);
    this->expect_true(msrs::ia32_pat::pa4::get() == 6UL);

    msrs::ia32_pat::pa4::set(4UL);
    this->expect_true(msrs::ia32_pat::pa4::get() == 4UL);
}

void
intrinsics_ut::test_ia32_pat_pa5()
{
    msrs::ia32_pat::pa5::set(6UL);
    this->expect_true(msrs::ia32_pat::pa5::get() == 6UL);

    msrs::ia32_pat::pa5::set(4UL);
    this->expect_true(msrs::ia32_pat::pa5::get() == 4UL);
}

void
intrinsics_ut::test_ia32_pat_pa6()
{
    msrs::ia32_pat::pa6::set(6UL);
    this->expect_true(msrs::ia32_pat::pa6::get() == 6UL);

    msrs::ia32_pat::pa6::set(4UL);
    this->expect_true(msrs::ia32_pat::pa6::get() == 4UL);
}

void
intrinsics_ut::test_ia32_pat_pa7()
{
    msrs::ia32_pat::pa7::set(6UL);
    this->expect_true(msrs::ia32_pat::pa7::get() == 6UL);

    msrs::ia32_pat::pa7::set(4UL);
    this->expect_true(msrs::ia32_pat::pa7::get() == 4UL);
}

void
intrinsics_ut::test_ia32_perf_global_ctrl()
{
    msrs::ia32_perf_global_ctrl::set(0xFFFFFFFFFFFFFFFFUL);
    this->expect_true(msrs::ia32_perf_global_ctrl::get() == 0xFFFFFFFFFFFFFFFFUL);

    msrs::ia32_perf_global_ctrl::dump();

    msrs::ia32_perf_global_ctrl::set(0x0U);
    this->expect_true(msrs::ia32_perf_global_ctrl::get() == 0x0U);
}

void
intrinsics_ut::test_ia32_perf_global_ctrl_pmc0()
{
    msrs::ia32_perf_global_ctrl::pmc0::set(true);
    this->expect_true(msrs::ia32_perf_global_ctrl::pmc0::get());

    msrs::ia32_perf_global_ctrl::pmc0::set(false);
    this->expect_false(msrs::ia32_perf_global_ctrl::pmc0::get());
}

void
intrinsics_ut::test_ia32_perf_global_ctrl_pmc1()
{
    msrs::ia32_perf_global_ctrl::pmc1::set(true);
    this->expect_true(msrs::ia32_perf_global_ctrl::pmc1::get());

    msrs::ia32_perf_global_ctrl::pmc1::set(false);
    this->expect_false(msrs::ia32_perf_global_ctrl::pmc1::get());
}

void
intrinsics_ut::test_ia32_perf_global_ctrl_pmc2()
{
    msrs::ia32_perf_global_ctrl::pmc2::set(true);
    this->expect_true(msrs::ia32_perf_global_ctrl::pmc2::get());

    msrs::ia32_perf_global_ctrl::pmc2::set(false);
    this->expect_false(msrs::ia32_perf_global_ctrl::pmc2::get());
}

void
intrinsics_ut::test_ia32_perf_global_ctrl_pmc3()
{
    msrs::ia32_perf_global_ctrl::pmc3::set(true);
    this->expect_true(msrs::ia32_perf_global_ctrl::pmc3::get());

    msrs::ia32_perf_global_ctrl::pmc3::set(false);
    this->expect_false(msrs::ia32_perf_global_ctrl::pmc3::get());
}

void
intrinsics_ut::test_ia32_perf_global_ctrl_pmc4()
{
    msrs::ia32_perf_global_ctrl::pmc4::set(true);
    this->expect_true(msrs::ia32_perf_global_ctrl::pmc4::get());

    msrs::ia32_perf_global_ctrl::pmc4::set(false);
    this->expect_false(msrs::ia32_perf_global_ctrl::pmc4::get());
}

void
intrinsics_ut::test_ia32_perf_global_ctrl_pmc5()
{
    msrs::ia32_perf_global_ctrl::pmc5::set(true);
    this->expect_true(msrs::ia32_perf_global_ctrl::pmc5::get());

    msrs::ia32_perf_global_ctrl::pmc5::set(false);
    this->expect_false(msrs::ia32_perf_global_ctrl::pmc5::get());
}

void
intrinsics_ut::test_ia32_perf_global_ctrl_pmc6()
{
    msrs::ia32_perf_global_ctrl::pmc6::set(true);
    this->expect_true(msrs::ia32_perf_global_ctrl::pmc6::get());

    msrs::ia32_perf_global_ctrl::pmc6::set(false);
    this->expect_false(msrs::ia32_perf_global_ctrl::pmc6::get());
}

void
intrinsics_ut::test_ia32_perf_global_ctrl_pmc7()
{
    msrs::ia32_perf_global_ctrl::pmc7::set(true);
    this->expect_true(msrs::ia32_perf_global_ctrl::pmc7::get());

    msrs::ia32_perf_global_ctrl::pmc7::set(false);
    this->expect_false(msrs::ia32_perf_global_ctrl::pmc7::get());
}

void
intrinsics_ut::test_ia32_perf_global_ctrl_fixed_ctr0()
{
    msrs::ia32_perf_global_ctrl::fixed_ctr0::set(true);
    this->expect_true(msrs::ia32_perf_global_ctrl::fixed_ctr0::get());

    msrs::ia32_perf_global_ctrl::fixed_ctr0::set(false);
    this->expect_false(msrs::ia32_perf_global_ctrl::fixed_ctr0::get());
}

void
intrinsics_ut::test_ia32_perf_global_ctrl_fixed_ctr1()
{
    msrs::ia32_perf_global_ctrl::fixed_ctr1::set(true);
    this->expect_true(msrs::ia32_perf_global_ctrl::fixed_ctr1::get());

    msrs::ia32_perf_global_ctrl::fixed_ctr1::set(false);
    this->expect_false(msrs::ia32_perf_global_ctrl::fixed_ctr1::get());
}

void
intrinsics_ut::test_ia32_perf_global_ctrl_fixed_ctr2()
{
    msrs::ia32_perf_global_ctrl::fixed_ctr2::set(true);
    this->expect_true(msrs::ia32_perf_global_ctrl::fixed_ctr2::get());

    msrs::ia32_perf_global_ctrl::fixed_ctr2::set(false);
    this->expect_false(msrs::ia32_perf_global_ctrl::fixed_ctr2::get());
}

void
intrinsics_ut::test_ia32_vmx_basic()
{
    g_msrs[msrs::ia32_vmx_basic::addr] = 0xFFFFFFFFFFFFFFFFUL;
    this->expect_true(msrs::ia32_vmx_basic::get() == 0xFFFFFFFFFFFFFFFFUL);

    msrs::ia32_vmx_basic::dump();

    g_msrs[msrs::ia32_vmx_basic::addr] = 0x0U;
    this->expect_true(msrs::ia32_vmx_basic::get() == 0x0U);
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

    g_msrs[msrs::ia32_vmx_basic::addr] = mask;
    this->expect_true(msrs::ia32_vmx_basic::physical_address_width::get());

    g_msrs[msrs::ia32_vmx_basic::addr] = ~mask;
    this->expect_false(msrs::ia32_vmx_basic::physical_address_width::get());
}

void
intrinsics_ut::test_ia32_vmx_basic_dual_monitor_mode_support()
{
    auto mask = msrs::ia32_vmx_basic::dual_monitor_mode_support::mask;

    g_msrs[msrs::ia32_vmx_basic::addr] = mask;
    this->expect_true(msrs::ia32_vmx_basic::dual_monitor_mode_support::get());

    g_msrs[msrs::ia32_vmx_basic::addr] = ~mask;
    this->expect_false(msrs::ia32_vmx_basic::dual_monitor_mode_support::get());
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

    g_msrs[msrs::ia32_vmx_basic::addr] = mask;
    this->expect_true(msrs::ia32_vmx_basic::ins_outs_exit_information::get());

    g_msrs[msrs::ia32_vmx_basic::addr] = ~mask;
    this->expect_false(msrs::ia32_vmx_basic::ins_outs_exit_information::get());
}

void
intrinsics_ut::test_ia32_vmx_basic_true_based_controls()
{
    auto mask = msrs::ia32_vmx_basic::true_based_controls::mask;

    g_msrs[msrs::ia32_vmx_basic::addr] = mask;
    this->expect_true(msrs::ia32_vmx_basic::true_based_controls::get());

    g_msrs[msrs::ia32_vmx_basic::addr] = ~mask;
    this->expect_false(msrs::ia32_vmx_basic::true_based_controls::get());
}

void
intrinsics_ut::test_ia32_vmx_misc()
{
    g_msrs[msrs::ia32_vmx_misc::addr] = 0xFFFFFFFFFFFFFFFFUL;
    this->expect_true(msrs::ia32_vmx_misc::get() == 0xFFFFFFFFFFFFFFFFUL);

    msrs::ia32_vmx_misc::dump();

    g_msrs[msrs::ia32_vmx_misc::addr] = 0x0U;
    this->expect_true(msrs::ia32_vmx_misc::get() == 0x0U);
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

    g_msrs[msrs::ia32_vmx_misc::addr] = mask;
    this->expect_true(msrs::ia32_vmx_misc::store_efer_lma_on_vm_exit::get());

    g_msrs[msrs::ia32_vmx_misc::addr] = ~mask;
    this->expect_false(msrs::ia32_vmx_misc::store_efer_lma_on_vm_exit::get());
}

void
intrinsics_ut::test_ia32_vmx_misc_activity_state_hlt_support()
{
    auto mask = msrs::ia32_vmx_misc::activity_state_hlt_support::mask;

    g_msrs[msrs::ia32_vmx_misc::addr] = mask;
    this->expect_true(msrs::ia32_vmx_misc::activity_state_hlt_support::get());

    g_msrs[msrs::ia32_vmx_misc::addr] = ~mask;
    this->expect_false(msrs::ia32_vmx_misc::activity_state_hlt_support::get());
}

void
intrinsics_ut::test_ia32_vmx_misc_activity_state_shutdown_support()
{
    auto mask = msrs::ia32_vmx_misc::activity_state_shutdown_support::mask;

    g_msrs[msrs::ia32_vmx_misc::addr] = mask;
    this->expect_true(msrs::ia32_vmx_misc::activity_state_shutdown_support::get());

    g_msrs[msrs::ia32_vmx_misc::addr] = ~mask;
    this->expect_false(msrs::ia32_vmx_misc::activity_state_shutdown_support::get());
}

void
intrinsics_ut::test_ia32_vmx_misc_activity_state_wait_for_sipi_support()
{
    auto mask = msrs::ia32_vmx_misc::activity_state_wait_for_sipi_support::mask;

    g_msrs[msrs::ia32_vmx_misc::addr] = mask;
    this->expect_true(msrs::ia32_vmx_misc::activity_state_wait_for_sipi_support::get());

    g_msrs[msrs::ia32_vmx_misc::addr] = ~mask;
    this->expect_false(msrs::ia32_vmx_misc::activity_state_wait_for_sipi_support::get());
}

void
intrinsics_ut::test_ia32_vmx_misc_processor_trace_support()
{
    auto mask = msrs::ia32_vmx_misc::processor_trace_support::mask;

    g_msrs[msrs::ia32_vmx_misc::addr] = mask;
    this->expect_true(msrs::ia32_vmx_misc::processor_trace_support::get());

    g_msrs[msrs::ia32_vmx_misc::addr] = ~mask;
    this->expect_false(msrs::ia32_vmx_misc::processor_trace_support::get());
}

void
intrinsics_ut::test_ia32_vmx_misc_rdmsr_in_smm_support()
{
    auto mask = msrs::ia32_vmx_misc::rdmsr_in_smm_support::mask;

    g_msrs[msrs::ia32_vmx_misc::addr] = mask;
    this->expect_true(msrs::ia32_vmx_misc::rdmsr_in_smm_support::get());

    g_msrs[msrs::ia32_vmx_misc::addr] = ~mask;
    this->expect_false(msrs::ia32_vmx_misc::rdmsr_in_smm_support::get());
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

    g_msrs[msrs::ia32_vmx_misc::addr] = mask;
    this->expect_true(msrs::ia32_vmx_misc::vmxoff_blocked_smi_support::get());

    g_msrs[msrs::ia32_vmx_misc::addr] = ~mask;
    this->expect_false(msrs::ia32_vmx_misc::vmxoff_blocked_smi_support::get());
}

void
intrinsics_ut::test_ia32_vmx_misc_vmwrite_all_fields_support()
{
    auto mask = msrs::ia32_vmx_misc::vmwrite_all_fields_support::mask;

    g_msrs[msrs::ia32_vmx_misc::addr] = mask;
    this->expect_true(msrs::ia32_vmx_misc::vmwrite_all_fields_support::get());

    g_msrs[msrs::ia32_vmx_misc::addr] = ~mask;
    this->expect_false(msrs::ia32_vmx_misc::vmwrite_all_fields_support::get());
}

void
intrinsics_ut::test_ia32_vmx_misc_injection_with_instruction_length_of_zero()
{
    auto mask = msrs::ia32_vmx_misc::injection_with_instruction_length_of_zero::mask;

    g_msrs[msrs::ia32_vmx_misc::addr] = mask;
    this->expect_true(msrs::ia32_vmx_misc::injection_with_instruction_length_of_zero::get());

    g_msrs[msrs::ia32_vmx_misc::addr] = ~mask;
    this->expect_false(msrs::ia32_vmx_misc::injection_with_instruction_length_of_zero::get());
}

void
intrinsics_ut::test_ia32_vmx_cr0_fixed0()
{
    g_msrs[msrs::ia32_vmx_cr0_fixed0::addr] = 0xFFFFFFFFFFFFFFFFUL;
    this->expect_true(msrs::ia32_vmx_cr0_fixed0::get() == 0xFFFFFFFFFFFFFFFFUL);

    g_msrs[msrs::ia32_vmx_cr0_fixed0::addr] = 0x0U;
    this->expect_true(msrs::ia32_vmx_cr0_fixed0::get() == 0x0U);
}

void
intrinsics_ut::test_ia32_vmx_cr0_fixed1()
{
    g_msrs[msrs::ia32_vmx_cr0_fixed1::addr] = 0xFFFFFFFFFFFFFFFFUL;
    this->expect_true(msrs::ia32_vmx_cr0_fixed1::get() == 0xFFFFFFFFFFFFFFFFUL);

    g_msrs[msrs::ia32_vmx_cr0_fixed1::addr] = 0x0U;
    this->expect_true(msrs::ia32_vmx_cr0_fixed1::get() == 0x0U);
}

void
intrinsics_ut::test_ia32_vmx_cr4_fixed0()
{
    g_msrs[msrs::ia32_vmx_cr4_fixed0::addr] = 0xFFFFFFFFFFFFFFFFUL;
    this->expect_true(msrs::ia32_vmx_cr4_fixed0::get() == 0xFFFFFFFFFFFFFFFFUL);

    g_msrs[msrs::ia32_vmx_cr4_fixed0::addr] = 0x0U;
    this->expect_true(msrs::ia32_vmx_cr4_fixed0::get() == 0x0U);
}

void
intrinsics_ut::test_ia32_vmx_cr4_fixed1()
{
    g_msrs[msrs::ia32_vmx_cr4_fixed1::addr] = 0xFFFFFFFFFFFFFFFFUL;
    this->expect_true(msrs::ia32_vmx_cr4_fixed1::get() == 0xFFFFFFFFFFFFFFFFUL);

    g_msrs[msrs::ia32_vmx_cr4_fixed1::addr] = 0x0U;
    this->expect_true(msrs::ia32_vmx_cr4_fixed1::get() == 0x0U);
}

void
intrinsics_ut::test_ia32_vmx_procbased_ctls2()
{
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0x00000000FFFFFFFFUL;
    this->expect_true(msrs::ia32_vmx_procbased_ctls2::get() == 0x00000000FFFFFFFFUL);

    msrs::ia32_vmx_procbased_ctls2::dump();

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0x0UL;
    this->expect_true(msrs::ia32_vmx_procbased_ctls2::get() == 0x0UL);

    msrs::ia32_vmx_procbased_ctls2::dump();

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0x00000000FFFFFFFFUL;
    this->expect_true(msrs::ia32_vmx_procbased_ctls2::allowed0() == 0xFFFFFFFFU);
    this->expect_true(msrs::ia32_vmx_procbased_ctls2::allowed1() == 0x00000000U);

    msrs::ia32_vmx_procbased_ctls2::dump();

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0xFFFFFFFF00000000U;
    this->expect_true(msrs::ia32_vmx_procbased_ctls2::allowed0() == 0x00000000U);
    this->expect_true(msrs::ia32_vmx_procbased_ctls2::allowed1() == 0xFFFFFFFFU);

    msrs::ia32_vmx_procbased_ctls2::dump();
}

void
intrinsics_ut::test_ia32_vmx_procbased_ctls2_virtualize_apic_accesses()
{
    auto mask = msrs::ia32_vmx_procbased_ctls2::virtualize_apic_accesses::mask;

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = mask;
    this->expect_true(msrs::ia32_vmx_procbased_ctls2::virtualize_apic_accesses::get());

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = ~mask;
    this->expect_false(msrs::ia32_vmx_procbased_ctls2::virtualize_apic_accesses::get());

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = mask | (mask << 32);
    this->expect_false(msrs::ia32_vmx_procbased_ctls2::virtualize_apic_accesses::is_allowed0());
    this->expect_true(msrs::ia32_vmx_procbased_ctls2::virtualize_apic_accesses::is_allowed1());

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = ~mask & ~(mask << 32);
    this->expect_true(msrs::ia32_vmx_procbased_ctls2::virtualize_apic_accesses::is_allowed0());
    this->expect_false(msrs::ia32_vmx_procbased_ctls2::virtualize_apic_accesses::is_allowed1());
}

void
intrinsics_ut::test_ia32_vmx_procbased_ctls2_enable_ept()
{
    auto mask = msrs::ia32_vmx_procbased_ctls2::enable_ept::mask;

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = mask;
    this->expect_true(msrs::ia32_vmx_procbased_ctls2::enable_ept::get());

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = ~mask;
    this->expect_false(msrs::ia32_vmx_procbased_ctls2::enable_ept::get());

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = mask | (mask << 32);
    this->expect_false(msrs::ia32_vmx_procbased_ctls2::enable_ept::is_allowed0());
    this->expect_true(msrs::ia32_vmx_procbased_ctls2::enable_ept::is_allowed1());

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = ~mask & ~(mask << 32);
    this->expect_true(msrs::ia32_vmx_procbased_ctls2::enable_ept::is_allowed0());
    this->expect_false(msrs::ia32_vmx_procbased_ctls2::enable_ept::is_allowed1());
}

void
intrinsics_ut::test_ia32_vmx_procbased_ctls2_descriptor_table_exiting()
{
    auto mask = msrs::ia32_vmx_procbased_ctls2::descriptor_table_exiting::mask;

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = mask;
    this->expect_true(msrs::ia32_vmx_procbased_ctls2::descriptor_table_exiting::get());

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = ~mask;
    this->expect_false(msrs::ia32_vmx_procbased_ctls2::descriptor_table_exiting::get());

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = mask | (mask << 32);
    this->expect_false(msrs::ia32_vmx_procbased_ctls2::descriptor_table_exiting::is_allowed0());
    this->expect_true(msrs::ia32_vmx_procbased_ctls2::descriptor_table_exiting::is_allowed1());

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = ~mask & ~(mask << 32);
    this->expect_true(msrs::ia32_vmx_procbased_ctls2::descriptor_table_exiting::is_allowed0());
    this->expect_false(msrs::ia32_vmx_procbased_ctls2::descriptor_table_exiting::is_allowed1());
}

void
intrinsics_ut::test_ia32_vmx_procbased_ctls2_enable_rdtscp()
{
    auto mask = msrs::ia32_vmx_procbased_ctls2::enable_rdtscp::mask;

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = mask;
    this->expect_true(msrs::ia32_vmx_procbased_ctls2::enable_rdtscp::get());

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = ~mask;
    this->expect_false(msrs::ia32_vmx_procbased_ctls2::enable_rdtscp::get());

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = mask | (mask << 32);
    this->expect_false(msrs::ia32_vmx_procbased_ctls2::enable_rdtscp::is_allowed0());
    this->expect_true(msrs::ia32_vmx_procbased_ctls2::enable_rdtscp::is_allowed1());

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = ~mask & ~(mask << 32);
    this->expect_true(msrs::ia32_vmx_procbased_ctls2::enable_rdtscp::is_allowed0());
    this->expect_false(msrs::ia32_vmx_procbased_ctls2::enable_rdtscp::is_allowed1());
}

void
intrinsics_ut::test_ia32_vmx_procbased_ctls2_virtualize_x2apic_mode()
{
    auto mask = msrs::ia32_vmx_procbased_ctls2::virtualize_x2apic_mode::mask;

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = mask;
    this->expect_true(msrs::ia32_vmx_procbased_ctls2::virtualize_x2apic_mode::get());

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = ~mask;
    this->expect_false(msrs::ia32_vmx_procbased_ctls2::virtualize_x2apic_mode::get());

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = mask | (mask << 32);
    this->expect_false(msrs::ia32_vmx_procbased_ctls2::virtualize_x2apic_mode::is_allowed0());
    this->expect_true(msrs::ia32_vmx_procbased_ctls2::virtualize_x2apic_mode::is_allowed1());

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = ~mask & ~(mask << 32);
    this->expect_true(msrs::ia32_vmx_procbased_ctls2::virtualize_x2apic_mode::is_allowed0());
    this->expect_false(msrs::ia32_vmx_procbased_ctls2::virtualize_x2apic_mode::is_allowed1());
}

void
intrinsics_ut::test_ia32_vmx_procbased_ctls2_enable_vpid()
{
    auto mask = msrs::ia32_vmx_procbased_ctls2::enable_vpid::mask;

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = mask;
    this->expect_true(msrs::ia32_vmx_procbased_ctls2::enable_vpid::get());

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = ~mask;
    this->expect_false(msrs::ia32_vmx_procbased_ctls2::enable_vpid::get());

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = mask | (mask << 32);
    this->expect_false(msrs::ia32_vmx_procbased_ctls2::enable_vpid::is_allowed0());
    this->expect_true(msrs::ia32_vmx_procbased_ctls2::enable_vpid::is_allowed1());

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = ~mask & ~(mask << 32);
    this->expect_true(msrs::ia32_vmx_procbased_ctls2::enable_vpid::is_allowed0());
    this->expect_false(msrs::ia32_vmx_procbased_ctls2::enable_vpid::is_allowed1());
}

void
intrinsics_ut::test_ia32_vmx_procbased_ctls2_wbinvd_exiting()
{
    auto mask = msrs::ia32_vmx_procbased_ctls2::wbinvd_exiting::mask;

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = mask;
    this->expect_true(msrs::ia32_vmx_procbased_ctls2::wbinvd_exiting::get());

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = ~mask;
    this->expect_false(msrs::ia32_vmx_procbased_ctls2::wbinvd_exiting::get());

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = mask | (mask << 32);
    this->expect_false(msrs::ia32_vmx_procbased_ctls2::wbinvd_exiting::is_allowed0());
    this->expect_true(msrs::ia32_vmx_procbased_ctls2::wbinvd_exiting::is_allowed1());

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = ~mask & ~(mask << 32);
    this->expect_true(msrs::ia32_vmx_procbased_ctls2::wbinvd_exiting::is_allowed0());
    this->expect_false(msrs::ia32_vmx_procbased_ctls2::wbinvd_exiting::is_allowed1());
}

void
intrinsics_ut::test_ia32_vmx_procbased_ctls2_unrestricted_guest()
{
    auto mask = msrs::ia32_vmx_procbased_ctls2::unrestricted_guest::mask;

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = mask;
    this->expect_true(msrs::ia32_vmx_procbased_ctls2::unrestricted_guest::get());

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = ~mask;
    this->expect_false(msrs::ia32_vmx_procbased_ctls2::unrestricted_guest::get());

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = mask | (mask << 32);
    this->expect_false(msrs::ia32_vmx_procbased_ctls2::unrestricted_guest::is_allowed0());
    this->expect_true(msrs::ia32_vmx_procbased_ctls2::unrestricted_guest::is_allowed1());

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = ~mask & ~(mask << 32);
    this->expect_true(msrs::ia32_vmx_procbased_ctls2::unrestricted_guest::is_allowed0());
    this->expect_false(msrs::ia32_vmx_procbased_ctls2::unrestricted_guest::is_allowed1());
}

void
intrinsics_ut::test_ia32_vmx_procbased_ctls2_apic_register_virtualization()
{
    auto mask = msrs::ia32_vmx_procbased_ctls2::apic_register_virtualization::mask;

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = mask;
    this->expect_true(msrs::ia32_vmx_procbased_ctls2::apic_register_virtualization::get());

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = ~mask;
    this->expect_false(msrs::ia32_vmx_procbased_ctls2::apic_register_virtualization::get());

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = mask | (mask << 32);
    this->expect_false(msrs::ia32_vmx_procbased_ctls2::apic_register_virtualization::is_allowed0());
    this->expect_true(msrs::ia32_vmx_procbased_ctls2::apic_register_virtualization::is_allowed1());

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = ~mask & ~(mask << 32);
    this->expect_true(msrs::ia32_vmx_procbased_ctls2::apic_register_virtualization::is_allowed0());
    this->expect_false(msrs::ia32_vmx_procbased_ctls2::apic_register_virtualization::is_allowed1());
}

void
intrinsics_ut::test_ia32_vmx_procbased_ctls2_virtual_interrupt_delivery()
{
    auto mask = msrs::ia32_vmx_procbased_ctls2::virtual_interrupt_delivery::mask;

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = mask;
    this->expect_true(msrs::ia32_vmx_procbased_ctls2::virtual_interrupt_delivery::get());

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = ~mask;
    this->expect_false(msrs::ia32_vmx_procbased_ctls2::virtual_interrupt_delivery::get());

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = mask | (mask << 32);
    this->expect_false(msrs::ia32_vmx_procbased_ctls2::virtual_interrupt_delivery::is_allowed0());
    this->expect_true(msrs::ia32_vmx_procbased_ctls2::virtual_interrupt_delivery::is_allowed1());

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = ~mask & ~(mask << 32);
    this->expect_true(msrs::ia32_vmx_procbased_ctls2::virtual_interrupt_delivery::is_allowed0());
    this->expect_false(msrs::ia32_vmx_procbased_ctls2::virtual_interrupt_delivery::is_allowed1());
}

void
intrinsics_ut::test_ia32_vmx_procbased_ctls2_pause_loop_exiting()
{
    auto mask = msrs::ia32_vmx_procbased_ctls2::pause_loop_exiting::mask;

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = mask;
    this->expect_true(msrs::ia32_vmx_procbased_ctls2::pause_loop_exiting::get());

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = ~mask;
    this->expect_false(msrs::ia32_vmx_procbased_ctls2::pause_loop_exiting::get());

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = mask | (mask << 32);
    this->expect_false(msrs::ia32_vmx_procbased_ctls2::pause_loop_exiting::is_allowed0());
    this->expect_true(msrs::ia32_vmx_procbased_ctls2::pause_loop_exiting::is_allowed1());

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = ~mask & ~(mask << 32);
    this->expect_true(msrs::ia32_vmx_procbased_ctls2::pause_loop_exiting::is_allowed0());
    this->expect_false(msrs::ia32_vmx_procbased_ctls2::pause_loop_exiting::is_allowed1());
}

void
intrinsics_ut::test_ia32_vmx_procbased_ctls2_rdrand_exiting()
{
    auto mask = msrs::ia32_vmx_procbased_ctls2::rdrand_exiting::mask;

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = mask;
    this->expect_true(msrs::ia32_vmx_procbased_ctls2::rdrand_exiting::get());

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = ~mask;
    this->expect_false(msrs::ia32_vmx_procbased_ctls2::rdrand_exiting::get());

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = mask | (mask << 32);
    this->expect_false(msrs::ia32_vmx_procbased_ctls2::rdrand_exiting::is_allowed0());
    this->expect_true(msrs::ia32_vmx_procbased_ctls2::rdrand_exiting::is_allowed1());

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = ~mask & ~(mask << 32);
    this->expect_true(msrs::ia32_vmx_procbased_ctls2::rdrand_exiting::is_allowed0());
    this->expect_false(msrs::ia32_vmx_procbased_ctls2::rdrand_exiting::is_allowed1());
}

void
intrinsics_ut::test_ia32_vmx_procbased_ctls2_enable_invpcid()
{
    auto mask = msrs::ia32_vmx_procbased_ctls2::enable_invpcid::mask;

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = mask;
    this->expect_true(msrs::ia32_vmx_procbased_ctls2::enable_invpcid::get());

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = ~mask;
    this->expect_false(msrs::ia32_vmx_procbased_ctls2::enable_invpcid::get());

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = mask | (mask << 32);
    this->expect_false(msrs::ia32_vmx_procbased_ctls2::enable_invpcid::is_allowed0());
    this->expect_true(msrs::ia32_vmx_procbased_ctls2::enable_invpcid::is_allowed1());

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = ~mask & ~(mask << 32);
    this->expect_true(msrs::ia32_vmx_procbased_ctls2::enable_invpcid::is_allowed0());
    this->expect_false(msrs::ia32_vmx_procbased_ctls2::enable_invpcid::is_allowed1());
}

void
intrinsics_ut::test_ia32_vmx_procbased_ctls2_enable_vm_functions()
{
    auto mask = msrs::ia32_vmx_procbased_ctls2::enable_vm_functions::mask;

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = mask;
    this->expect_true(msrs::ia32_vmx_procbased_ctls2::enable_vm_functions::get());

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = ~mask;
    this->expect_false(msrs::ia32_vmx_procbased_ctls2::enable_vm_functions::get());

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = mask | (mask << 32);
    this->expect_false(msrs::ia32_vmx_procbased_ctls2::enable_vm_functions::is_allowed0());
    this->expect_true(msrs::ia32_vmx_procbased_ctls2::enable_vm_functions::is_allowed1());

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = ~mask & ~(mask << 32);
    this->expect_true(msrs::ia32_vmx_procbased_ctls2::enable_vm_functions::is_allowed0());
    this->expect_false(msrs::ia32_vmx_procbased_ctls2::enable_vm_functions::is_allowed1());
}

void
intrinsics_ut::test_ia32_vmx_procbased_ctls2_vmcs_shadowing()
{
    auto mask = msrs::ia32_vmx_procbased_ctls2::vmcs_shadowing::mask;

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = mask;
    this->expect_true(msrs::ia32_vmx_procbased_ctls2::vmcs_shadowing::get());

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = ~mask;
    this->expect_false(msrs::ia32_vmx_procbased_ctls2::vmcs_shadowing::get());

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = mask | (mask << 32);
    this->expect_false(msrs::ia32_vmx_procbased_ctls2::vmcs_shadowing::is_allowed0());
    this->expect_true(msrs::ia32_vmx_procbased_ctls2::vmcs_shadowing::is_allowed1());

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = ~mask & ~(mask << 32);
    this->expect_true(msrs::ia32_vmx_procbased_ctls2::vmcs_shadowing::is_allowed0());
    this->expect_false(msrs::ia32_vmx_procbased_ctls2::vmcs_shadowing::is_allowed1());
}

void
intrinsics_ut::test_ia32_vmx_procbased_ctls2_rdseed_exiting()
{
    auto mask = msrs::ia32_vmx_procbased_ctls2::rdseed_exiting::mask;

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = mask;
    this->expect_true(msrs::ia32_vmx_procbased_ctls2::rdseed_exiting::get());

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = ~mask;
    this->expect_false(msrs::ia32_vmx_procbased_ctls2::rdseed_exiting::get());

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = mask | (mask << 32);
    this->expect_false(msrs::ia32_vmx_procbased_ctls2::rdseed_exiting::is_allowed0());
    this->expect_true(msrs::ia32_vmx_procbased_ctls2::rdseed_exiting::is_allowed1());

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = ~mask & ~(mask << 32);
    this->expect_true(msrs::ia32_vmx_procbased_ctls2::rdseed_exiting::is_allowed0());
    this->expect_false(msrs::ia32_vmx_procbased_ctls2::rdseed_exiting::is_allowed1());
}

void
intrinsics_ut::test_ia32_vmx_procbased_ctls2_enable_pml()
{
    auto mask = msrs::ia32_vmx_procbased_ctls2::enable_pml::mask;

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = mask;
    this->expect_true(msrs::ia32_vmx_procbased_ctls2::enable_pml::get());

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = ~mask;
    this->expect_false(msrs::ia32_vmx_procbased_ctls2::enable_pml::get());

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = mask | (mask << 32);
    this->expect_false(msrs::ia32_vmx_procbased_ctls2::enable_pml::is_allowed0());
    this->expect_true(msrs::ia32_vmx_procbased_ctls2::enable_pml::is_allowed1());

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = ~mask & ~(mask << 32);
    this->expect_true(msrs::ia32_vmx_procbased_ctls2::enable_pml::is_allowed0());
    this->expect_false(msrs::ia32_vmx_procbased_ctls2::enable_pml::is_allowed1());
}

void
intrinsics_ut::test_ia32_vmx_procbased_ctls2_ept_violation_ve()
{
    auto mask = msrs::ia32_vmx_procbased_ctls2::ept_violation_ve::mask;

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = mask;
    this->expect_true(msrs::ia32_vmx_procbased_ctls2::ept_violation_ve::get());

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = ~mask;
    this->expect_false(msrs::ia32_vmx_procbased_ctls2::ept_violation_ve::get());

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = mask | (mask << 32);
    this->expect_false(msrs::ia32_vmx_procbased_ctls2::ept_violation_ve::is_allowed0());
    this->expect_true(msrs::ia32_vmx_procbased_ctls2::ept_violation_ve::is_allowed1());

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = ~mask & ~(mask << 32);
    this->expect_true(msrs::ia32_vmx_procbased_ctls2::ept_violation_ve::is_allowed0());
    this->expect_false(msrs::ia32_vmx_procbased_ctls2::ept_violation_ve::is_allowed1());
}

void
intrinsics_ut::test_ia32_vmx_procbased_ctls2_enable_xsaves_xrstors()
{
    auto mask = msrs::ia32_vmx_procbased_ctls2::enable_xsaves_xrstors::mask;

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = mask;
    this->expect_true(msrs::ia32_vmx_procbased_ctls2::enable_xsaves_xrstors::get());

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = ~mask;
    this->expect_false(msrs::ia32_vmx_procbased_ctls2::enable_xsaves_xrstors::get());

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = mask | (mask << 32);
    this->expect_false(msrs::ia32_vmx_procbased_ctls2::enable_xsaves_xrstors::is_allowed0());
    this->expect_true(msrs::ia32_vmx_procbased_ctls2::enable_xsaves_xrstors::is_allowed1());

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = ~mask & ~(mask << 32);
    this->expect_true(msrs::ia32_vmx_procbased_ctls2::enable_xsaves_xrstors::is_allowed0());
    this->expect_false(msrs::ia32_vmx_procbased_ctls2::enable_xsaves_xrstors::is_allowed1());
}

void
intrinsics_ut::test_ia32_vmx_ept_vpid_cap()
{
    g_msrs[msrs::ia32_vmx_ept_vpid_cap::addr] = 0xFFFFFFFFFFFFFFFFUL;
    this->expect_true(msrs::ia32_vmx_ept_vpid_cap::get() == 0xFFFFFFFFFFFFFFFFUL);

    msrs::ia32_vmx_ept_vpid_cap::dump();

    g_msrs[msrs::ia32_vmx_ept_vpid_cap::addr] = 0x0U;
    this->expect_true(msrs::ia32_vmx_ept_vpid_cap::get() == 0x0U);
}

void
intrinsics_ut::test_ia32_vmx_ept_vpid_cap_execute_only_translation()
{
    auto mask = msrs::ia32_vmx_ept_vpid_cap::execute_only_translation::mask;

    g_msrs[msrs::ia32_vmx_ept_vpid_cap::addr] = mask;
    this->expect_true(msrs::ia32_vmx_ept_vpid_cap::execute_only_translation::get());

    g_msrs[msrs::ia32_vmx_ept_vpid_cap::addr] = ~mask;
    this->expect_false(msrs::ia32_vmx_ept_vpid_cap::execute_only_translation::get());
}

void
intrinsics_ut::test_ia32_vmx_ept_vpid_cap_page_walk_length_of_4()
{
    auto mask = msrs::ia32_vmx_ept_vpid_cap::page_walk_length_of_4::mask;

    g_msrs[msrs::ia32_vmx_ept_vpid_cap::addr] = mask;
    this->expect_true(msrs::ia32_vmx_ept_vpid_cap::page_walk_length_of_4::get());

    g_msrs[msrs::ia32_vmx_ept_vpid_cap::addr] = ~mask;
    this->expect_false(msrs::ia32_vmx_ept_vpid_cap::page_walk_length_of_4::get());
}

void
intrinsics_ut::test_ia32_vmx_ept_vpid_cap_memory_type_uncacheable_supported()
{
    auto mask = msrs::ia32_vmx_ept_vpid_cap::memory_type_uncacheable_supported::mask;

    g_msrs[msrs::ia32_vmx_ept_vpid_cap::addr] = mask;
    this->expect_true(msrs::ia32_vmx_ept_vpid_cap::memory_type_uncacheable_supported::get());

    g_msrs[msrs::ia32_vmx_ept_vpid_cap::addr] = ~mask;
    this->expect_false(msrs::ia32_vmx_ept_vpid_cap::memory_type_uncacheable_supported::get());
}

void
intrinsics_ut::test_ia32_vmx_ept_vpid_cap_memory_type_write_back_supported()
{
    auto mask = msrs::ia32_vmx_ept_vpid_cap::memory_type_write_back_supported::mask;

    g_msrs[msrs::ia32_vmx_ept_vpid_cap::addr] = mask;
    this->expect_true(msrs::ia32_vmx_ept_vpid_cap::memory_type_write_back_supported::get());

    g_msrs[msrs::ia32_vmx_ept_vpid_cap::addr] = ~mask;
    this->expect_false(msrs::ia32_vmx_ept_vpid_cap::memory_type_write_back_supported::get());
}

void
intrinsics_ut::test_ia32_vmx_ept_vpid_cap_pde_2mb_support()
{
    auto mask = msrs::ia32_vmx_ept_vpid_cap::pde_2mb_support::mask;

    g_msrs[msrs::ia32_vmx_ept_vpid_cap::addr] = mask;
    this->expect_true(msrs::ia32_vmx_ept_vpid_cap::pde_2mb_support::get());

    g_msrs[msrs::ia32_vmx_ept_vpid_cap::addr] = ~mask;
    this->expect_false(msrs::ia32_vmx_ept_vpid_cap::pde_2mb_support::get());
}

void
intrinsics_ut::test_ia32_vmx_ept_vpid_cap_pdpte_1mb_support()
{
    auto mask = msrs::ia32_vmx_ept_vpid_cap::pdpte_1mb_support::mask;

    g_msrs[msrs::ia32_vmx_ept_vpid_cap::addr] = mask;
    this->expect_true(msrs::ia32_vmx_ept_vpid_cap::pdpte_1mb_support::get());

    g_msrs[msrs::ia32_vmx_ept_vpid_cap::addr] = ~mask;
    this->expect_false(msrs::ia32_vmx_ept_vpid_cap::pdpte_1mb_support::get());
}

void
intrinsics_ut::test_ia32_vmx_ept_vpid_cap_invept_support()
{
    auto mask = msrs::ia32_vmx_ept_vpid_cap::invept_support::mask;

    g_msrs[msrs::ia32_vmx_ept_vpid_cap::addr] = mask;
    this->expect_true(msrs::ia32_vmx_ept_vpid_cap::invept_support::get());

    g_msrs[msrs::ia32_vmx_ept_vpid_cap::addr] = ~mask;
    this->expect_false(msrs::ia32_vmx_ept_vpid_cap::invept_support::get());
}

void
intrinsics_ut::test_ia32_vmx_ept_vpid_cap_accessed_dirty_support()
{
    auto mask = msrs::ia32_vmx_ept_vpid_cap::accessed_dirty_support::mask;

    g_msrs[msrs::ia32_vmx_ept_vpid_cap::addr] = mask;
    this->expect_true(msrs::ia32_vmx_ept_vpid_cap::accessed_dirty_support::get());

    g_msrs[msrs::ia32_vmx_ept_vpid_cap::addr] = ~mask;
    this->expect_false(msrs::ia32_vmx_ept_vpid_cap::accessed_dirty_support::get());
}

void
intrinsics_ut::test_ia32_vmx_ept_vpid_cap_invept_single_context_support()
{
    auto mask = msrs::ia32_vmx_ept_vpid_cap::invept_single_context_support::mask;

    g_msrs[msrs::ia32_vmx_ept_vpid_cap::addr] = mask;
    this->expect_true(msrs::ia32_vmx_ept_vpid_cap::invept_single_context_support::get());

    g_msrs[msrs::ia32_vmx_ept_vpid_cap::addr] = ~mask;
    this->expect_false(msrs::ia32_vmx_ept_vpid_cap::invept_single_context_support::get());
}

void
intrinsics_ut::test_ia32_vmx_ept_vpid_cap_invept_all_context_support()
{
    auto mask = msrs::ia32_vmx_ept_vpid_cap::invept_all_context_support::mask;

    g_msrs[msrs::ia32_vmx_ept_vpid_cap::addr] = mask;
    this->expect_true(msrs::ia32_vmx_ept_vpid_cap::invept_all_context_support::get());

    g_msrs[msrs::ia32_vmx_ept_vpid_cap::addr] = ~mask;
    this->expect_false(msrs::ia32_vmx_ept_vpid_cap::invept_all_context_support::get());
}

void
intrinsics_ut::test_ia32_vmx_ept_vpid_cap_invvpid_support()
{
    auto mask = msrs::ia32_vmx_ept_vpid_cap::invvpid_support::mask;

    g_msrs[msrs::ia32_vmx_ept_vpid_cap::addr] = mask;
    this->expect_true(msrs::ia32_vmx_ept_vpid_cap::invvpid_support::get());

    g_msrs[msrs::ia32_vmx_ept_vpid_cap::addr] = ~mask;
    this->expect_false(msrs::ia32_vmx_ept_vpid_cap::invvpid_support::get());
}

void
intrinsics_ut::test_ia32_vmx_ept_vpid_cap_invvpid_individual_address_support()
{
    auto mask = msrs::ia32_vmx_ept_vpid_cap::invvpid_individual_address_support::mask;

    g_msrs[msrs::ia32_vmx_ept_vpid_cap::addr] = mask;
    this->expect_true(msrs::ia32_vmx_ept_vpid_cap::invvpid_individual_address_support::get());

    g_msrs[msrs::ia32_vmx_ept_vpid_cap::addr] = ~mask;
    this->expect_false(msrs::ia32_vmx_ept_vpid_cap::invvpid_individual_address_support::get());
}

void
intrinsics_ut::test_ia32_vmx_ept_vpid_cap_invvpid_single_context_support()
{
    auto mask = msrs::ia32_vmx_ept_vpid_cap::invvpid_single_context_support::mask;

    g_msrs[msrs::ia32_vmx_ept_vpid_cap::addr] = mask;
    this->expect_true(msrs::ia32_vmx_ept_vpid_cap::invvpid_single_context_support::get());

    g_msrs[msrs::ia32_vmx_ept_vpid_cap::addr] = ~mask;
    this->expect_false(msrs::ia32_vmx_ept_vpid_cap::invvpid_single_context_support::get());
}

void
intrinsics_ut::test_ia32_vmx_ept_vpid_cap_invvpid_all_context_support()
{
    auto mask = msrs::ia32_vmx_ept_vpid_cap::invvpid_all_context_support::mask;

    g_msrs[msrs::ia32_vmx_ept_vpid_cap::addr] = mask;
    this->expect_true(msrs::ia32_vmx_ept_vpid_cap::invvpid_all_context_support::get());

    g_msrs[msrs::ia32_vmx_ept_vpid_cap::addr] = ~mask;
    this->expect_false(msrs::ia32_vmx_ept_vpid_cap::invvpid_all_context_support::get());
}

void
intrinsics_ut::test_ia32_vmx_ept_vpid_cap_invvpid_single_context_retaining_globals_support()
{
    auto mask = msrs::ia32_vmx_ept_vpid_cap::invvpid_single_context_retaining_globals_support::mask;

    g_msrs[msrs::ia32_vmx_ept_vpid_cap::addr] = mask;
    this->expect_true(msrs::ia32_vmx_ept_vpid_cap::invvpid_single_context_retaining_globals_support::get());

    g_msrs[msrs::ia32_vmx_ept_vpid_cap::addr] = ~mask;
    this->expect_false(msrs::ia32_vmx_ept_vpid_cap::invvpid_single_context_retaining_globals_support::get());
}

void
intrinsics_ut::test_ia32_vmx_true_pinbased_ctls()
{
    g_msrs[msrs::ia32_vmx_true_pinbased_ctls::addr] = 0x00000000FFFFFFFFUL;
    this->expect_true(msrs::ia32_vmx_true_pinbased_ctls::get() == 0x00000000FFFFFFFFUL);

    msrs::ia32_vmx_true_pinbased_ctls::dump();

    g_msrs[msrs::ia32_vmx_true_pinbased_ctls::addr] = 0x0UL;
    this->expect_true(msrs::ia32_vmx_true_pinbased_ctls::get() == 0x0UL);

    msrs::ia32_vmx_true_pinbased_ctls::dump();

    g_msrs[msrs::ia32_vmx_true_pinbased_ctls::addr] = 0x00000000FFFFFFFFUL;
    this->expect_true(msrs::ia32_vmx_true_pinbased_ctls::allowed0() == 0xFFFFFFFFU);
    this->expect_true(msrs::ia32_vmx_true_pinbased_ctls::allowed1() == 0x00000000U);

    msrs::ia32_vmx_true_pinbased_ctls::dump();

    g_msrs[msrs::ia32_vmx_true_pinbased_ctls::addr] = 0xFFFFFFFF00000000U;
    this->expect_true(msrs::ia32_vmx_true_pinbased_ctls::allowed0() == 0x00000000U);
    this->expect_true(msrs::ia32_vmx_true_pinbased_ctls::allowed1() == 0xFFFFFFFFU);

    msrs::ia32_vmx_true_pinbased_ctls::dump();
}

void
intrinsics_ut::test_ia32_vmx_true_pinbased_ctls_external_interrupt_exiting()
{
    auto mask = msrs::ia32_vmx_true_pinbased_ctls::external_interrupt_exiting::mask;

    g_msrs[msrs::ia32_vmx_true_pinbased_ctls::addr] = mask;
    this->expect_true(msrs::ia32_vmx_true_pinbased_ctls::external_interrupt_exiting::get());

    g_msrs[msrs::ia32_vmx_true_pinbased_ctls::addr] = ~mask;
    this->expect_false(msrs::ia32_vmx_true_pinbased_ctls::external_interrupt_exiting::get());

    g_msrs[msrs::ia32_vmx_true_pinbased_ctls::addr] = mask | (mask << 32);
    this->expect_false(msrs::ia32_vmx_true_pinbased_ctls::external_interrupt_exiting::is_allowed0());
    this->expect_true(msrs::ia32_vmx_true_pinbased_ctls::external_interrupt_exiting::is_allowed1());

    g_msrs[msrs::ia32_vmx_true_pinbased_ctls::addr] = ~mask & ~(mask << 32);
    this->expect_true(msrs::ia32_vmx_true_pinbased_ctls::external_interrupt_exiting::is_allowed0());
    this->expect_false(msrs::ia32_vmx_true_pinbased_ctls::external_interrupt_exiting::is_allowed1());
}

void
intrinsics_ut::test_ia32_vmx_true_pinbased_ctls_nmi_exiting()
{
    auto mask = msrs::ia32_vmx_true_pinbased_ctls::nmi_exiting::mask;

    g_msrs[msrs::ia32_vmx_true_pinbased_ctls::addr] = mask;
    this->expect_true(msrs::ia32_vmx_true_pinbased_ctls::nmi_exiting::get());

    g_msrs[msrs::ia32_vmx_true_pinbased_ctls::addr] = ~mask;
    this->expect_false(msrs::ia32_vmx_true_pinbased_ctls::nmi_exiting::get());

    g_msrs[msrs::ia32_vmx_true_pinbased_ctls::addr] = mask | (mask << 32);
    this->expect_false(msrs::ia32_vmx_true_pinbased_ctls::nmi_exiting::is_allowed0());
    this->expect_true(msrs::ia32_vmx_true_pinbased_ctls::nmi_exiting::is_allowed1());

    g_msrs[msrs::ia32_vmx_true_pinbased_ctls::addr] = ~mask & ~(mask << 32);
    this->expect_true(msrs::ia32_vmx_true_pinbased_ctls::nmi_exiting::is_allowed0());
    this->expect_false(msrs::ia32_vmx_true_pinbased_ctls::nmi_exiting::is_allowed1());
}

void
intrinsics_ut::test_ia32_vmx_true_pinbased_ctls_virtual_nmis()
{
    auto mask = msrs::ia32_vmx_true_pinbased_ctls::virtual_nmis::mask;

    g_msrs[msrs::ia32_vmx_true_pinbased_ctls::addr] = mask;
    this->expect_true(msrs::ia32_vmx_true_pinbased_ctls::virtual_nmis::get());

    g_msrs[msrs::ia32_vmx_true_pinbased_ctls::addr] = ~mask;
    this->expect_false(msrs::ia32_vmx_true_pinbased_ctls::virtual_nmis::get());

    g_msrs[msrs::ia32_vmx_true_pinbased_ctls::addr] = mask | (mask << 32);
    this->expect_false(msrs::ia32_vmx_true_pinbased_ctls::virtual_nmis::is_allowed0());
    this->expect_true(msrs::ia32_vmx_true_pinbased_ctls::virtual_nmis::is_allowed1());

    g_msrs[msrs::ia32_vmx_true_pinbased_ctls::addr] = ~mask & ~(mask << 32);
    this->expect_true(msrs::ia32_vmx_true_pinbased_ctls::virtual_nmis::is_allowed0());
    this->expect_false(msrs::ia32_vmx_true_pinbased_ctls::virtual_nmis::is_allowed1());
}

void
intrinsics_ut::test_ia32_vmx_true_pinbased_ctls_activate_vmx_preemption_timer()
{
    auto mask = msrs::ia32_vmx_true_pinbased_ctls::activate_vmx_preemption_timer::mask;

    g_msrs[msrs::ia32_vmx_true_pinbased_ctls::addr] = mask;
    this->expect_true(msrs::ia32_vmx_true_pinbased_ctls::activate_vmx_preemption_timer::get());

    g_msrs[msrs::ia32_vmx_true_pinbased_ctls::addr] = ~mask;
    this->expect_false(msrs::ia32_vmx_true_pinbased_ctls::activate_vmx_preemption_timer::get());

    g_msrs[msrs::ia32_vmx_true_pinbased_ctls::addr] = mask | (mask << 32);
    this->expect_false(msrs::ia32_vmx_true_pinbased_ctls::activate_vmx_preemption_timer::is_allowed0());
    this->expect_true(msrs::ia32_vmx_true_pinbased_ctls::activate_vmx_preemption_timer::is_allowed1());

    g_msrs[msrs::ia32_vmx_true_pinbased_ctls::addr] = ~mask & ~(mask << 32);
    this->expect_true(msrs::ia32_vmx_true_pinbased_ctls::activate_vmx_preemption_timer::is_allowed0());
    this->expect_false(msrs::ia32_vmx_true_pinbased_ctls::activate_vmx_preemption_timer::is_allowed1());
}

void
intrinsics_ut::test_ia32_vmx_true_pinbased_ctls_process_posted_interrupts()
{
    auto mask = msrs::ia32_vmx_true_pinbased_ctls::process_posted_interrupts::mask;

    g_msrs[msrs::ia32_vmx_true_pinbased_ctls::addr] = mask;
    this->expect_true(msrs::ia32_vmx_true_pinbased_ctls::process_posted_interrupts::get());

    g_msrs[msrs::ia32_vmx_true_pinbased_ctls::addr] = ~mask;
    this->expect_false(msrs::ia32_vmx_true_pinbased_ctls::process_posted_interrupts::get());

    g_msrs[msrs::ia32_vmx_true_pinbased_ctls::addr] = mask | (mask << 32);
    this->expect_false(msrs::ia32_vmx_true_pinbased_ctls::process_posted_interrupts::is_allowed0());
    this->expect_true(msrs::ia32_vmx_true_pinbased_ctls::process_posted_interrupts::is_allowed1());

    g_msrs[msrs::ia32_vmx_true_pinbased_ctls::addr] = ~mask & ~(mask << 32);
    this->expect_true(msrs::ia32_vmx_true_pinbased_ctls::process_posted_interrupts::is_allowed0());
    this->expect_false(msrs::ia32_vmx_true_pinbased_ctls::process_posted_interrupts::is_allowed1());
}

void
intrinsics_ut::test_ia32_vmx_true_procbased_ctls()
{
    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0x00000000FFFFFFFFUL;
    this->expect_true(msrs::ia32_vmx_true_procbased_ctls::get() == 0x00000000FFFFFFFFUL);

    msrs::ia32_vmx_true_procbased_ctls::dump();

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0x0UL;
    this->expect_true(msrs::ia32_vmx_true_procbased_ctls::get() == 0x0UL);

    msrs::ia32_vmx_true_procbased_ctls::dump();

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0x00000000FFFFFFFFUL;
    this->expect_true(msrs::ia32_vmx_true_procbased_ctls::allowed0() == 0xFFFFFFFFU);
    this->expect_true(msrs::ia32_vmx_true_procbased_ctls::allowed1() == 0x00000000U);

    msrs::ia32_vmx_true_procbased_ctls::dump();

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xFFFFFFFF00000000U;
    this->expect_true(msrs::ia32_vmx_true_procbased_ctls::allowed0() == 0x00000000U);
    this->expect_true(msrs::ia32_vmx_true_procbased_ctls::allowed1() == 0xFFFFFFFFU);

    msrs::ia32_vmx_true_procbased_ctls::dump();
}

void
intrinsics_ut::test_ia32_vmx_true_procbased_ctls_interrupt_window_exiting()
{
    auto mask = msrs::ia32_vmx_true_procbased_ctls::interrupt_window_exiting::mask;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = mask;
    this->expect_true(msrs::ia32_vmx_true_procbased_ctls::interrupt_window_exiting::get());

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = ~mask;
    this->expect_false(msrs::ia32_vmx_true_procbased_ctls::interrupt_window_exiting::get());

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = mask | (mask << 32);
    this->expect_false(msrs::ia32_vmx_true_procbased_ctls::interrupt_window_exiting::is_allowed0());
    this->expect_true(msrs::ia32_vmx_true_procbased_ctls::interrupt_window_exiting::is_allowed1());

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = ~mask & ~(mask << 32);
    this->expect_true(msrs::ia32_vmx_true_procbased_ctls::interrupt_window_exiting::is_allowed0());
    this->expect_false(msrs::ia32_vmx_true_procbased_ctls::interrupt_window_exiting::is_allowed1());
}

void
intrinsics_ut::test_ia32_vmx_true_procbased_ctls_use_tsc_offsetting()
{
    auto mask = msrs::ia32_vmx_true_procbased_ctls::use_tsc_offsetting::mask;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = mask;
    this->expect_true(msrs::ia32_vmx_true_procbased_ctls::use_tsc_offsetting::get());

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = ~mask;
    this->expect_false(msrs::ia32_vmx_true_procbased_ctls::use_tsc_offsetting::get());

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = mask | (mask << 32);
    this->expect_false(msrs::ia32_vmx_true_procbased_ctls::use_tsc_offsetting::is_allowed0());
    this->expect_true(msrs::ia32_vmx_true_procbased_ctls::use_tsc_offsetting::is_allowed1());

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = ~mask & ~(mask << 32);
    this->expect_true(msrs::ia32_vmx_true_procbased_ctls::use_tsc_offsetting::is_allowed0());
    this->expect_false(msrs::ia32_vmx_true_procbased_ctls::use_tsc_offsetting::is_allowed1());
}

void
intrinsics_ut::test_ia32_vmx_true_procbased_ctls_hlt_exiting()
{
    auto mask = msrs::ia32_vmx_true_procbased_ctls::hlt_exiting::mask;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = mask;
    this->expect_true(msrs::ia32_vmx_true_procbased_ctls::hlt_exiting::get());

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = ~mask;
    this->expect_false(msrs::ia32_vmx_true_procbased_ctls::hlt_exiting::get());

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = mask | (mask << 32);
    this->expect_false(msrs::ia32_vmx_true_procbased_ctls::hlt_exiting::is_allowed0());
    this->expect_true(msrs::ia32_vmx_true_procbased_ctls::hlt_exiting::is_allowed1());

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = ~mask & ~(mask << 32);
    this->expect_true(msrs::ia32_vmx_true_procbased_ctls::hlt_exiting::is_allowed0());
    this->expect_false(msrs::ia32_vmx_true_procbased_ctls::hlt_exiting::is_allowed1());
}

void
intrinsics_ut::test_ia32_vmx_true_procbased_ctls_invlpg_exiting()
{
    auto mask = msrs::ia32_vmx_true_procbased_ctls::invlpg_exiting::mask;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = mask;
    this->expect_true(msrs::ia32_vmx_true_procbased_ctls::invlpg_exiting::get());

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = ~mask;
    this->expect_false(msrs::ia32_vmx_true_procbased_ctls::invlpg_exiting::get());

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = mask | (mask << 32);
    this->expect_false(msrs::ia32_vmx_true_procbased_ctls::invlpg_exiting::is_allowed0());
    this->expect_true(msrs::ia32_vmx_true_procbased_ctls::invlpg_exiting::is_allowed1());

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = ~mask & ~(mask << 32);
    this->expect_true(msrs::ia32_vmx_true_procbased_ctls::invlpg_exiting::is_allowed0());
    this->expect_false(msrs::ia32_vmx_true_procbased_ctls::invlpg_exiting::is_allowed1());
}

void
intrinsics_ut::test_ia32_vmx_true_procbased_ctls_mwait_exiting()
{
    auto mask = msrs::ia32_vmx_true_procbased_ctls::mwait_exiting::mask;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = mask;
    this->expect_true(msrs::ia32_vmx_true_procbased_ctls::mwait_exiting::get());

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = ~mask;
    this->expect_false(msrs::ia32_vmx_true_procbased_ctls::mwait_exiting::get());

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = mask | (mask << 32);
    this->expect_false(msrs::ia32_vmx_true_procbased_ctls::mwait_exiting::is_allowed0());
    this->expect_true(msrs::ia32_vmx_true_procbased_ctls::mwait_exiting::is_allowed1());

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = ~mask & ~(mask << 32);
    this->expect_true(msrs::ia32_vmx_true_procbased_ctls::mwait_exiting::is_allowed0());
    this->expect_false(msrs::ia32_vmx_true_procbased_ctls::mwait_exiting::is_allowed1());
}

void
intrinsics_ut::test_ia32_vmx_true_procbased_ctls_rdpmc_exiting()
{
    auto mask = msrs::ia32_vmx_true_procbased_ctls::rdpmc_exiting::mask;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = mask;
    this->expect_true(msrs::ia32_vmx_true_procbased_ctls::rdpmc_exiting::get());

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = ~mask;
    this->expect_false(msrs::ia32_vmx_true_procbased_ctls::rdpmc_exiting::get());

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = mask | (mask << 32);
    this->expect_false(msrs::ia32_vmx_true_procbased_ctls::rdpmc_exiting::is_allowed0());
    this->expect_true(msrs::ia32_vmx_true_procbased_ctls::rdpmc_exiting::is_allowed1());

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = ~mask & ~(mask << 32);
    this->expect_true(msrs::ia32_vmx_true_procbased_ctls::rdpmc_exiting::is_allowed0());
    this->expect_false(msrs::ia32_vmx_true_procbased_ctls::rdpmc_exiting::is_allowed1());
}

void
intrinsics_ut::test_ia32_vmx_true_procbased_ctls_rdtsc_exiting()
{
    auto mask = msrs::ia32_vmx_true_procbased_ctls::rdtsc_exiting::mask;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = mask;
    this->expect_true(msrs::ia32_vmx_true_procbased_ctls::rdtsc_exiting::get());

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = ~mask;
    this->expect_false(msrs::ia32_vmx_true_procbased_ctls::rdtsc_exiting::get());

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = mask | (mask << 32);
    this->expect_false(msrs::ia32_vmx_true_procbased_ctls::rdtsc_exiting::is_allowed0());
    this->expect_true(msrs::ia32_vmx_true_procbased_ctls::rdtsc_exiting::is_allowed1());

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = ~mask & ~(mask << 32);
    this->expect_true(msrs::ia32_vmx_true_procbased_ctls::rdtsc_exiting::is_allowed0());
    this->expect_false(msrs::ia32_vmx_true_procbased_ctls::rdtsc_exiting::is_allowed1());
}

void
intrinsics_ut::test_ia32_vmx_true_procbased_ctls_cr3_load_exiting()
{
    auto mask = msrs::ia32_vmx_true_procbased_ctls::cr3_load_exiting::mask;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = mask;
    this->expect_true(msrs::ia32_vmx_true_procbased_ctls::cr3_load_exiting::get());

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = ~mask;
    this->expect_false(msrs::ia32_vmx_true_procbased_ctls::cr3_load_exiting::get());

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = mask | (mask << 32);
    this->expect_false(msrs::ia32_vmx_true_procbased_ctls::cr3_load_exiting::is_allowed0());
    this->expect_true(msrs::ia32_vmx_true_procbased_ctls::cr3_load_exiting::is_allowed1());

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = ~mask & ~(mask << 32);
    this->expect_true(msrs::ia32_vmx_true_procbased_ctls::cr3_load_exiting::is_allowed0());
    this->expect_false(msrs::ia32_vmx_true_procbased_ctls::cr3_load_exiting::is_allowed1());
}

void
intrinsics_ut::test_ia32_vmx_true_procbased_ctls_cr3_store_exiting()
{
    auto mask = msrs::ia32_vmx_true_procbased_ctls::cr3_store_exiting::mask;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = mask;
    this->expect_true(msrs::ia32_vmx_true_procbased_ctls::cr3_store_exiting::get());

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = ~mask;
    this->expect_false(msrs::ia32_vmx_true_procbased_ctls::cr3_store_exiting::get());

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = mask | (mask << 32);
    this->expect_false(msrs::ia32_vmx_true_procbased_ctls::cr3_store_exiting::is_allowed0());
    this->expect_true(msrs::ia32_vmx_true_procbased_ctls::cr3_store_exiting::is_allowed1());

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = ~mask & ~(mask << 32);
    this->expect_true(msrs::ia32_vmx_true_procbased_ctls::cr3_store_exiting::is_allowed0());
    this->expect_false(msrs::ia32_vmx_true_procbased_ctls::cr3_store_exiting::is_allowed1());
}

void
intrinsics_ut::test_ia32_vmx_true_procbased_ctls_cr8_load_exiting()
{
    auto mask = msrs::ia32_vmx_true_procbased_ctls::cr8_load_exiting::mask;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = mask;
    this->expect_true(msrs::ia32_vmx_true_procbased_ctls::cr8_load_exiting::get());

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = ~mask;
    this->expect_false(msrs::ia32_vmx_true_procbased_ctls::cr8_load_exiting::get());

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = mask | (mask << 32);
    this->expect_false(msrs::ia32_vmx_true_procbased_ctls::cr8_load_exiting::is_allowed0());
    this->expect_true(msrs::ia32_vmx_true_procbased_ctls::cr8_load_exiting::is_allowed1());

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = ~mask & ~(mask << 32);
    this->expect_true(msrs::ia32_vmx_true_procbased_ctls::cr8_load_exiting::is_allowed0());
    this->expect_false(msrs::ia32_vmx_true_procbased_ctls::cr8_load_exiting::is_allowed1());
}

void
intrinsics_ut::test_ia32_vmx_true_procbased_ctls_cr8_store_exiting()
{
    auto mask = msrs::ia32_vmx_true_procbased_ctls::cr8_store_exiting::mask;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = mask;
    this->expect_true(msrs::ia32_vmx_true_procbased_ctls::cr8_store_exiting::get());

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = ~mask;
    this->expect_false(msrs::ia32_vmx_true_procbased_ctls::cr8_store_exiting::get());

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = mask | (mask << 32);
    this->expect_false(msrs::ia32_vmx_true_procbased_ctls::cr8_store_exiting::is_allowed0());
    this->expect_true(msrs::ia32_vmx_true_procbased_ctls::cr8_store_exiting::is_allowed1());

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = ~mask & ~(mask << 32);
    this->expect_true(msrs::ia32_vmx_true_procbased_ctls::cr8_store_exiting::is_allowed0());
    this->expect_false(msrs::ia32_vmx_true_procbased_ctls::cr8_store_exiting::is_allowed1());
}

void
intrinsics_ut::test_ia32_vmx_true_procbased_ctls_use_tpr_shadow()
{
    auto mask = msrs::ia32_vmx_true_procbased_ctls::use_tpr_shadow::mask;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = mask;
    this->expect_true(msrs::ia32_vmx_true_procbased_ctls::use_tpr_shadow::get());

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = ~mask;
    this->expect_false(msrs::ia32_vmx_true_procbased_ctls::use_tpr_shadow::get());

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = mask | (mask << 32);
    this->expect_false(msrs::ia32_vmx_true_procbased_ctls::use_tpr_shadow::is_allowed0());
    this->expect_true(msrs::ia32_vmx_true_procbased_ctls::use_tpr_shadow::is_allowed1());

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = ~mask & ~(mask << 32);
    this->expect_true(msrs::ia32_vmx_true_procbased_ctls::use_tpr_shadow::is_allowed0());
    this->expect_false(msrs::ia32_vmx_true_procbased_ctls::use_tpr_shadow::is_allowed1());
}

void
intrinsics_ut::test_ia32_vmx_true_procbased_ctls_nmi_window_exiting()
{
    auto mask = msrs::ia32_vmx_true_procbased_ctls::nmi_window_exiting::mask;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = mask;
    this->expect_true(msrs::ia32_vmx_true_procbased_ctls::nmi_window_exiting::get());

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = ~mask;
    this->expect_false(msrs::ia32_vmx_true_procbased_ctls::nmi_window_exiting::get());

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = mask | (mask << 32);
    this->expect_false(msrs::ia32_vmx_true_procbased_ctls::nmi_window_exiting::is_allowed0());
    this->expect_true(msrs::ia32_vmx_true_procbased_ctls::nmi_window_exiting::is_allowed1());

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = ~mask & ~(mask << 32);
    this->expect_true(msrs::ia32_vmx_true_procbased_ctls::nmi_window_exiting::is_allowed0());
    this->expect_false(msrs::ia32_vmx_true_procbased_ctls::nmi_window_exiting::is_allowed1());
}

void
intrinsics_ut::test_ia32_vmx_true_procbased_ctls_mov_dr_exiting()
{
    auto mask = msrs::ia32_vmx_true_procbased_ctls::mov_dr_exiting::mask;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = mask;
    this->expect_true(msrs::ia32_vmx_true_procbased_ctls::mov_dr_exiting::get());

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = ~mask;
    this->expect_false(msrs::ia32_vmx_true_procbased_ctls::mov_dr_exiting::get());

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = mask | (mask << 32);
    this->expect_false(msrs::ia32_vmx_true_procbased_ctls::mov_dr_exiting::is_allowed0());
    this->expect_true(msrs::ia32_vmx_true_procbased_ctls::mov_dr_exiting::is_allowed1());

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = ~mask & ~(mask << 32);
    this->expect_true(msrs::ia32_vmx_true_procbased_ctls::mov_dr_exiting::is_allowed0());
    this->expect_false(msrs::ia32_vmx_true_procbased_ctls::mov_dr_exiting::is_allowed1());
}

void
intrinsics_ut::test_ia32_vmx_true_procbased_ctls_unconditional_io_exiting()
{
    auto mask = msrs::ia32_vmx_true_procbased_ctls::unconditional_io_exiting::mask;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = mask;
    this->expect_true(msrs::ia32_vmx_true_procbased_ctls::unconditional_io_exiting::get());

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = ~mask;
    this->expect_false(msrs::ia32_vmx_true_procbased_ctls::unconditional_io_exiting::get());

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = mask | (mask << 32);
    this->expect_false(msrs::ia32_vmx_true_procbased_ctls::unconditional_io_exiting::is_allowed0());
    this->expect_true(msrs::ia32_vmx_true_procbased_ctls::unconditional_io_exiting::is_allowed1());

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = ~mask & ~(mask << 32);
    this->expect_true(msrs::ia32_vmx_true_procbased_ctls::unconditional_io_exiting::is_allowed0());
    this->expect_false(msrs::ia32_vmx_true_procbased_ctls::unconditional_io_exiting::is_allowed1());
}

void
intrinsics_ut::test_ia32_vmx_true_procbased_ctls_use_io_bitmaps()
{
    auto mask = msrs::ia32_vmx_true_procbased_ctls::use_io_bitmaps::mask;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = mask;
    this->expect_true(msrs::ia32_vmx_true_procbased_ctls::use_io_bitmaps::get());

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = ~mask;
    this->expect_false(msrs::ia32_vmx_true_procbased_ctls::use_io_bitmaps::get());

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = mask | (mask << 32);
    this->expect_false(msrs::ia32_vmx_true_procbased_ctls::use_io_bitmaps::is_allowed0());
    this->expect_true(msrs::ia32_vmx_true_procbased_ctls::use_io_bitmaps::is_allowed1());

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = ~mask & ~(mask << 32);
    this->expect_true(msrs::ia32_vmx_true_procbased_ctls::use_io_bitmaps::is_allowed0());
    this->expect_false(msrs::ia32_vmx_true_procbased_ctls::use_io_bitmaps::is_allowed1());
}

void
intrinsics_ut::test_ia32_vmx_true_procbased_ctls_monitor_trap_flag()
{
    auto mask = msrs::ia32_vmx_true_procbased_ctls::monitor_trap_flag::mask;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = mask;
    this->expect_true(msrs::ia32_vmx_true_procbased_ctls::monitor_trap_flag::get());

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = ~mask;
    this->expect_false(msrs::ia32_vmx_true_procbased_ctls::monitor_trap_flag::get());

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = mask | (mask << 32);
    this->expect_false(msrs::ia32_vmx_true_procbased_ctls::monitor_trap_flag::is_allowed0());
    this->expect_true(msrs::ia32_vmx_true_procbased_ctls::monitor_trap_flag::is_allowed1());

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = ~mask & ~(mask << 32);
    this->expect_true(msrs::ia32_vmx_true_procbased_ctls::monitor_trap_flag::is_allowed0());
    this->expect_false(msrs::ia32_vmx_true_procbased_ctls::monitor_trap_flag::is_allowed1());
}

void
intrinsics_ut::test_ia32_vmx_true_procbased_ctls_use_msr_bitmaps()
{
    auto mask = msrs::ia32_vmx_true_procbased_ctls::use_msr_bitmaps::mask;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = mask;
    this->expect_true(msrs::ia32_vmx_true_procbased_ctls::use_msr_bitmaps::get());

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = ~mask;
    this->expect_false(msrs::ia32_vmx_true_procbased_ctls::use_msr_bitmaps::get());

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = mask | (mask << 32);
    this->expect_false(msrs::ia32_vmx_true_procbased_ctls::use_msr_bitmaps::is_allowed0());
    this->expect_true(msrs::ia32_vmx_true_procbased_ctls::use_msr_bitmaps::is_allowed1());

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = ~mask & ~(mask << 32);
    this->expect_true(msrs::ia32_vmx_true_procbased_ctls::use_msr_bitmaps::is_allowed0());
    this->expect_false(msrs::ia32_vmx_true_procbased_ctls::use_msr_bitmaps::is_allowed1());
}

void
intrinsics_ut::test_ia32_vmx_true_procbased_ctls_monitor_exiting()
{
    auto mask = msrs::ia32_vmx_true_procbased_ctls::monitor_exiting::mask;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = mask;
    this->expect_true(msrs::ia32_vmx_true_procbased_ctls::monitor_exiting::get());

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = ~mask;
    this->expect_false(msrs::ia32_vmx_true_procbased_ctls::monitor_exiting::get());

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = mask | (mask << 32);
    this->expect_false(msrs::ia32_vmx_true_procbased_ctls::monitor_exiting::is_allowed0());
    this->expect_true(msrs::ia32_vmx_true_procbased_ctls::monitor_exiting::is_allowed1());

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = ~mask & ~(mask << 32);
    this->expect_true(msrs::ia32_vmx_true_procbased_ctls::monitor_exiting::is_allowed0());
    this->expect_false(msrs::ia32_vmx_true_procbased_ctls::monitor_exiting::is_allowed1());
}

void
intrinsics_ut::test_ia32_vmx_true_procbased_ctls_pause_exiting()
{
    auto mask = msrs::ia32_vmx_true_procbased_ctls::pause_exiting::mask;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = mask;
    this->expect_true(msrs::ia32_vmx_true_procbased_ctls::pause_exiting::get());

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = ~mask;
    this->expect_false(msrs::ia32_vmx_true_procbased_ctls::pause_exiting::get());

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = mask | (mask << 32);
    this->expect_false(msrs::ia32_vmx_true_procbased_ctls::pause_exiting::is_allowed0());
    this->expect_true(msrs::ia32_vmx_true_procbased_ctls::pause_exiting::is_allowed1());

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = ~mask & ~(mask << 32);
    this->expect_true(msrs::ia32_vmx_true_procbased_ctls::pause_exiting::is_allowed0());
    this->expect_false(msrs::ia32_vmx_true_procbased_ctls::pause_exiting::is_allowed1());
}

void
intrinsics_ut::test_ia32_vmx_true_procbased_ctls_activate_secondary_controls()
{
    auto mask = msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = mask;
    this->expect_true(msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::get());

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = ~mask;
    this->expect_false(msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::get());

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = mask | (mask << 32);
    this->expect_false(msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::is_allowed0());
    this->expect_true(msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::is_allowed1());

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = ~mask & ~(mask << 32);
    this->expect_true(msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::is_allowed0());
    this->expect_false(msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::is_allowed1());
}

void
intrinsics_ut::test_ia32_vmx_true_exit_ctls()
{
    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] = 0x00000000FFFFFFFFUL;
    this->expect_true(msrs::ia32_vmx_true_exit_ctls::get() == 0x00000000FFFFFFFFUL);

    msrs::ia32_vmx_true_exit_ctls::dump();

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] = 0x0UL;
    this->expect_true(msrs::ia32_vmx_true_exit_ctls::get() == 0x0UL);

    msrs::ia32_vmx_true_exit_ctls::dump();

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] = 0x00000000FFFFFFFFUL;
    this->expect_true(msrs::ia32_vmx_true_exit_ctls::allowed0() == 0xFFFFFFFFU);
    this->expect_true(msrs::ia32_vmx_true_exit_ctls::allowed1() == 0x00000000U);

    msrs::ia32_vmx_true_exit_ctls::dump();

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] = 0xFFFFFFFF00000000U;
    this->expect_true(msrs::ia32_vmx_true_exit_ctls::allowed0() == 0x00000000U);
    this->expect_true(msrs::ia32_vmx_true_exit_ctls::allowed1() == 0xFFFFFFFFU);

    msrs::ia32_vmx_true_exit_ctls::dump();
}

void
intrinsics_ut::test_ia32_vmx_true_exit_ctls_save_debug_controls()
{
    auto mask = msrs::ia32_vmx_true_exit_ctls::save_debug_controls::mask;

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] = mask;
    this->expect_true(msrs::ia32_vmx_true_exit_ctls::save_debug_controls::get());

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] = ~mask;
    this->expect_false(msrs::ia32_vmx_true_exit_ctls::save_debug_controls::get());

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] = mask | (mask << 32);
    this->expect_false(msrs::ia32_vmx_true_exit_ctls::save_debug_controls::is_allowed0());
    this->expect_true(msrs::ia32_vmx_true_exit_ctls::save_debug_controls::is_allowed1());

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] = ~mask & ~(mask << 32);
    this->expect_true(msrs::ia32_vmx_true_exit_ctls::save_debug_controls::is_allowed0());
    this->expect_false(msrs::ia32_vmx_true_exit_ctls::save_debug_controls::is_allowed1());
}

void
intrinsics_ut::test_ia32_vmx_true_exit_ctls_host_address_space_size()
{
    auto mask = msrs::ia32_vmx_true_exit_ctls::host_address_space_size::mask;

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] = mask;
    this->expect_true(msrs::ia32_vmx_true_exit_ctls::host_address_space_size::get());

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] = ~mask;
    this->expect_false(msrs::ia32_vmx_true_exit_ctls::host_address_space_size::get());

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] = mask | (mask << 32);
    this->expect_false(msrs::ia32_vmx_true_exit_ctls::host_address_space_size::is_allowed0());
    this->expect_true(msrs::ia32_vmx_true_exit_ctls::host_address_space_size::is_allowed1());

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] = ~mask & ~(mask << 32);
    this->expect_true(msrs::ia32_vmx_true_exit_ctls::host_address_space_size::is_allowed0());
    this->expect_false(msrs::ia32_vmx_true_exit_ctls::host_address_space_size::is_allowed1());
}

void
intrinsics_ut::test_ia32_vmx_true_exit_ctls_load_ia32_perf_global_ctrl()
{
    auto mask = msrs::ia32_vmx_true_exit_ctls::load_ia32_perf_global_ctrl::mask;

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] = mask;
    this->expect_true(msrs::ia32_vmx_true_exit_ctls::load_ia32_perf_global_ctrl::get());

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] = ~mask;
    this->expect_false(msrs::ia32_vmx_true_exit_ctls::load_ia32_perf_global_ctrl::get());

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] = mask | (mask << 32);
    this->expect_false(msrs::ia32_vmx_true_exit_ctls::load_ia32_perf_global_ctrl::is_allowed0());
    this->expect_true(msrs::ia32_vmx_true_exit_ctls::load_ia32_perf_global_ctrl::is_allowed1());

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] = ~mask & ~(mask << 32);
    this->expect_true(msrs::ia32_vmx_true_exit_ctls::load_ia32_perf_global_ctrl::is_allowed0());
    this->expect_false(msrs::ia32_vmx_true_exit_ctls::load_ia32_perf_global_ctrl::is_allowed1());
}

void
intrinsics_ut::test_ia32_vmx_true_exit_ctls_acknowledge_interrupt_on_exit()
{
    auto mask = msrs::ia32_vmx_true_exit_ctls::acknowledge_interrupt_on_exit::mask;

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] = mask;
    this->expect_true(msrs::ia32_vmx_true_exit_ctls::acknowledge_interrupt_on_exit::get());

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] = ~mask;
    this->expect_false(msrs::ia32_vmx_true_exit_ctls::acknowledge_interrupt_on_exit::get());

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] = mask | (mask << 32);
    this->expect_false(msrs::ia32_vmx_true_exit_ctls::acknowledge_interrupt_on_exit::is_allowed0());
    this->expect_true(msrs::ia32_vmx_true_exit_ctls::acknowledge_interrupt_on_exit::is_allowed1());

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] = ~mask & ~(mask << 32);
    this->expect_true(msrs::ia32_vmx_true_exit_ctls::acknowledge_interrupt_on_exit::is_allowed0());
    this->expect_false(msrs::ia32_vmx_true_exit_ctls::acknowledge_interrupt_on_exit::is_allowed1());
}

void
intrinsics_ut::test_ia32_vmx_true_exit_ctls_save_ia32_pat()
{
    auto mask = msrs::ia32_vmx_true_exit_ctls::save_ia32_pat::mask;

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] = mask;
    this->expect_true(msrs::ia32_vmx_true_exit_ctls::save_ia32_pat::get());

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] = ~mask;
    this->expect_false(msrs::ia32_vmx_true_exit_ctls::save_ia32_pat::get());

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] = mask | (mask << 32);
    this->expect_false(msrs::ia32_vmx_true_exit_ctls::save_ia32_pat::is_allowed0());
    this->expect_true(msrs::ia32_vmx_true_exit_ctls::save_ia32_pat::is_allowed1());

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] = ~mask & ~(mask << 32);
    this->expect_true(msrs::ia32_vmx_true_exit_ctls::save_ia32_pat::is_allowed0());
    this->expect_false(msrs::ia32_vmx_true_exit_ctls::save_ia32_pat::is_allowed1());
}

void
intrinsics_ut::test_ia32_vmx_true_exit_ctls_load_ia32_pat()
{
    auto mask = msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::mask;

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] = mask;
    this->expect_true(msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::get());

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] = ~mask;
    this->expect_false(msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::get());

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] = mask | (mask << 32);
    this->expect_false(msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::is_allowed0());
    this->expect_true(msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::is_allowed1());

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] = ~mask & ~(mask << 32);
    this->expect_true(msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::is_allowed0());
    this->expect_false(msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::is_allowed1());
}

void
intrinsics_ut::test_ia32_vmx_true_exit_ctls_save_ia32_efer()
{
    auto mask = msrs::ia32_vmx_true_exit_ctls::save_ia32_efer::mask;

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] = mask;
    this->expect_true(msrs::ia32_vmx_true_exit_ctls::save_ia32_efer::get());

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] = ~mask;
    this->expect_false(msrs::ia32_vmx_true_exit_ctls::save_ia32_efer::get());

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] = mask | (mask << 32);
    this->expect_false(msrs::ia32_vmx_true_exit_ctls::save_ia32_efer::is_allowed0());
    this->expect_true(msrs::ia32_vmx_true_exit_ctls::save_ia32_efer::is_allowed1());

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] = ~mask & ~(mask << 32);
    this->expect_true(msrs::ia32_vmx_true_exit_ctls::save_ia32_efer::is_allowed0());
    this->expect_false(msrs::ia32_vmx_true_exit_ctls::save_ia32_efer::is_allowed1());
}

void
intrinsics_ut::test_ia32_vmx_true_exit_ctls_load_ia32_efer()
{
    auto mask = msrs::ia32_vmx_true_exit_ctls::load_ia32_efer::mask;

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] = mask;
    this->expect_true(msrs::ia32_vmx_true_exit_ctls::load_ia32_efer::get());

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] = ~mask;
    this->expect_false(msrs::ia32_vmx_true_exit_ctls::load_ia32_efer::get());

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] = mask | (mask << 32);
    this->expect_false(msrs::ia32_vmx_true_exit_ctls::load_ia32_efer::is_allowed0());
    this->expect_true(msrs::ia32_vmx_true_exit_ctls::load_ia32_efer::is_allowed1());

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] = ~mask & ~(mask << 32);
    this->expect_true(msrs::ia32_vmx_true_exit_ctls::load_ia32_efer::is_allowed0());
    this->expect_false(msrs::ia32_vmx_true_exit_ctls::load_ia32_efer::is_allowed1());
}

void
intrinsics_ut::test_ia32_vmx_true_exit_ctls_save_vmx_preemption_timer_value()
{
    auto mask = msrs::ia32_vmx_true_exit_ctls::save_vmx_preemption_timer_value::mask;

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] = mask;
    this->expect_true(msrs::ia32_vmx_true_exit_ctls::save_vmx_preemption_timer_value::get());

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] = ~mask;
    this->expect_false(msrs::ia32_vmx_true_exit_ctls::save_vmx_preemption_timer_value::get());

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] = mask | (mask << 32);
    this->expect_false(msrs::ia32_vmx_true_exit_ctls::save_vmx_preemption_timer_value::is_allowed0());
    this->expect_true(msrs::ia32_vmx_true_exit_ctls::save_vmx_preemption_timer_value::is_allowed1());

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] = ~mask & ~(mask << 32);
    this->expect_true(msrs::ia32_vmx_true_exit_ctls::save_vmx_preemption_timer_value::is_allowed0());
    this->expect_false(msrs::ia32_vmx_true_exit_ctls::save_vmx_preemption_timer_value::is_allowed1());
}

void
intrinsics_ut::test_ia32_vmx_true_entry_ctls()
{
    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] = 0x00000000FFFFFFFFUL;
    this->expect_true(msrs::ia32_vmx_true_entry_ctls::get() == 0x00000000FFFFFFFFUL);

    msrs::ia32_vmx_true_entry_ctls::dump();

    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] = 0x0UL;
    this->expect_true(msrs::ia32_vmx_true_entry_ctls::get() == 0x0UL);

    msrs::ia32_vmx_true_entry_ctls::dump();

    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] = 0x00000000FFFFFFFFUL;
    this->expect_true(msrs::ia32_vmx_true_entry_ctls::allowed0() == 0xFFFFFFFFU);
    this->expect_true(msrs::ia32_vmx_true_entry_ctls::allowed1() == 0x00000000U);

    msrs::ia32_vmx_true_entry_ctls::dump();

    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] = 0xFFFFFFFF00000000U;
    this->expect_true(msrs::ia32_vmx_true_entry_ctls::allowed0() == 0x00000000U);
    this->expect_true(msrs::ia32_vmx_true_entry_ctls::allowed1() == 0xFFFFFFFFU);

    msrs::ia32_vmx_true_entry_ctls::dump();
}

void
intrinsics_ut::test_ia32_vmx_true_entry_ctls_load_debug_controls()
{
    auto mask = msrs::ia32_vmx_true_entry_ctls::load_debug_controls::mask;

    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] = mask;
    this->expect_true(msrs::ia32_vmx_true_entry_ctls::load_debug_controls::get());

    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] = ~mask;
    this->expect_false(msrs::ia32_vmx_true_entry_ctls::load_debug_controls::get());

    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] = mask | (mask << 32);
    this->expect_false(msrs::ia32_vmx_true_entry_ctls::load_debug_controls::is_allowed0());
    this->expect_true(msrs::ia32_vmx_true_entry_ctls::load_debug_controls::is_allowed1());

    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] = ~mask & ~(mask << 32);
    this->expect_true(msrs::ia32_vmx_true_entry_ctls::load_debug_controls::is_allowed0());
    this->expect_false(msrs::ia32_vmx_true_entry_ctls::load_debug_controls::is_allowed1());
}

void
intrinsics_ut::test_ia32_vmx_true_entry_ctls_ia_32e_mode_guest()
{
    auto mask = msrs::ia32_vmx_true_entry_ctls::ia_32e_mode_guest::mask;

    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] = mask;
    this->expect_true(msrs::ia32_vmx_true_entry_ctls::ia_32e_mode_guest::get());

    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] = ~mask;
    this->expect_false(msrs::ia32_vmx_true_entry_ctls::ia_32e_mode_guest::get());

    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] = mask | (mask << 32);
    this->expect_false(msrs::ia32_vmx_true_entry_ctls::ia_32e_mode_guest::is_allowed0());
    this->expect_true(msrs::ia32_vmx_true_entry_ctls::ia_32e_mode_guest::is_allowed1());

    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] = ~mask & ~(mask << 32);
    this->expect_true(msrs::ia32_vmx_true_entry_ctls::ia_32e_mode_guest::is_allowed0());
    this->expect_false(msrs::ia32_vmx_true_entry_ctls::ia_32e_mode_guest::is_allowed1());
}

void
intrinsics_ut::test_ia32_vmx_true_entry_ctls_entry_to_smm()
{
    auto mask = msrs::ia32_vmx_true_entry_ctls::entry_to_smm::mask;

    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] = mask;
    this->expect_true(msrs::ia32_vmx_true_entry_ctls::entry_to_smm::get());

    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] = ~mask;
    this->expect_false(msrs::ia32_vmx_true_entry_ctls::entry_to_smm::get());

    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] = mask | (mask << 32);
    this->expect_false(msrs::ia32_vmx_true_entry_ctls::entry_to_smm::is_allowed0());
    this->expect_true(msrs::ia32_vmx_true_entry_ctls::entry_to_smm::is_allowed1());

    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] = ~mask & ~(mask << 32);
    this->expect_true(msrs::ia32_vmx_true_entry_ctls::entry_to_smm::is_allowed0());
    this->expect_false(msrs::ia32_vmx_true_entry_ctls::entry_to_smm::is_allowed1());
}

void
intrinsics_ut::test_ia32_vmx_true_entry_ctls_deactivate_dual_monitor_treatment()
{
    auto mask = msrs::ia32_vmx_true_entry_ctls::deactivate_dual_monitor_treatment::mask;

    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] = mask;
    this->expect_true(msrs::ia32_vmx_true_entry_ctls::deactivate_dual_monitor_treatment::get());

    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] = ~mask;
    this->expect_false(msrs::ia32_vmx_true_entry_ctls::deactivate_dual_monitor_treatment::get());

    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] = mask | (mask << 32);
    this->expect_false(msrs::ia32_vmx_true_entry_ctls::deactivate_dual_monitor_treatment::is_allowed0());
    this->expect_true(msrs::ia32_vmx_true_entry_ctls::deactivate_dual_monitor_treatment::is_allowed1());

    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] = ~mask & ~(mask << 32);
    this->expect_true(msrs::ia32_vmx_true_entry_ctls::deactivate_dual_monitor_treatment::is_allowed0());
    this->expect_false(msrs::ia32_vmx_true_entry_ctls::deactivate_dual_monitor_treatment::is_allowed1());
}

void
intrinsics_ut::test_ia32_vmx_true_entry_ctls_load_ia32_perf_global_ctrl()
{
    auto mask = msrs::ia32_vmx_true_entry_ctls::load_ia32_perf_global_ctrl::mask;

    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] = mask;
    this->expect_true(msrs::ia32_vmx_true_entry_ctls::load_ia32_perf_global_ctrl::get());

    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] = ~mask;
    this->expect_false(msrs::ia32_vmx_true_entry_ctls::load_ia32_perf_global_ctrl::get());

    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] = mask | (mask << 32);
    this->expect_false(msrs::ia32_vmx_true_entry_ctls::load_ia32_perf_global_ctrl::is_allowed0());
    this->expect_true(msrs::ia32_vmx_true_entry_ctls::load_ia32_perf_global_ctrl::is_allowed1());

    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] = ~mask & ~(mask << 32);
    this->expect_true(msrs::ia32_vmx_true_entry_ctls::load_ia32_perf_global_ctrl::is_allowed0());
    this->expect_false(msrs::ia32_vmx_true_entry_ctls::load_ia32_perf_global_ctrl::is_allowed1());
}

void
intrinsics_ut::test_ia32_vmx_true_entry_ctls_load_ia32_pat()
{
    auto mask = msrs::ia32_vmx_true_entry_ctls::load_ia32_pat::mask;

    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] = mask;
    this->expect_true(msrs::ia32_vmx_true_entry_ctls::load_ia32_pat::get());

    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] = ~mask;
    this->expect_false(msrs::ia32_vmx_true_entry_ctls::load_ia32_pat::get());

    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] = mask | (mask << 32);
    this->expect_false(msrs::ia32_vmx_true_entry_ctls::load_ia32_pat::is_allowed0());
    this->expect_true(msrs::ia32_vmx_true_entry_ctls::load_ia32_pat::is_allowed1());

    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] = ~mask & ~(mask << 32);
    this->expect_true(msrs::ia32_vmx_true_entry_ctls::load_ia32_pat::is_allowed0());
    this->expect_false(msrs::ia32_vmx_true_entry_ctls::load_ia32_pat::is_allowed1());
}

void
intrinsics_ut::test_ia32_vmx_true_entry_ctls_load_ia32_efer()
{
    auto mask = msrs::ia32_vmx_true_entry_ctls::load_ia32_efer::mask;

    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] = mask;
    this->expect_true(msrs::ia32_vmx_true_entry_ctls::load_ia32_efer::get());

    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] = ~mask;
    this->expect_false(msrs::ia32_vmx_true_entry_ctls::load_ia32_efer::get());

    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] = mask | (mask << 32);
    this->expect_false(msrs::ia32_vmx_true_entry_ctls::load_ia32_efer::is_allowed0());
    this->expect_true(msrs::ia32_vmx_true_entry_ctls::load_ia32_efer::is_allowed1());

    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] = ~mask & ~(mask << 32);
    this->expect_true(msrs::ia32_vmx_true_entry_ctls::load_ia32_efer::is_allowed0());
    this->expect_false(msrs::ia32_vmx_true_entry_ctls::load_ia32_efer::is_allowed1());
}

void
intrinsics_ut::test_ia32_vmx_vmfunc()
{
    g_msrs[msrs::ia32_vmx_vmfunc::addr] = 0xFFFFFFFFFFFFFFFFUL;
    this->expect_true(msrs::ia32_vmx_vmfunc::get() == 0xFFFFFFFFFFFFFFFFUL);

    g_msrs[msrs::ia32_vmx_vmfunc::addr] = 0x0U;
    this->expect_true(msrs::ia32_vmx_vmfunc::get() == 0x0U);
}

void
intrinsics_ut::test_ia32_efer()
{
    msrs::ia32_efer::set(0xFFFFFFFFFFFFFFFFUL);
    this->expect_true(msrs::ia32_efer::get() == 0xFFFFFFFFFFFFFFFFUL);

    msrs::ia32_efer::dump();

    msrs::ia32_efer::set(0x0U);
    this->expect_true(msrs::ia32_efer::get() == 0x0U);
}

void
intrinsics_ut::test_ia32_efer_sce()
{
    msrs::ia32_efer::sce::set(true);
    this->expect_true(msrs::ia32_efer::sce::get());

    msrs::ia32_efer::sce::set(false);
    this->expect_false(msrs::ia32_efer::sce::get());
}

void
intrinsics_ut::test_ia32_efer_lme()
{
    msrs::ia32_efer::lme::set(true);
    this->expect_true(msrs::ia32_efer::lme::get());

    msrs::ia32_efer::lme::set(false);
    this->expect_false(msrs::ia32_efer::lme::get());
}

void
intrinsics_ut::test_ia32_efer_lma()
{
    msrs::ia32_efer::lma::set(true);
    this->expect_true(msrs::ia32_efer::lma::get());

    msrs::ia32_efer::lma::set(false);
    this->expect_false(msrs::ia32_efer::lma::get());
}

void
intrinsics_ut::test_ia32_efer_nxe()
{
    msrs::ia32_efer::nxe::set(true);
    this->expect_true(msrs::ia32_efer::nxe::get());

    msrs::ia32_efer::nxe::set(false);
    this->expect_false(msrs::ia32_efer::nxe::get());
}

void
intrinsics_ut::test_ia32_efer_reserved()
{
    msrs::ia32_efer::reserved::set(0x10000UL);
    this->expect_true(msrs::ia32_efer::reserved::get() == 0x10000UL);
}

void
intrinsics_ut::test_ia32_fs_base()
{
    msrs::ia32_fs_base::set(0xFFFFFFFFFFFFFFFFUL);
    this->expect_true(msrs::ia32_fs_base::get() == 0xFFFFFFFFFFFFFFFFUL);

    msrs::ia32_fs_base::set(0x0U);
    this->expect_true(msrs::ia32_fs_base::get() == 0x0U);
}

void
intrinsics_ut::test_ia32_gs_base()
{
    msrs::ia32_gs_base::set(0xFFFFFFFFFFFFFFFFUL);
    this->expect_true(msrs::ia32_gs_base::get() == 0xFFFFFFFFFFFFFFFFUL);

    msrs::ia32_gs_base::set(0x0U);
    this->expect_true(msrs::ia32_gs_base::get() == 0x0U);
}
