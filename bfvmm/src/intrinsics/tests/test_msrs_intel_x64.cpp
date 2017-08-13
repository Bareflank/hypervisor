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

#include <catch/catch.hpp>
#include <intrinsics/x86/intel_x64.h>
#include <hippomocks.h>

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

using namespace x64;

std::map<msrs::field_type, msrs::value_type> g_msrs;

extern "C" uint64_t
test_read_msr(uint32_t addr) noexcept
{ return g_msrs[addr]; }

extern "C" void
test_write_msr(uint32_t addr, uint64_t val) noexcept
{ g_msrs[addr] = val; }

static void
setup_intrinsics(MockRepository &mocks)
{
    mocks.OnCallFunc(_read_msr).Do(test_read_msr);
    mocks.OnCallFunc(_write_msr).Do(test_write_msr);
}

TEST_CASE("general_msr_access")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::set(0x1UL, 100UL);
    CHECK(intel_x64::msrs::get(gsl::narrow_cast<uint32_t>(0x1UL)) == 100UL);
}

TEST_CASE("ia32_monitor_filter_size")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000006UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_monitor_filter_size::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_platform_id")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000017UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_platform_id::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_platform_id_platform_id")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000017UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_platform_id::platform_id::get() == 0x0000000000000007ULL);
}

TEST_CASE("ia32_feature_control")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_feature_control::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_feature_control::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_feature_control_lock_bit")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_feature_control::lock_bit::set(true);
    CHECK(intel_x64::msrs::ia32_feature_control::lock_bit::get());

    intel_x64::msrs::ia32_feature_control::lock_bit::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_feature_control::lock_bit::get());
}

TEST_CASE("ia32_feature_control_enable_vmx_inside_smx")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_feature_control::enable_vmx_inside_smx::set(true);
    CHECK(intel_x64::msrs::ia32_feature_control::enable_vmx_inside_smx::get());

    intel_x64::msrs::ia32_feature_control::enable_vmx_inside_smx::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_feature_control::enable_vmx_inside_smx::get());
}

TEST_CASE("ia32_feature_control_enable_vmx_outside_smx")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_feature_control::enable_vmx_outside_smx::set(true);
    CHECK(intel_x64::msrs::ia32_feature_control::enable_vmx_outside_smx::get());

    intel_x64::msrs::ia32_feature_control::enable_vmx_outside_smx::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_feature_control::enable_vmx_outside_smx::get());
}

TEST_CASE("ia32_feature_control_senter_local_function_enable")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_feature_control::senter_local_function_enable::set(true);
    CHECK(intel_x64::msrs::ia32_feature_control::senter_local_function_enable::get());

    intel_x64::msrs::ia32_feature_control::senter_local_function_enable::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_feature_control::senter_local_function_enable::get());
}

TEST_CASE("ia32_feature_control_senter_global_function_enables")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_feature_control::senter_global_function_enables::set(true);
    CHECK(intel_x64::msrs::ia32_feature_control::senter_global_function_enables::get());

    intel_x64::msrs::ia32_feature_control::senter_global_function_enables::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_feature_control::senter_global_function_enables::get());
}

TEST_CASE("ia32_feature_control_sgx_launch_control_enable")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_feature_control::sgx_launch_control_enable::set(true);
    CHECK(intel_x64::msrs::ia32_feature_control::sgx_launch_control_enable::get());

    intel_x64::msrs::ia32_feature_control::sgx_launch_control_enable::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_feature_control::sgx_launch_control_enable::get());
}

TEST_CASE("ia32_feature_control_sgx_global_enable")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_feature_control::sgx_global_enable::set(true);
    CHECK(intel_x64::msrs::ia32_feature_control::sgx_global_enable::get());

    intel_x64::msrs::ia32_feature_control::sgx_global_enable::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_feature_control::sgx_global_enable::get());
}

TEST_CASE("ia32_feature_control_lmce")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_feature_control::lmce::set(true);
    CHECK(intel_x64::msrs::ia32_feature_control::lmce::get());

    intel_x64::msrs::ia32_feature_control::lmce::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_feature_control::lmce::get());
}

TEST_CASE("ia32_tsc_adjust")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_tsc_adjust::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_tsc_adjust::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_tsc_adjust_thread_adjust")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_tsc_adjust::thread_adjust::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_tsc_adjust::thread_adjust::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_bios_updt_trig")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_bios_updt_trig::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(g_msrs[0x00000079UL] == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_bios_sign_id")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000008BUL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_bios_sign_id::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_bios_sign_id_bios_sign_id")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_bios_sign_id::bios_sign_id::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_bios_sign_id::bios_sign_id::get() == 0x00000000FFFFFFFFULL);
}

TEST_CASE("ia32_sgxlepubkeyhash0")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_sgxlepubkeyhash0::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_sgxlepubkeyhash0::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_sgxlepubkeyhash1")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_sgxlepubkeyhash1::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_sgxlepubkeyhash1::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_sgxlepubkeyhash2")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_sgxlepubkeyhash2::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_sgxlepubkeyhash2::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_sgxlepubkeyhash3")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_sgxlepubkeyhash3::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_sgxlepubkeyhash3::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_smm_monitor_ctl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_smm_monitor_ctl::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_smm_monitor_ctl::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_smm_monitor_ctl_valid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_smm_monitor_ctl::valid::set(true);
    CHECK(intel_x64::msrs::ia32_smm_monitor_ctl::valid::get());

    intel_x64::msrs::ia32_smm_monitor_ctl::valid::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_smm_monitor_ctl::valid::get());
}

TEST_CASE("ia32_smm_monitor_ctl_vmxoff")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_smm_monitor_ctl::vmxoff::set(true);
    CHECK(intel_x64::msrs::ia32_smm_monitor_ctl::vmxoff::get());

    intel_x64::msrs::ia32_smm_monitor_ctl::vmxoff::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_smm_monitor_ctl::vmxoff::get());
}

TEST_CASE("ia32_smm_monitor_ctl_mseg_base")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_smm_monitor_ctl::mseg_base::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_smm_monitor_ctl::mseg_base::get() == 0x00000000000FFFFFULL);
}

TEST_CASE("ia32_smbase")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000009EUL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_smbase::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_pmc0")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_pmc0::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_pmc0::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_pmc1")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_pmc1::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_pmc1::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_pmc2")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_pmc2::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_pmc2::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_pmc3")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_pmc3::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_pmc3::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_pmc4")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_pmc4::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_pmc4::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_pmc5")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_pmc5::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_pmc5::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_pmc6")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_pmc6::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_pmc6::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_pmc7")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_pmc7::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_pmc7::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_sysenter_cs")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_sysenter_cs::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_sysenter_cs::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_sysenter_esp")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_sysenter_esp::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_sysenter_esp::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_sysenter_eip")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_sysenter_eip::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_sysenter_eip::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_perfevtsel0")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_perfevtsel0::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_perfevtsel0::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_perfevtsel0_event_select")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_perfevtsel0::event_select::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_perfevtsel0::event_select::get() == 0x00000000000000FFULL);
}

TEST_CASE("ia32_perfevtsel0_umask")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_perfevtsel0::umask::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_perfevtsel0::umask::get() == 0x00000000000000FFULL);
}

TEST_CASE("ia32_perfevtsel0_usr")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_perfevtsel0::usr::set(true);
    CHECK(intel_x64::msrs::ia32_perfevtsel0::usr::get());

    intel_x64::msrs::ia32_perfevtsel0::usr::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_perfevtsel0::usr::get());
}

TEST_CASE("ia32_perfevtsel0_os")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_perfevtsel0::os::set(true);
    CHECK(intel_x64::msrs::ia32_perfevtsel0::os::get());

    intel_x64::msrs::ia32_perfevtsel0::os::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_perfevtsel0::os::get());
}

TEST_CASE("ia32_perfevtsel0_edge")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_perfevtsel0::edge::set(true);
    CHECK(intel_x64::msrs::ia32_perfevtsel0::edge::get());

    intel_x64::msrs::ia32_perfevtsel0::edge::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_perfevtsel0::edge::get());
}

TEST_CASE("ia32_perfevtsel0_pc")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_perfevtsel0::pc::set(true);
    CHECK(intel_x64::msrs::ia32_perfevtsel0::pc::get());

    intel_x64::msrs::ia32_perfevtsel0::pc::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_perfevtsel0::pc::get());
}

TEST_CASE("ia32_perfevtsel0_interrupt")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_perfevtsel0::interrupt::set(true);
    CHECK(intel_x64::msrs::ia32_perfevtsel0::interrupt::get());

    intel_x64::msrs::ia32_perfevtsel0::interrupt::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_perfevtsel0::interrupt::get());
}

TEST_CASE("ia32_perfevtsel0_anythread")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_perfevtsel0::anythread::set(true);
    CHECK(intel_x64::msrs::ia32_perfevtsel0::anythread::get());

    intel_x64::msrs::ia32_perfevtsel0::anythread::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_perfevtsel0::anythread::get());
}

TEST_CASE("ia32_perfevtsel0_en")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_perfevtsel0::en::set(true);
    CHECK(intel_x64::msrs::ia32_perfevtsel0::en::get());

    intel_x64::msrs::ia32_perfevtsel0::en::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_perfevtsel0::en::get());
}

TEST_CASE("ia32_perfevtsel0_inv")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_perfevtsel0::inv::set(true);
    CHECK(intel_x64::msrs::ia32_perfevtsel0::inv::get());

    intel_x64::msrs::ia32_perfevtsel0::inv::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_perfevtsel0::inv::get());
}

TEST_CASE("ia32_perfevtsel0_cmask")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_perfevtsel0::cmask::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_perfevtsel0::cmask::get() == 0x00000000000000FFULL);
}

TEST_CASE("ia32_perfevtsel1")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_perfevtsel1::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_perfevtsel1::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_perfevtsel2")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_perfevtsel2::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_perfevtsel2::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_perfevtsel3")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_perfevtsel3::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_perfevtsel3::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_perf_status")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000198UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_perf_status::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_perf_status_state_value")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000198UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_perf_status::state_value::get() == 0x000000000000FFFFULL);
}

TEST_CASE("ia32_perf_ctl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_perf_ctl::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_perf_ctl::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_perf_ctl_state_value")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_perf_ctl::state_value::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_perf_ctl::state_value::get() == 0x000000000000FFFFULL);
}

TEST_CASE("ia32_perf_ctl_ida_engage")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_perf_ctl::ida_engage::set(true);
    CHECK(intel_x64::msrs::ia32_perf_ctl::ida_engage::get());

    intel_x64::msrs::ia32_perf_ctl::ida_engage::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_perf_ctl::ida_engage::get());
}

TEST_CASE("ia32_clock_modulation")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_clock_modulation::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_clock_modulation::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_clock_modulation_ext_duty_cycle")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_clock_modulation::ext_duty_cycle::set(true);
    CHECK(intel_x64::msrs::ia32_clock_modulation::ext_duty_cycle::get());

    intel_x64::msrs::ia32_clock_modulation::ext_duty_cycle::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_clock_modulation::ext_duty_cycle::get());
}

TEST_CASE("ia32_clock_modulation_duty_cycle_values")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_clock_modulation::duty_cycle_values::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_clock_modulation::duty_cycle_values::get() == 0x0000000000000007ULL);
}

TEST_CASE("ia32_clock_modulation_enable_modulation")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_clock_modulation::enable_modulation::set(true);
    CHECK(intel_x64::msrs::ia32_clock_modulation::enable_modulation::get());

    intel_x64::msrs::ia32_clock_modulation::enable_modulation::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_clock_modulation::enable_modulation::get());
}

TEST_CASE("ia32_therm_interrupt")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_therm_interrupt::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_therm_interrupt::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_therm_interrupt_high_temp")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_therm_interrupt::high_temp::set(true);
    CHECK(intel_x64::msrs::ia32_therm_interrupt::high_temp::get());

    intel_x64::msrs::ia32_therm_interrupt::high_temp::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_therm_interrupt::high_temp::get());
}

TEST_CASE("ia32_therm_interrupt_low_temp")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_therm_interrupt::low_temp::set(true);
    CHECK(intel_x64::msrs::ia32_therm_interrupt::low_temp::get());

    intel_x64::msrs::ia32_therm_interrupt::low_temp::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_therm_interrupt::low_temp::get());
}

TEST_CASE("ia32_therm_interrupt_prochot")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_therm_interrupt::prochot::set(true);
    CHECK(intel_x64::msrs::ia32_therm_interrupt::prochot::get());

    intel_x64::msrs::ia32_therm_interrupt::prochot::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_therm_interrupt::prochot::get());
}

TEST_CASE("ia32_therm_interrupt_forcepr")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_therm_interrupt::forcepr::set(true);
    CHECK(intel_x64::msrs::ia32_therm_interrupt::forcepr::get());

    intel_x64::msrs::ia32_therm_interrupt::forcepr::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_therm_interrupt::forcepr::get());
}

TEST_CASE("ia32_therm_interrupt_crit_temp")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_therm_interrupt::crit_temp::set(true);
    CHECK(intel_x64::msrs::ia32_therm_interrupt::crit_temp::get());

    intel_x64::msrs::ia32_therm_interrupt::crit_temp::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_therm_interrupt::crit_temp::get());
}

TEST_CASE("ia32_therm_interrupt_threshold_1_enable")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_therm_interrupt::threshold_1_enable::set(true);
    CHECK(intel_x64::msrs::ia32_therm_interrupt::threshold_1_enable::get());

    intel_x64::msrs::ia32_therm_interrupt::threshold_1_enable::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_therm_interrupt::threshold_1_enable::get());
}

TEST_CASE("ia32_therm_interrupt_threshold_1_value")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_therm_interrupt::threshold_1_value::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_therm_interrupt::threshold_1_value::get() == 0x000000000000007FULL);
}

TEST_CASE("ia32_therm_interrupt_threshold_2_enable")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_therm_interrupt::threshold_2_enable::set(true);
    CHECK(intel_x64::msrs::ia32_therm_interrupt::threshold_2_enable::get());

    intel_x64::msrs::ia32_therm_interrupt::threshold_2_enable::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_therm_interrupt::threshold_2_enable::get());
}

TEST_CASE("ia32_therm_interrupt_threshold_2_value")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_therm_interrupt::threshold_2_value::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_therm_interrupt::threshold_2_value::get() == 0x000000000000007FULL);
}

TEST_CASE("ia32_therm_interrupt_power_limit")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_therm_interrupt::power_limit::set(true);
    CHECK(intel_x64::msrs::ia32_therm_interrupt::power_limit::get());

    intel_x64::msrs::ia32_therm_interrupt::power_limit::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_therm_interrupt::power_limit::get());
}

TEST_CASE("ia32_therm_status")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000019CUL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_therm_status::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_therm_status_therm_status")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000019CUL] = 0x0000000000000001ULL;
    CHECK(intel_x64::msrs::ia32_therm_status::therm_status::get());

    g_msrs[0x0000019CUL] = 0x0000000000000000ULL;
    CHECK_FALSE(intel_x64::msrs::ia32_therm_status::therm_status::get());
}

TEST_CASE("ia32_therm_status_thermal_status_log")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_therm_status::thermal_status_log::set(true);
    CHECK(intel_x64::msrs::ia32_therm_status::thermal_status_log::get());

    intel_x64::msrs::ia32_therm_status::thermal_status_log::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_therm_status::thermal_status_log::get());
}

TEST_CASE("ia32_therm_status_forcepr_event")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000019CUL] = 0x0000000000000004ULL;
    CHECK(intel_x64::msrs::ia32_therm_status::forcepr_event::get());

    g_msrs[0x0000019CUL] = 0x0000000000000000ULL;
    CHECK_FALSE(intel_x64::msrs::ia32_therm_status::forcepr_event::get());
}

TEST_CASE("ia32_therm_status_forcepr_log")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_therm_status::forcepr_log::set(true);
    CHECK(intel_x64::msrs::ia32_therm_status::forcepr_log::get());

    intel_x64::msrs::ia32_therm_status::forcepr_log::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_therm_status::forcepr_log::get());
}

TEST_CASE("ia32_therm_status_crit_temp_status")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000019CUL] = 0x0000000000000010ULL;
    CHECK(intel_x64::msrs::ia32_therm_status::crit_temp_status::get());

    g_msrs[0x0000019CUL] = 0x0000000000000000ULL;
    CHECK_FALSE(intel_x64::msrs::ia32_therm_status::crit_temp_status::get());
}

TEST_CASE("ia32_therm_status_crit_temp_log")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_therm_status::crit_temp_log::set(true);
    CHECK(intel_x64::msrs::ia32_therm_status::crit_temp_log::get());

    intel_x64::msrs::ia32_therm_status::crit_temp_log::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_therm_status::crit_temp_log::get());
}

TEST_CASE("ia32_therm_status_therm_threshold1_status")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000019CUL] = 0x0000000000000040ULL;
    CHECK(intel_x64::msrs::ia32_therm_status::therm_threshold1_status::get());

    g_msrs[0x0000019CUL] = 0x0000000000000000ULL;
    CHECK_FALSE(intel_x64::msrs::ia32_therm_status::therm_threshold1_status::get());
}

TEST_CASE("ia32_therm_status_therm_threshold1_log")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_therm_status::therm_threshold1_log::set(true);
    CHECK(intel_x64::msrs::ia32_therm_status::therm_threshold1_log::get());

    intel_x64::msrs::ia32_therm_status::therm_threshold1_log::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_therm_status::therm_threshold1_log::get());
}

TEST_CASE("ia32_therm_status_therm_threshold2_status")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000019CUL] = 0x0000000000000100ULL;
    CHECK(intel_x64::msrs::ia32_therm_status::therm_threshold2_status::get());

    g_msrs[0x0000019CUL] = 0x0000000000000000ULL;
    CHECK_FALSE(intel_x64::msrs::ia32_therm_status::therm_threshold2_status::get());
}

TEST_CASE("ia32_therm_status_therm_threshold2_log")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_therm_status::therm_threshold2_log::set(true);
    CHECK(intel_x64::msrs::ia32_therm_status::therm_threshold2_log::get());

    intel_x64::msrs::ia32_therm_status::therm_threshold2_log::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_therm_status::therm_threshold2_log::get());
}

TEST_CASE("ia32_therm_status_power_limit_status")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000019CUL] = 0x0000000000000400ULL;
    CHECK(intel_x64::msrs::ia32_therm_status::power_limit_status::get());

    g_msrs[0x0000019CUL] = 0x0000000000000000ULL;
    CHECK_FALSE(intel_x64::msrs::ia32_therm_status::power_limit_status::get());
}

TEST_CASE("ia32_therm_status_power_limit_log")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_therm_status::power_limit_log::set(true);
    CHECK(intel_x64::msrs::ia32_therm_status::power_limit_log::get());

    intel_x64::msrs::ia32_therm_status::power_limit_log::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_therm_status::power_limit_log::get());
}

TEST_CASE("ia32_therm_status_current_limit_status")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000019CUL] = 0x0000000000001000ULL;
    CHECK(intel_x64::msrs::ia32_therm_status::current_limit_status::get());

    g_msrs[0x0000019CUL] = 0x0000000000000000ULL;
    CHECK_FALSE(intel_x64::msrs::ia32_therm_status::current_limit_status::get());
}

TEST_CASE("ia32_therm_status_current_limit_log")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_therm_status::current_limit_log::set(true);
    CHECK(intel_x64::msrs::ia32_therm_status::current_limit_log::get());

    intel_x64::msrs::ia32_therm_status::current_limit_log::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_therm_status::current_limit_log::get());
}

TEST_CASE("ia32_therm_status_cross_domain_status")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000019CUL] = 0x0000000000004000ULL;
    CHECK(intel_x64::msrs::ia32_therm_status::cross_domain_status::get());

    g_msrs[0x0000019CUL] = 0x0000000000000000ULL;
    CHECK_FALSE(intel_x64::msrs::ia32_therm_status::cross_domain_status::get());
}

TEST_CASE("ia32_therm_status_cross_domain_log")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_therm_status::cross_domain_log::set(true);
    CHECK(intel_x64::msrs::ia32_therm_status::cross_domain_log::get());

    intel_x64::msrs::ia32_therm_status::cross_domain_log::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_therm_status::cross_domain_log::get());
}

TEST_CASE("ia32_therm_status_digital_readout")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000019CUL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_therm_status::digital_readout::get() == 0x000000000000007FULL);
}

TEST_CASE("ia32_therm_status_resolution_celcius")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000019CUL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_therm_status::resolution_celcius::get() == 0x000000000000000FULL);
}

TEST_CASE("ia32_therm_status_reading_valid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000019CUL] = 0x0000000080000000ULL;
    CHECK(intel_x64::msrs::ia32_therm_status::reading_valid::get());

    g_msrs[0x0000019CUL] = 0x0000000000000000ULL;
    CHECK_FALSE(intel_x64::msrs::ia32_therm_status::reading_valid::get());
}

TEST_CASE("ia32_misc_enable")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_misc_enable::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_misc_enable::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_misc_enable_fast_strings")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_misc_enable::fast_strings::set(true);
    CHECK(intel_x64::msrs::ia32_misc_enable::fast_strings::get());

    intel_x64::msrs::ia32_misc_enable::fast_strings::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_misc_enable::fast_strings::get());
}

TEST_CASE("ia32_misc_enable_auto_therm_control")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_misc_enable::auto_therm_control::set(true);
    CHECK(intel_x64::msrs::ia32_misc_enable::auto_therm_control::get());

    intel_x64::msrs::ia32_misc_enable::auto_therm_control::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_misc_enable::auto_therm_control::get());
}

TEST_CASE("ia32_misc_enable_perf_monitor")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x000001A0UL] = 0x0000000000000080ULL;
    CHECK(intel_x64::msrs::ia32_misc_enable::perf_monitor::get());

    g_msrs[0x000001A0UL] = 0x0000000000000000ULL;
    CHECK_FALSE(intel_x64::msrs::ia32_misc_enable::perf_monitor::get());
}

TEST_CASE("ia32_misc_enable_branch_trace_storage")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x000001A0UL] = 0x0000000000000800ULL;
    CHECK(intel_x64::msrs::ia32_misc_enable::branch_trace_storage::get());

    g_msrs[0x000001A0UL] = 0x0000000000000000ULL;
    CHECK_FALSE(intel_x64::msrs::ia32_misc_enable::branch_trace_storage::get());
}

TEST_CASE("ia32_misc_enable_processor_sampling")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x000001A0UL] = 0x0000000000001000ULL;
    CHECK(intel_x64::msrs::ia32_misc_enable::processor_sampling::get());

    g_msrs[0x000001A0UL] = 0x0000000000000000ULL;
    CHECK_FALSE(intel_x64::msrs::ia32_misc_enable::processor_sampling::get());
}

TEST_CASE("ia32_misc_enable_intel_speedstep")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_misc_enable::intel_speedstep::set(true);
    CHECK(intel_x64::msrs::ia32_misc_enable::intel_speedstep::get());

    intel_x64::msrs::ia32_misc_enable::intel_speedstep::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_misc_enable::intel_speedstep::get());
}

TEST_CASE("ia32_misc_enable_monitor_fsm")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_misc_enable::monitor_fsm::set(true);
    CHECK(intel_x64::msrs::ia32_misc_enable::monitor_fsm::get());

    intel_x64::msrs::ia32_misc_enable::monitor_fsm::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_misc_enable::monitor_fsm::get());
}

TEST_CASE("ia32_misc_enable_limit_cpuid_maxval")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_misc_enable::limit_cpuid_maxval::set(true);
    CHECK(intel_x64::msrs::ia32_misc_enable::limit_cpuid_maxval::get());

    intel_x64::msrs::ia32_misc_enable::limit_cpuid_maxval::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_misc_enable::limit_cpuid_maxval::get());
}

TEST_CASE("ia32_misc_enable_xtpr_message")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_misc_enable::xtpr_message::set(true);
    CHECK(intel_x64::msrs::ia32_misc_enable::xtpr_message::get());

    intel_x64::msrs::ia32_misc_enable::xtpr_message::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_misc_enable::xtpr_message::get());
}

TEST_CASE("ia32_misc_enable_xd_bit")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_misc_enable::xd_bit::set(true);
    CHECK(intel_x64::msrs::ia32_misc_enable::xd_bit::get());

    intel_x64::msrs::ia32_misc_enable::xd_bit::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_misc_enable::xd_bit::get());
}

TEST_CASE("ia32_energy_perf_bias")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_energy_perf_bias::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_energy_perf_bias::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_energy_perf_bias_power_policy")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_energy_perf_bias::power_policy::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_energy_perf_bias::power_policy::get() == 0x000000000000000FULL);
}

TEST_CASE("ia32_package_therm_status")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x000001B1UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_package_therm_status::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_package_therm_status_pkg_therm_status")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x000001B1UL] = 0x0000000000000001ULL;
    CHECK(intel_x64::msrs::ia32_package_therm_status::pkg_therm_status::get());

    g_msrs[0x000001B1UL] = 0x0000000000000000ULL;
    CHECK_FALSE(intel_x64::msrs::ia32_package_therm_status::pkg_therm_status::get());
}

TEST_CASE("ia32_package_therm_status_pkg_therm_log")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_package_therm_status::pkg_therm_log::set(true);
    CHECK(intel_x64::msrs::ia32_package_therm_status::pkg_therm_log::get());

    intel_x64::msrs::ia32_package_therm_status::pkg_therm_log::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_package_therm_status::pkg_therm_log::get());
}

TEST_CASE("ia32_package_therm_status_pkg_prochot_event")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x000001B1UL] = 0x0000000000000004ULL;
    CHECK(intel_x64::msrs::ia32_package_therm_status::pkg_prochot_event::get());

    g_msrs[0x000001B1UL] = 0x0000000000000000ULL;
    CHECK_FALSE(intel_x64::msrs::ia32_package_therm_status::pkg_prochot_event::get());
}

TEST_CASE("ia32_package_therm_status_pkg_prochot_log")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_package_therm_status::pkg_prochot_log::set(true);
    CHECK(intel_x64::msrs::ia32_package_therm_status::pkg_prochot_log::get());

    intel_x64::msrs::ia32_package_therm_status::pkg_prochot_log::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_package_therm_status::pkg_prochot_log::get());
}

TEST_CASE("ia32_package_therm_status_pkg_crit_temp_status")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x000001B1UL] = 0x0000000000000010ULL;
    CHECK(intel_x64::msrs::ia32_package_therm_status::pkg_crit_temp_status::get());

    g_msrs[0x000001B1UL] = 0x0000000000000000ULL;
    CHECK_FALSE(intel_x64::msrs::ia32_package_therm_status::pkg_crit_temp_status::get());
}

TEST_CASE("ia32_package_therm_status_pkg_crit_temp_log")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_package_therm_status::pkg_crit_temp_log::set(true);
    CHECK(intel_x64::msrs::ia32_package_therm_status::pkg_crit_temp_log::get());

    intel_x64::msrs::ia32_package_therm_status::pkg_crit_temp_log::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_package_therm_status::pkg_crit_temp_log::get());
}

TEST_CASE("ia32_package_therm_status_pkg_therm_thresh1_status")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x000001B1UL] = 0x0000000000000040ULL;
    CHECK(intel_x64::msrs::ia32_package_therm_status::pkg_therm_thresh1_status::get());

    g_msrs[0x000001B1UL] = 0x0000000000000000ULL;
    CHECK_FALSE(intel_x64::msrs::ia32_package_therm_status::pkg_therm_thresh1_status::get());
}

TEST_CASE("ia32_package_therm_status_pkg_therm_thresh1_log")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_package_therm_status::pkg_therm_thresh1_log::set(true);
    CHECK(intel_x64::msrs::ia32_package_therm_status::pkg_therm_thresh1_log::get());

    intel_x64::msrs::ia32_package_therm_status::pkg_therm_thresh1_log::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_package_therm_status::pkg_therm_thresh1_log::get());
}

TEST_CASE("ia32_package_therm_status_pkg_therm_thresh2_status")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x000001B1UL] = 0x0000000000000100ULL;
    CHECK(intel_x64::msrs::ia32_package_therm_status::pkg_therm_thresh2_status::get());

    g_msrs[0x000001B1UL] = 0x0000000000000000ULL;
    CHECK_FALSE(intel_x64::msrs::ia32_package_therm_status::pkg_therm_thresh2_status::get());
}

TEST_CASE("ia32_package_therm_status_pkg_therm_thresh2_log")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_package_therm_status::pkg_therm_thresh2_log::set(true);
    CHECK(intel_x64::msrs::ia32_package_therm_status::pkg_therm_thresh2_log::get());

    intel_x64::msrs::ia32_package_therm_status::pkg_therm_thresh2_log::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_package_therm_status::pkg_therm_thresh2_log::get());
}

TEST_CASE("ia32_package_therm_status_pkg_power_limit_status")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x000001B1UL] = 0x0000000000000400ULL;
    CHECK(intel_x64::msrs::ia32_package_therm_status::pkg_power_limit_status::get());

    g_msrs[0x000001B1UL] = 0x0000000000000000ULL;
    CHECK_FALSE(intel_x64::msrs::ia32_package_therm_status::pkg_power_limit_status::get());
}

TEST_CASE("ia32_package_therm_status_pkg_power_limit_log")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_package_therm_status::pkg_power_limit_log::set(true);
    CHECK(intel_x64::msrs::ia32_package_therm_status::pkg_power_limit_log::get());

    intel_x64::msrs::ia32_package_therm_status::pkg_power_limit_log::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_package_therm_status::pkg_power_limit_log::get());
}

TEST_CASE("ia32_package_therm_status_pkg_digital_readout")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x000001B1UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_package_therm_status::pkg_digital_readout::get() == 0x000000000000007FULL);
}

TEST_CASE("ia32_package_therm_interrupt")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_package_therm_interrupt::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_package_therm_interrupt::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_package_therm_interrupt_pkg_high_temp")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_package_therm_interrupt::pkg_high_temp::set(true);
    CHECK(intel_x64::msrs::ia32_package_therm_interrupt::pkg_high_temp::get());

    intel_x64::msrs::ia32_package_therm_interrupt::pkg_high_temp::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_package_therm_interrupt::pkg_high_temp::get());
}

TEST_CASE("ia32_package_therm_interrupt_pkg_low_temp")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_package_therm_interrupt::pkg_low_temp::set(true);
    CHECK(intel_x64::msrs::ia32_package_therm_interrupt::pkg_low_temp::get());

    intel_x64::msrs::ia32_package_therm_interrupt::pkg_low_temp::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_package_therm_interrupt::pkg_low_temp::get());
}

TEST_CASE("ia32_package_therm_interrupt_pkg_prochot")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_package_therm_interrupt::pkg_prochot::set(true);
    CHECK(intel_x64::msrs::ia32_package_therm_interrupt::pkg_prochot::get());

    intel_x64::msrs::ia32_package_therm_interrupt::pkg_prochot::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_package_therm_interrupt::pkg_prochot::get());
}

TEST_CASE("ia32_package_therm_interrupt_pkg_overheat")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_package_therm_interrupt::pkg_overheat::set(true);
    CHECK(intel_x64::msrs::ia32_package_therm_interrupt::pkg_overheat::get());

    intel_x64::msrs::ia32_package_therm_interrupt::pkg_overheat::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_package_therm_interrupt::pkg_overheat::get());
}

TEST_CASE("ia32_package_therm_interrupt_pkg_threshold_1_value")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_package_therm_interrupt::pkg_threshold_1_value::set(true);
    CHECK(intel_x64::msrs::ia32_package_therm_interrupt::pkg_threshold_1_value::get());

    intel_x64::msrs::ia32_package_therm_interrupt::pkg_threshold_1_value::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_package_therm_interrupt::pkg_threshold_1_value::get());
}

TEST_CASE("ia32_package_therm_interrupt_pkg_threshold_1_enable")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_package_therm_interrupt::pkg_threshold_1_enable::set(true);
    CHECK(intel_x64::msrs::ia32_package_therm_interrupt::pkg_threshold_1_enable::get());

    intel_x64::msrs::ia32_package_therm_interrupt::pkg_threshold_1_enable::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_package_therm_interrupt::pkg_threshold_1_enable::get());
}

TEST_CASE("ia32_package_therm_interrupt_pkg_threshold_2_value")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_package_therm_interrupt::pkg_threshold_2_value::set(true);
    CHECK(intel_x64::msrs::ia32_package_therm_interrupt::pkg_threshold_2_value::get());

    intel_x64::msrs::ia32_package_therm_interrupt::pkg_threshold_2_value::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_package_therm_interrupt::pkg_threshold_2_value::get());
}

TEST_CASE("ia32_package_therm_interrupt_pkg_threshold_2_enable")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_package_therm_interrupt::pkg_threshold_2_enable::set(true);
    CHECK(intel_x64::msrs::ia32_package_therm_interrupt::pkg_threshold_2_enable::get());

    intel_x64::msrs::ia32_package_therm_interrupt::pkg_threshold_2_enable::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_package_therm_interrupt::pkg_threshold_2_enable::get());
}

TEST_CASE("ia32_package_therm_interrupt_pkg_power_limit")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_package_therm_interrupt::pkg_power_limit::set(true);
    CHECK(intel_x64::msrs::ia32_package_therm_interrupt::pkg_power_limit::get());

    intel_x64::msrs::ia32_package_therm_interrupt::pkg_power_limit::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_package_therm_interrupt::pkg_power_limit::get());
}

TEST_CASE("ia32_debugctl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_debugctl::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_debugctl::get() == 0xFFFFFFFFFFFFFFFFULL);

    intel_x64::msrs::ia32_debugctl::dump();
}

TEST_CASE("ia32_debugctl_lbr")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_debugctl::lbr::set(true);
    CHECK(intel_x64::msrs::ia32_debugctl::lbr::get());

    intel_x64::msrs::ia32_debugctl::lbr::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_debugctl::lbr::get());
}

TEST_CASE("ia32_debugctl_btf")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_debugctl::btf::set(true);
    CHECK(intel_x64::msrs::ia32_debugctl::btf::get());

    intel_x64::msrs::ia32_debugctl::btf::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_debugctl::btf::get());
}

TEST_CASE("ia32_debugctl_tr")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_debugctl::tr::set(true);
    CHECK(intel_x64::msrs::ia32_debugctl::tr::get());

    intel_x64::msrs::ia32_debugctl::tr::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_debugctl::tr::get());
}

TEST_CASE("ia32_debugctl_bts")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_debugctl::bts::set(true);
    CHECK(intel_x64::msrs::ia32_debugctl::bts::get());

    intel_x64::msrs::ia32_debugctl::bts::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_debugctl::bts::get());
}

TEST_CASE("ia32_debugctl_btint")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_debugctl::btint::set(true);
    CHECK(intel_x64::msrs::ia32_debugctl::btint::get());

    intel_x64::msrs::ia32_debugctl::btint::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_debugctl::btint::get());
}

TEST_CASE("ia32_debugctl_bt_off_os")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_debugctl::bt_off_os::set(true);
    CHECK(intel_x64::msrs::ia32_debugctl::bt_off_os::get());

    intel_x64::msrs::ia32_debugctl::bt_off_os::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_debugctl::bt_off_os::get());
}

TEST_CASE("ia32_debugctl_bt_off_user")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_debugctl::bt_off_user::set(true);
    CHECK(intel_x64::msrs::ia32_debugctl::bt_off_user::get());

    intel_x64::msrs::ia32_debugctl::bt_off_user::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_debugctl::bt_off_user::get());
}

TEST_CASE("ia32_debugctl_freeze_lbrs_on_pmi")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_debugctl::freeze_lbrs_on_pmi::set(true);
    CHECK(intel_x64::msrs::ia32_debugctl::freeze_lbrs_on_pmi::get());

    intel_x64::msrs::ia32_debugctl::freeze_lbrs_on_pmi::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_debugctl::freeze_lbrs_on_pmi::get());
}

TEST_CASE("ia32_debugctl_freeze_perfmon_on_pmi")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_debugctl::freeze_perfmon_on_pmi::set(true);
    CHECK(intel_x64::msrs::ia32_debugctl::freeze_perfmon_on_pmi::get());

    intel_x64::msrs::ia32_debugctl::freeze_perfmon_on_pmi::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_debugctl::freeze_perfmon_on_pmi::get());
}

TEST_CASE("ia32_debugctl_enable_uncore_pmi")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_debugctl::enable_uncore_pmi::set(true);
    CHECK(intel_x64::msrs::ia32_debugctl::enable_uncore_pmi::get());

    intel_x64::msrs::ia32_debugctl::enable_uncore_pmi::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_debugctl::enable_uncore_pmi::get());
}

TEST_CASE("ia32_debugctl_freeze_while_smm")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_debugctl::freeze_while_smm::set(true);
    CHECK(intel_x64::msrs::ia32_debugctl::freeze_while_smm::get());

    intel_x64::msrs::ia32_debugctl::freeze_while_smm::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_debugctl::freeze_while_smm::get());
}

TEST_CASE("ia32_debugctl_rtm_debug")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_debugctl::rtm_debug::set(true);
    CHECK(intel_x64::msrs::ia32_debugctl::rtm_debug::get());

    intel_x64::msrs::ia32_debugctl::rtm_debug::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_debugctl::rtm_debug::get());
}

TEST_CASE("ia32_debugctl_reserved")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_debugctl::reserved::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_debugctl::reserved::get() == 0xFFFFFFFFFFFF003CULL);
}

TEST_CASE("ia32_smrr_physbase")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_smrr_physbase::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_smrr_physbase::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_smrr_physbase_type")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_smrr_physbase::type::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_smrr_physbase::type::get() == 0x00000000000000FFULL);
}

TEST_CASE("ia32_smrr_physbase_physbase")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_smrr_physbase::physbase::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_smrr_physbase::physbase::get() == 0x00000000000FFFFFULL);
}

TEST_CASE("ia32_smrr_physmask")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_smrr_physmask::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_smrr_physmask::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_smrr_physmask_valid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_smrr_physmask::valid::set(true);
    CHECK(intel_x64::msrs::ia32_smrr_physmask::valid::get());

    intel_x64::msrs::ia32_smrr_physmask::valid::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_smrr_physmask::valid::get());
}

TEST_CASE("ia32_smrr_physmask_physmask")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_smrr_physmask::physmask::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_smrr_physmask::physmask::get() == 0x00000000000FFFFFULL);
}

TEST_CASE("ia32_platform_dca_cap")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x000001F8UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_platform_dca_cap::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_cpu_dca_cap")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_cpu_dca_cap::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_cpu_dca_cap::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_dca_0_cap")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_dca_0_cap::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_dca_0_cap::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_dca_0_cap_dca_active")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_dca_0_cap::dca_active::set(true);
    CHECK(intel_x64::msrs::ia32_dca_0_cap::dca_active::get());

    intel_x64::msrs::ia32_dca_0_cap::dca_active::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_dca_0_cap::dca_active::get());
}

TEST_CASE("ia32_dca_0_cap_transaction")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_dca_0_cap::transaction::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_dca_0_cap::transaction::get() == 0x0000000000000003ULL);
}

TEST_CASE("ia32_dca_0_cap_dca_type")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_dca_0_cap::dca_type::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_dca_0_cap::dca_type::get() == 0x000000000000000FULL);
}

TEST_CASE("ia32_dca_0_cap_dca_queue_size")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_dca_0_cap::dca_queue_size::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_dca_0_cap::dca_queue_size::get() == 0x000000000000000FULL);
}

TEST_CASE("ia32_dca_0_cap_dca_delay")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_dca_0_cap::dca_delay::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_dca_0_cap::dca_delay::get() == 0x000000000000000FULL);
}

TEST_CASE("ia32_dca_0_cap_sw_block")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_dca_0_cap::sw_block::set(true);
    CHECK(intel_x64::msrs::ia32_dca_0_cap::sw_block::get());

    intel_x64::msrs::ia32_dca_0_cap::sw_block::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_dca_0_cap::sw_block::get());
}

TEST_CASE("ia32_dca_0_cap_hw_block")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_dca_0_cap::hw_block::set(true);
    CHECK(intel_x64::msrs::ia32_dca_0_cap::hw_block::get());

    intel_x64::msrs::ia32_dca_0_cap::hw_block::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_dca_0_cap::hw_block::get());
}

TEST_CASE("ia32_mtrr_physbase0")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000200UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mtrr_physbase0::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mtrr_physmask0")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000201UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mtrr_physmask0::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mtrr_physbase1")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000202UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mtrr_physbase1::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mtrr_physmask1")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000203UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mtrr_physmask1::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mtrr_physbase2")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000204UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mtrr_physbase2::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mtrr_physmask2")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000205UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mtrr_physmask2::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mtrr_physbase3")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000206UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mtrr_physbase3::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mtrr_physmask3")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000207UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mtrr_physmask3::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mtrr_physbase4")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000208UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mtrr_physbase4::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mtrr_physmask4")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000209UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mtrr_physmask4::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mtrr_physbase5")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000020AUL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mtrr_physbase5::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mtrr_physmask5")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000020BUL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mtrr_physmask5::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mtrr_physbase6")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000020CUL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mtrr_physbase6::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mtrr_physmask6")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000020DUL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mtrr_physmask6::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mtrr_physbase7")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000020EUL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mtrr_physbase7::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mtrr_physmask7")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000020FUL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mtrr_physmask7::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mtrr_physbase8")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000210UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mtrr_physbase8::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mtrr_physmask8")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000211UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mtrr_physmask8::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mtrr_physbase9")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000212UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mtrr_physbase9::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mtrr_physmask9")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000213UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mtrr_physmask9::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mtrr_fix64k_00000")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000250UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mtrr_fix64k_00000::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mtrr_fix16k_80000")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000258UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mtrr_fix16k_80000::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mtrr_fix16k_A0000")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000259UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mtrr_fix16k_A0000::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mtrr_fix4k_C0000")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000268UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mtrr_fix4k_C0000::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mtrr_fix4k_C8000")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000269UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mtrr_fix4k_C8000::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mtrr_fix4k_D0000")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000026AUL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mtrr_fix4k_D0000::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mtrr_fix4k_D8000")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000026BUL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mtrr_fix4k_D8000::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mtrr_fix4k_E0000")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000026CUL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mtrr_fix4k_E0000::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mtrr_fix4k_E8000")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000026DUL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mtrr_fix4k_E8000::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mtrr_fix4k_F0000")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000026EUL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mtrr_fix4k_F0000::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mtrr_fix4k_F8000")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000026FUL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mtrr_fix4k_F8000::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc0_ctl2")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc0_ctl2::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_mc0_ctl2::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc0_ctl2_error_threshold")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc0_ctl2::error_threshold::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_mc0_ctl2::error_threshold::get() == 0x0000000000007FFFULL);
}

TEST_CASE("ia32_mc0_ctl2_cmci_en")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc0_ctl2::cmci_en::set(true);
    CHECK(intel_x64::msrs::ia32_mc0_ctl2::cmci_en::get());

    intel_x64::msrs::ia32_mc0_ctl2::cmci_en::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_mc0_ctl2::cmci_en::get());
}

TEST_CASE("ia32_mc1_ctl2")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc1_ctl2::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_mc1_ctl2::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc1_ctl2_error_threshold")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc1_ctl2::error_threshold::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_mc1_ctl2::error_threshold::get() == 0x0000000000007FFFULL);
}

TEST_CASE("ia32_mc1_ctl2_cmci_en")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc1_ctl2::cmci_en::set(true);
    CHECK(intel_x64::msrs::ia32_mc1_ctl2::cmci_en::get());

    intel_x64::msrs::ia32_mc1_ctl2::cmci_en::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_mc1_ctl2::cmci_en::get());
}

TEST_CASE("ia32_mc2_ctl2")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc2_ctl2::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_mc2_ctl2::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc2_ctl2_error_threshold")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc2_ctl2::error_threshold::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_mc2_ctl2::error_threshold::get() == 0x0000000000007FFFULL);
}

TEST_CASE("ia32_mc2_ctl2_cmci_en")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc2_ctl2::cmci_en::set(true);
    CHECK(intel_x64::msrs::ia32_mc2_ctl2::cmci_en::get());

    intel_x64::msrs::ia32_mc2_ctl2::cmci_en::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_mc2_ctl2::cmci_en::get());
}

TEST_CASE("ia32_mc3_ctl2")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc3_ctl2::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_mc3_ctl2::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc3_ctl2_error_threshold")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc3_ctl2::error_threshold::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_mc3_ctl2::error_threshold::get() == 0x0000000000007FFFULL);
}

TEST_CASE("ia32_mc3_ctl2_cmci_en")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc3_ctl2::cmci_en::set(true);
    CHECK(intel_x64::msrs::ia32_mc3_ctl2::cmci_en::get());

    intel_x64::msrs::ia32_mc3_ctl2::cmci_en::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_mc3_ctl2::cmci_en::get());
}

TEST_CASE("ia32_mc4_ctl2")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc4_ctl2::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_mc4_ctl2::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc4_ctl2_error_threshold")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc4_ctl2::error_threshold::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_mc4_ctl2::error_threshold::get() == 0x0000000000007FFFULL);
}

TEST_CASE("ia32_mc4_ctl2_cmci_en")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc4_ctl2::cmci_en::set(true);
    CHECK(intel_x64::msrs::ia32_mc4_ctl2::cmci_en::get());

    intel_x64::msrs::ia32_mc4_ctl2::cmci_en::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_mc4_ctl2::cmci_en::get());
}

TEST_CASE("ia32_mc5_ctl2")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc5_ctl2::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_mc5_ctl2::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc5_ctl2_error_threshold")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc5_ctl2::error_threshold::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_mc5_ctl2::error_threshold::get() == 0x0000000000007FFFULL);
}

TEST_CASE("ia32_mc5_ctl2_cmci_en")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc5_ctl2::cmci_en::set(true);
    CHECK(intel_x64::msrs::ia32_mc5_ctl2::cmci_en::get());

    intel_x64::msrs::ia32_mc5_ctl2::cmci_en::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_mc5_ctl2::cmci_en::get());
}

TEST_CASE("ia32_mc6_ctl2")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc6_ctl2::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_mc6_ctl2::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc6_ctl2_error_threshold")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc6_ctl2::error_threshold::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_mc6_ctl2::error_threshold::get() == 0x0000000000007FFFULL);
}

TEST_CASE("ia32_mc6_ctl2_cmci_en")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc6_ctl2::cmci_en::set(true);
    CHECK(intel_x64::msrs::ia32_mc6_ctl2::cmci_en::get());

    intel_x64::msrs::ia32_mc6_ctl2::cmci_en::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_mc6_ctl2::cmci_en::get());
}

TEST_CASE("ia32_mc7_ctl2")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc7_ctl2::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_mc7_ctl2::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc7_ctl2_error_threshold")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc7_ctl2::error_threshold::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_mc7_ctl2::error_threshold::get() == 0x0000000000007FFFULL);
}

TEST_CASE("ia32_mc7_ctl2_cmci_en")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc7_ctl2::cmci_en::set(true);
    CHECK(intel_x64::msrs::ia32_mc7_ctl2::cmci_en::get());

    intel_x64::msrs::ia32_mc7_ctl2::cmci_en::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_mc7_ctl2::cmci_en::get());
}

TEST_CASE("ia32_mc8_ctl2")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc8_ctl2::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_mc8_ctl2::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc8_ctl2_error_threshold")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc8_ctl2::error_threshold::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_mc8_ctl2::error_threshold::get() == 0x0000000000007FFFULL);
}

TEST_CASE("ia32_mc8_ctl2_cmci_en")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc8_ctl2::cmci_en::set(true);
    CHECK(intel_x64::msrs::ia32_mc8_ctl2::cmci_en::get());

    intel_x64::msrs::ia32_mc8_ctl2::cmci_en::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_mc8_ctl2::cmci_en::get());
}

TEST_CASE("ia32_mc9_ctl2")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc9_ctl2::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_mc9_ctl2::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc9_ctl2_error_threshold")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc9_ctl2::error_threshold::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_mc9_ctl2::error_threshold::get() == 0x0000000000007FFFULL);
}

TEST_CASE("ia32_mc9_ctl2_cmci_en")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc9_ctl2::cmci_en::set(true);
    CHECK(intel_x64::msrs::ia32_mc9_ctl2::cmci_en::get());

    intel_x64::msrs::ia32_mc9_ctl2::cmci_en::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_mc9_ctl2::cmci_en::get());
}

TEST_CASE("ia32_mc10_ctl2")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc10_ctl2::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_mc10_ctl2::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc10_ctl2_error_threshold")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc10_ctl2::error_threshold::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_mc10_ctl2::error_threshold::get() == 0x0000000000007FFFULL);
}

TEST_CASE("ia32_mc10_ctl2_cmci_en")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc10_ctl2::cmci_en::set(true);
    CHECK(intel_x64::msrs::ia32_mc10_ctl2::cmci_en::get());

    intel_x64::msrs::ia32_mc10_ctl2::cmci_en::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_mc10_ctl2::cmci_en::get());
}

TEST_CASE("ia32_mc11_ctl2")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc11_ctl2::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_mc11_ctl2::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc11_ctl2_error_threshold")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc11_ctl2::error_threshold::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_mc11_ctl2::error_threshold::get() == 0x0000000000007FFFULL);
}

TEST_CASE("ia32_mc11_ctl2_cmci_en")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc11_ctl2::cmci_en::set(true);
    CHECK(intel_x64::msrs::ia32_mc11_ctl2::cmci_en::get());

    intel_x64::msrs::ia32_mc11_ctl2::cmci_en::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_mc11_ctl2::cmci_en::get());
}

TEST_CASE("ia32_mc12_ctl2")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc12_ctl2::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_mc12_ctl2::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc12_ctl2_error_threshold")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc12_ctl2::error_threshold::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_mc12_ctl2::error_threshold::get() == 0x0000000000007FFFULL);
}

TEST_CASE("ia32_mc12_ctl2_cmci_en")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc12_ctl2::cmci_en::set(true);
    CHECK(intel_x64::msrs::ia32_mc12_ctl2::cmci_en::get());

    intel_x64::msrs::ia32_mc12_ctl2::cmci_en::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_mc12_ctl2::cmci_en::get());
}

TEST_CASE("ia32_mc13_ctl2")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc13_ctl2::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_mc13_ctl2::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc13_ctl2_error_threshold")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc13_ctl2::error_threshold::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_mc13_ctl2::error_threshold::get() == 0x0000000000007FFFULL);
}

TEST_CASE("ia32_mc13_ctl2_cmci_en")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc13_ctl2::cmci_en::set(true);
    CHECK(intel_x64::msrs::ia32_mc13_ctl2::cmci_en::get());

    intel_x64::msrs::ia32_mc13_ctl2::cmci_en::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_mc13_ctl2::cmci_en::get());
}

TEST_CASE("ia32_mc14_ctl2")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc14_ctl2::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_mc14_ctl2::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc14_ctl2_error_threshold")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc14_ctl2::error_threshold::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_mc14_ctl2::error_threshold::get() == 0x0000000000007FFFULL);
}

TEST_CASE("ia32_mc14_ctl2_cmci_en")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc14_ctl2::cmci_en::set(true);
    CHECK(intel_x64::msrs::ia32_mc14_ctl2::cmci_en::get());

    intel_x64::msrs::ia32_mc14_ctl2::cmci_en::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_mc14_ctl2::cmci_en::get());
}

TEST_CASE("ia32_mc15_ctl2")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc15_ctl2::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_mc15_ctl2::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc15_ctl2_error_threshold")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc15_ctl2::error_threshold::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_mc15_ctl2::error_threshold::get() == 0x0000000000007FFFULL);
}

TEST_CASE("ia32_mc15_ctl2_cmci_en")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc15_ctl2::cmci_en::set(true);
    CHECK(intel_x64::msrs::ia32_mc15_ctl2::cmci_en::get());

    intel_x64::msrs::ia32_mc15_ctl2::cmci_en::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_mc15_ctl2::cmci_en::get());
}

TEST_CASE("ia32_mc16_ctl2")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc16_ctl2::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_mc16_ctl2::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc16_ctl2_error_threshold")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc16_ctl2::error_threshold::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_mc16_ctl2::error_threshold::get() == 0x0000000000007FFFULL);
}

TEST_CASE("ia32_mc16_ctl2_cmci_en")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc16_ctl2::cmci_en::set(true);
    CHECK(intel_x64::msrs::ia32_mc16_ctl2::cmci_en::get());

    intel_x64::msrs::ia32_mc16_ctl2::cmci_en::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_mc16_ctl2::cmci_en::get());
}

TEST_CASE("ia32_mc17_ctl2")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc17_ctl2::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_mc17_ctl2::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc17_ctl2_error_threshold")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc17_ctl2::error_threshold::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_mc17_ctl2::error_threshold::get() == 0x0000000000007FFFULL);
}

TEST_CASE("ia32_mc17_ctl2_cmci_en")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc17_ctl2::cmci_en::set(true);
    CHECK(intel_x64::msrs::ia32_mc17_ctl2::cmci_en::get());

    intel_x64::msrs::ia32_mc17_ctl2::cmci_en::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_mc17_ctl2::cmci_en::get());
}

TEST_CASE("ia32_mc18_ctl2")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc18_ctl2::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_mc18_ctl2::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc18_ctl2_error_threshold")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc18_ctl2::error_threshold::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_mc18_ctl2::error_threshold::get() == 0x0000000000007FFFULL);
}

TEST_CASE("ia32_mc18_ctl2_cmci_en")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc18_ctl2::cmci_en::set(true);
    CHECK(intel_x64::msrs::ia32_mc18_ctl2::cmci_en::get());

    intel_x64::msrs::ia32_mc18_ctl2::cmci_en::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_mc18_ctl2::cmci_en::get());
}

TEST_CASE("ia32_mc19_ctl2")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc19_ctl2::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_mc19_ctl2::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc19_ctl2_error_threshold")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc19_ctl2::error_threshold::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_mc19_ctl2::error_threshold::get() == 0x0000000000007FFFULL);
}

TEST_CASE("ia32_mc19_ctl2_cmci_en")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc19_ctl2::cmci_en::set(true);
    CHECK(intel_x64::msrs::ia32_mc19_ctl2::cmci_en::get());

    intel_x64::msrs::ia32_mc19_ctl2::cmci_en::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_mc19_ctl2::cmci_en::get());
}

TEST_CASE("ia32_mc20_ctl2")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc20_ctl2::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_mc20_ctl2::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc20_ctl2_error_threshold")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc20_ctl2::error_threshold::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_mc20_ctl2::error_threshold::get() == 0x0000000000007FFFULL);
}

TEST_CASE("ia32_mc20_ctl2_cmci_en")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc20_ctl2::cmci_en::set(true);
    CHECK(intel_x64::msrs::ia32_mc20_ctl2::cmci_en::get());

    intel_x64::msrs::ia32_mc20_ctl2::cmci_en::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_mc20_ctl2::cmci_en::get());
}

TEST_CASE("ia32_mc21_ctl2")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc21_ctl2::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_mc21_ctl2::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc21_ctl2_error_threshold")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc21_ctl2::error_threshold::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_mc21_ctl2::error_threshold::get() == 0x0000000000007FFFULL);
}

TEST_CASE("ia32_mc21_ctl2_cmci_en")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc21_ctl2::cmci_en::set(true);
    CHECK(intel_x64::msrs::ia32_mc21_ctl2::cmci_en::get());

    intel_x64::msrs::ia32_mc21_ctl2::cmci_en::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_mc21_ctl2::cmci_en::get());
}

TEST_CASE("ia32_mc22_ctl2")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc22_ctl2::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_mc22_ctl2::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc22_ctl2_error_threshold")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc22_ctl2::error_threshold::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_mc22_ctl2::error_threshold::get() == 0x0000000000007FFFULL);
}

TEST_CASE("ia32_mc22_ctl2_cmci_en")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc22_ctl2::cmci_en::set(true);
    CHECK(intel_x64::msrs::ia32_mc22_ctl2::cmci_en::get());

    intel_x64::msrs::ia32_mc22_ctl2::cmci_en::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_mc22_ctl2::cmci_en::get());
}

TEST_CASE("ia32_mc23_ctl2")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc23_ctl2::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_mc23_ctl2::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc23_ctl2_error_threshold")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc23_ctl2::error_threshold::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_mc23_ctl2::error_threshold::get() == 0x0000000000007FFFULL);
}

TEST_CASE("ia32_mc23_ctl2_cmci_en")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc23_ctl2::cmci_en::set(true);
    CHECK(intel_x64::msrs::ia32_mc23_ctl2::cmci_en::get());

    intel_x64::msrs::ia32_mc23_ctl2::cmci_en::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_mc23_ctl2::cmci_en::get());
}

TEST_CASE("ia32_mc24_ctl2")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc24_ctl2::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_mc24_ctl2::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc24_ctl2_error_threshold")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc24_ctl2::error_threshold::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_mc24_ctl2::error_threshold::get() == 0x0000000000007FFFULL);
}

TEST_CASE("ia32_mc24_ctl2_cmci_en")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc24_ctl2::cmci_en::set(true);
    CHECK(intel_x64::msrs::ia32_mc24_ctl2::cmci_en::get());

    intel_x64::msrs::ia32_mc24_ctl2::cmci_en::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_mc24_ctl2::cmci_en::get());
}

TEST_CASE("ia32_mc25_ctl2")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc25_ctl2::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_mc25_ctl2::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc25_ctl2_error_threshold")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc25_ctl2::error_threshold::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_mc25_ctl2::error_threshold::get() == 0x0000000000007FFFULL);
}

TEST_CASE("ia32_mc25_ctl2_cmci_en")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc25_ctl2::cmci_en::set(true);
    CHECK(intel_x64::msrs::ia32_mc25_ctl2::cmci_en::get());

    intel_x64::msrs::ia32_mc25_ctl2::cmci_en::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_mc25_ctl2::cmci_en::get());
}

TEST_CASE("ia32_mc26_ctl2")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc26_ctl2::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_mc26_ctl2::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc26_ctl2_error_threshold")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc26_ctl2::error_threshold::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_mc26_ctl2::error_threshold::get() == 0x0000000000007FFFULL);
}

TEST_CASE("ia32_mc26_ctl2_cmci_en")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc26_ctl2::cmci_en::set(true);
    CHECK(intel_x64::msrs::ia32_mc26_ctl2::cmci_en::get());

    intel_x64::msrs::ia32_mc26_ctl2::cmci_en::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_mc26_ctl2::cmci_en::get());
}

TEST_CASE("ia32_mc27_ctl2")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc27_ctl2::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_mc27_ctl2::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc27_ctl2_error_threshold")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc27_ctl2::error_threshold::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_mc27_ctl2::error_threshold::get() == 0x0000000000007FFFULL);
}

TEST_CASE("ia32_mc27_ctl2_cmci_en")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc27_ctl2::cmci_en::set(true);
    CHECK(intel_x64::msrs::ia32_mc27_ctl2::cmci_en::get());

    intel_x64::msrs::ia32_mc27_ctl2::cmci_en::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_mc27_ctl2::cmci_en::get());
}

TEST_CASE("ia32_mc28_ctl2")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc28_ctl2::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_mc28_ctl2::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc28_ctl2_error_threshold")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc28_ctl2::error_threshold::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_mc28_ctl2::error_threshold::get() == 0x0000000000007FFFULL);
}

TEST_CASE("ia32_mc28_ctl2_cmci_en")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc28_ctl2::cmci_en::set(true);
    CHECK(intel_x64::msrs::ia32_mc28_ctl2::cmci_en::get());

    intel_x64::msrs::ia32_mc28_ctl2::cmci_en::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_mc28_ctl2::cmci_en::get());
}

TEST_CASE("ia32_mc29_ctl2")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc29_ctl2::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_mc29_ctl2::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc29_ctl2_error_threshold")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc29_ctl2::error_threshold::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_mc29_ctl2::error_threshold::get() == 0x0000000000007FFFULL);
}

TEST_CASE("ia32_mc29_ctl2_cmci_en")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc29_ctl2::cmci_en::set(true);
    CHECK(intel_x64::msrs::ia32_mc29_ctl2::cmci_en::get());

    intel_x64::msrs::ia32_mc29_ctl2::cmci_en::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_mc29_ctl2::cmci_en::get());
}

TEST_CASE("ia32_mc30_ctl2")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc30_ctl2::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_mc30_ctl2::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc30_ctl2_error_threshold")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc30_ctl2::error_threshold::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_mc30_ctl2::error_threshold::get() == 0x0000000000007FFFULL);
}

TEST_CASE("ia32_mc30_ctl2_cmci_en")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc30_ctl2::cmci_en::set(true);
    CHECK(intel_x64::msrs::ia32_mc30_ctl2::cmci_en::get());

    intel_x64::msrs::ia32_mc30_ctl2::cmci_en::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_mc30_ctl2::cmci_en::get());
}

TEST_CASE("ia32_mc31_ctl2")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc31_ctl2::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_mc31_ctl2::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc31_ctl2_error_threshold")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc31_ctl2::error_threshold::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_mc31_ctl2::error_threshold::get() == 0x0000000000007FFFULL);
}

TEST_CASE("ia32_mc31_ctl2_cmci_en")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mc31_ctl2::cmci_en::set(true);
    CHECK(intel_x64::msrs::ia32_mc31_ctl2::cmci_en::get());

    intel_x64::msrs::ia32_mc31_ctl2::cmci_en::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_mc31_ctl2::cmci_en::get());
}

TEST_CASE("ia32_mtrr_def_type")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mtrr_def_type::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_mtrr_def_type::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mtrr_def_type_def_mem_type")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mtrr_def_type::def_mem_type::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_mtrr_def_type::def_mem_type::get() == 0x0000000000000007ULL);
}

TEST_CASE("ia32_mtrr_def_type_fixed_range_mtrr")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mtrr_def_type::fixed_range_mtrr::set(true);
    CHECK(intel_x64::msrs::ia32_mtrr_def_type::fixed_range_mtrr::get());

    intel_x64::msrs::ia32_mtrr_def_type::fixed_range_mtrr::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_mtrr_def_type::fixed_range_mtrr::get());
}

TEST_CASE("ia32_mtrr_def_type_mtrr")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mtrr_def_type::mtrr::set(true);
    CHECK(intel_x64::msrs::ia32_mtrr_def_type::mtrr::get());

    intel_x64::msrs::ia32_mtrr_def_type::mtrr::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_mtrr_def_type::mtrr::get());
}

TEST_CASE("ia32_fixed_ctr0")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_fixed_ctr0::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_fixed_ctr0::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_fixed_ctr1")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_fixed_ctr1::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_fixed_ctr1::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_fixed_ctr2")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_fixed_ctr2::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_fixed_ctr2::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_perf_capabilities")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000345UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_perf_capabilities::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_perf_capabilities_lbo_format")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000345UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_perf_capabilities::lbo_format::get() == 0x000000000000003FULL);
}

TEST_CASE("ia32_perf_capabilities_pebs_trap")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000345UL] = 0x0000000000000040ULL;
    CHECK(intel_x64::msrs::ia32_perf_capabilities::pebs_trap::get());

    g_msrs[0x00000345UL] = 0x0000000000000000ULL;
    CHECK_FALSE(intel_x64::msrs::ia32_perf_capabilities::pebs_trap::get());
}

TEST_CASE("ia32_perf_capabilities_pebs_savearchregs")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000345UL] = 0x0000000000000080ULL;
    CHECK(intel_x64::msrs::ia32_perf_capabilities::pebs_savearchregs::get());

    g_msrs[0x00000345UL] = 0x0000000000000000ULL;
    CHECK_FALSE(intel_x64::msrs::ia32_perf_capabilities::pebs_savearchregs::get());
}

TEST_CASE("ia32_perf_capabilities_pebs_record_format")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000345UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_perf_capabilities::pebs_record_format::get() == 0x000000000000000FULL);
}

TEST_CASE("ia32_perf_capabilities_freeze")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000345UL] = 0x0000000000001000ULL;
    CHECK(intel_x64::msrs::ia32_perf_capabilities::freeze::get());

    g_msrs[0x00000345UL] = 0x0000000000000000ULL;
    CHECK_FALSE(intel_x64::msrs::ia32_perf_capabilities::freeze::get());
}

TEST_CASE("ia32_perf_capabilities_counter_width")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000345UL] = 0x0000000000002000ULL;
    CHECK(intel_x64::msrs::ia32_perf_capabilities::counter_width::get());

    g_msrs[0x00000345UL] = 0x0000000000000000ULL;
    CHECK_FALSE(intel_x64::msrs::ia32_perf_capabilities::counter_width::get());
}

TEST_CASE("ia32_fixed_ctr_ctrl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_fixed_ctr_ctrl::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_fixed_ctr_ctrl::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_fixed_ctr_ctrl_en0_os")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_fixed_ctr_ctrl::en0_os::set(true);
    CHECK(intel_x64::msrs::ia32_fixed_ctr_ctrl::en0_os::get());

    intel_x64::msrs::ia32_fixed_ctr_ctrl::en0_os::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_fixed_ctr_ctrl::en0_os::get());
}

TEST_CASE("ia32_fixed_ctr_ctrl_en0_usr")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_fixed_ctr_ctrl::en0_usr::set(true);
    CHECK(intel_x64::msrs::ia32_fixed_ctr_ctrl::en0_usr::get());

    intel_x64::msrs::ia32_fixed_ctr_ctrl::en0_usr::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_fixed_ctr_ctrl::en0_usr::get());
}

TEST_CASE("ia32_fixed_ctr_ctrl_en0_anythread")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_fixed_ctr_ctrl::en0_anythread::set(true);
    CHECK(intel_x64::msrs::ia32_fixed_ctr_ctrl::en0_anythread::get());

    intel_x64::msrs::ia32_fixed_ctr_ctrl::en0_anythread::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_fixed_ctr_ctrl::en0_anythread::get());
}

TEST_CASE("ia32_fixed_ctr_ctrl_en0_pmi")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_fixed_ctr_ctrl::en0_pmi::set(true);
    CHECK(intel_x64::msrs::ia32_fixed_ctr_ctrl::en0_pmi::get());

    intel_x64::msrs::ia32_fixed_ctr_ctrl::en0_pmi::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_fixed_ctr_ctrl::en0_pmi::get());
}

TEST_CASE("ia32_fixed_ctr_ctrl_en1_os")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_fixed_ctr_ctrl::en1_os::set(true);
    CHECK(intel_x64::msrs::ia32_fixed_ctr_ctrl::en1_os::get());

    intel_x64::msrs::ia32_fixed_ctr_ctrl::en1_os::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_fixed_ctr_ctrl::en1_os::get());
}

TEST_CASE("ia32_fixed_ctr_ctrl_en1_usr")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_fixed_ctr_ctrl::en1_usr::set(true);
    CHECK(intel_x64::msrs::ia32_fixed_ctr_ctrl::en1_usr::get());

    intel_x64::msrs::ia32_fixed_ctr_ctrl::en1_usr::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_fixed_ctr_ctrl::en1_usr::get());
}

TEST_CASE("ia32_fixed_ctr_ctrl_en1_anythread")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_fixed_ctr_ctrl::en1_anythread::set(true);
    CHECK(intel_x64::msrs::ia32_fixed_ctr_ctrl::en1_anythread::get());

    intel_x64::msrs::ia32_fixed_ctr_ctrl::en1_anythread::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_fixed_ctr_ctrl::en1_anythread::get());
}

TEST_CASE("ia32_fixed_ctr_ctrl_en1_pmi")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_fixed_ctr_ctrl::en1_pmi::set(true);
    CHECK(intel_x64::msrs::ia32_fixed_ctr_ctrl::en1_pmi::get());

    intel_x64::msrs::ia32_fixed_ctr_ctrl::en1_pmi::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_fixed_ctr_ctrl::en1_pmi::get());
}

TEST_CASE("ia32_fixed_ctr_ctrl_en2_os")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_fixed_ctr_ctrl::en2_os::set(true);
    CHECK(intel_x64::msrs::ia32_fixed_ctr_ctrl::en2_os::get());

    intel_x64::msrs::ia32_fixed_ctr_ctrl::en2_os::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_fixed_ctr_ctrl::en2_os::get());
}

TEST_CASE("ia32_fixed_ctr_ctrl_en2_usr")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_fixed_ctr_ctrl::en2_usr::set(true);
    CHECK(intel_x64::msrs::ia32_fixed_ctr_ctrl::en2_usr::get());

    intel_x64::msrs::ia32_fixed_ctr_ctrl::en2_usr::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_fixed_ctr_ctrl::en2_usr::get());
}

TEST_CASE("ia32_fixed_ctr_ctrl_en2_anythread")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_fixed_ctr_ctrl::en2_anythread::set(true);
    CHECK(intel_x64::msrs::ia32_fixed_ctr_ctrl::en2_anythread::get());

    intel_x64::msrs::ia32_fixed_ctr_ctrl::en2_anythread::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_fixed_ctr_ctrl::en2_anythread::get());
}

TEST_CASE("ia32_fixed_ctr_ctrl_en2_pmi")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_fixed_ctr_ctrl::en2_pmi::set(true);
    CHECK(intel_x64::msrs::ia32_fixed_ctr_ctrl::en2_pmi::get());

    intel_x64::msrs::ia32_fixed_ctr_ctrl::en2_pmi::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_fixed_ctr_ctrl::en2_pmi::get());
}

TEST_CASE("ia32_perf_global_status")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000038EUL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_perf_global_status::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_perf_global_status_ovf_pmc0")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_perf_global_status::ovf_pmc0::set(true);
    CHECK(intel_x64::msrs::ia32_perf_global_status::ovf_pmc0::get());

    intel_x64::msrs::ia32_perf_global_status::ovf_pmc0::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_perf_global_status::ovf_pmc0::get());
}

TEST_CASE("ia32_perf_global_status_ovf_pmc1")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_perf_global_status::ovf_pmc1::set(true);
    CHECK(intel_x64::msrs::ia32_perf_global_status::ovf_pmc1::get());

    intel_x64::msrs::ia32_perf_global_status::ovf_pmc1::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_perf_global_status::ovf_pmc1::get());
}

TEST_CASE("ia32_perf_global_status_ovf_pmc2")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_perf_global_status::ovf_pmc2::set(true);
    CHECK(intel_x64::msrs::ia32_perf_global_status::ovf_pmc2::get());

    intel_x64::msrs::ia32_perf_global_status::ovf_pmc2::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_perf_global_status::ovf_pmc2::get());
}

TEST_CASE("ia32_perf_global_status_ovf_pmc3")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_perf_global_status::ovf_pmc3::set(true);
    CHECK(intel_x64::msrs::ia32_perf_global_status::ovf_pmc3::get());

    intel_x64::msrs::ia32_perf_global_status::ovf_pmc3::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_perf_global_status::ovf_pmc3::get());
}

TEST_CASE("ia32_perf_global_status_ovf_fixedctr0")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_perf_global_status::ovf_fixedctr0::set(true);
    CHECK(intel_x64::msrs::ia32_perf_global_status::ovf_fixedctr0::get());

    intel_x64::msrs::ia32_perf_global_status::ovf_fixedctr0::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_perf_global_status::ovf_fixedctr0::get());
}

TEST_CASE("ia32_perf_global_status_ovf_fixedctr1")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_perf_global_status::ovf_fixedctr1::set(true);
    CHECK(intel_x64::msrs::ia32_perf_global_status::ovf_fixedctr1::get());

    intel_x64::msrs::ia32_perf_global_status::ovf_fixedctr1::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_perf_global_status::ovf_fixedctr1::get());
}

TEST_CASE("ia32_perf_global_status_ovf_fixedctr2")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_perf_global_status::ovf_fixedctr2::set(true);
    CHECK(intel_x64::msrs::ia32_perf_global_status::ovf_fixedctr2::get());

    intel_x64::msrs::ia32_perf_global_status::ovf_fixedctr2::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_perf_global_status::ovf_fixedctr2::get());
}

TEST_CASE("ia32_perf_global_status_trace_topa_pmi")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_perf_global_status::trace_topa_pmi::set(true);
    CHECK(intel_x64::msrs::ia32_perf_global_status::trace_topa_pmi::get());

    intel_x64::msrs::ia32_perf_global_status::trace_topa_pmi::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_perf_global_status::trace_topa_pmi::get());
}

TEST_CASE("ia32_perf_global_status_lbr_frz")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_perf_global_status::lbr_frz::set(true);
    CHECK(intel_x64::msrs::ia32_perf_global_status::lbr_frz::get());

    intel_x64::msrs::ia32_perf_global_status::lbr_frz::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_perf_global_status::lbr_frz::get());
}

TEST_CASE("ia32_perf_global_status_ctr_frz")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_perf_global_status::ctr_frz::set(true);
    CHECK(intel_x64::msrs::ia32_perf_global_status::ctr_frz::get());

    intel_x64::msrs::ia32_perf_global_status::ctr_frz::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_perf_global_status::ctr_frz::get());
}

TEST_CASE("ia32_perf_global_status_asci")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_perf_global_status::asci::set(true);
    CHECK(intel_x64::msrs::ia32_perf_global_status::asci::get());

    intel_x64::msrs::ia32_perf_global_status::asci::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_perf_global_status::asci::get());
}

TEST_CASE("ia32_perf_global_status_ovf_uncore")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_perf_global_status::ovf_uncore::set(true);
    CHECK(intel_x64::msrs::ia32_perf_global_status::ovf_uncore::get());

    intel_x64::msrs::ia32_perf_global_status::ovf_uncore::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_perf_global_status::ovf_uncore::get());
}

TEST_CASE("ia32_perf_global_status_ovfbuf")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_perf_global_status::ovfbuf::set(true);
    CHECK(intel_x64::msrs::ia32_perf_global_status::ovfbuf::get());

    intel_x64::msrs::ia32_perf_global_status::ovfbuf::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_perf_global_status::ovfbuf::get());
}

TEST_CASE("ia32_perf_global_status_condchgd")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_perf_global_status::condchgd::set(true);
    CHECK(intel_x64::msrs::ia32_perf_global_status::condchgd::get());

    intel_x64::msrs::ia32_perf_global_status::condchgd::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_perf_global_status::condchgd::get());
}

TEST_CASE("ia32_perf_global_ctrl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_perf_global_ctrl::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_perf_global_ctrl::get() == 0xFFFFFFFFFFFFFFFFULL);

    intel_x64::msrs::ia32_perf_global_ctrl::dump();
}

TEST_CASE("ia32_perf_global_ctrl_pmc0")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_perf_global_ctrl::pmc0::set(true);
    CHECK(intel_x64::msrs::ia32_perf_global_ctrl::pmc0::get());

    intel_x64::msrs::ia32_perf_global_ctrl::pmc0::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_perf_global_ctrl::pmc0::get());
}

TEST_CASE("ia32_perf_global_ctrl_pmc1")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_perf_global_ctrl::pmc1::set(true);
    CHECK(intel_x64::msrs::ia32_perf_global_ctrl::pmc1::get());

    intel_x64::msrs::ia32_perf_global_ctrl::pmc1::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_perf_global_ctrl::pmc1::get());
}

TEST_CASE("ia32_perf_global_ctrl_pmc2")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_perf_global_ctrl::pmc2::set(true);
    CHECK(intel_x64::msrs::ia32_perf_global_ctrl::pmc2::get());

    intel_x64::msrs::ia32_perf_global_ctrl::pmc2::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_perf_global_ctrl::pmc2::get());
}

TEST_CASE("ia32_perf_global_ctrl_pmc3")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_perf_global_ctrl::pmc3::set(true);
    CHECK(intel_x64::msrs::ia32_perf_global_ctrl::pmc3::get());

    intel_x64::msrs::ia32_perf_global_ctrl::pmc3::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_perf_global_ctrl::pmc3::get());
}

TEST_CASE("ia32_perf_global_ctrl_pmc4")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_perf_global_ctrl::pmc4::set(true);
    CHECK(intel_x64::msrs::ia32_perf_global_ctrl::pmc4::get());

    intel_x64::msrs::ia32_perf_global_ctrl::pmc4::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_perf_global_ctrl::pmc4::get());
}

TEST_CASE("ia32_perf_global_ctrl_pmc5")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_perf_global_ctrl::pmc5::set(true);
    CHECK(intel_x64::msrs::ia32_perf_global_ctrl::pmc5::get());

    intel_x64::msrs::ia32_perf_global_ctrl::pmc5::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_perf_global_ctrl::pmc5::get());
}

TEST_CASE("ia32_perf_global_ctrl_pmc6")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_perf_global_ctrl::pmc6::set(true);
    CHECK(intel_x64::msrs::ia32_perf_global_ctrl::pmc6::get());

    intel_x64::msrs::ia32_perf_global_ctrl::pmc6::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_perf_global_ctrl::pmc6::get());
}

TEST_CASE("ia32_perf_global_ctrl_pmc7")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_perf_global_ctrl::pmc7::set(true);
    CHECK(intel_x64::msrs::ia32_perf_global_ctrl::pmc7::get());

    intel_x64::msrs::ia32_perf_global_ctrl::pmc7::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_perf_global_ctrl::pmc7::get());
}

TEST_CASE("ia32_perf_global_ctrl_fixed_ctr0")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_perf_global_ctrl::fixed_ctr0::set(true);
    CHECK(intel_x64::msrs::ia32_perf_global_ctrl::fixed_ctr0::get());

    intel_x64::msrs::ia32_perf_global_ctrl::fixed_ctr0::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_perf_global_ctrl::fixed_ctr0::get());
}

TEST_CASE("ia32_perf_global_ctrl_fixed_ctr1")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_perf_global_ctrl::fixed_ctr1::set(true);
    CHECK(intel_x64::msrs::ia32_perf_global_ctrl::fixed_ctr1::get());

    intel_x64::msrs::ia32_perf_global_ctrl::fixed_ctr1::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_perf_global_ctrl::fixed_ctr1::get());
}

TEST_CASE("ia32_perf_global_ctrl_fixed_ctr2")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_perf_global_ctrl::fixed_ctr2::set(true);
    CHECK(intel_x64::msrs::ia32_perf_global_ctrl::fixed_ctr2::get());

    intel_x64::msrs::ia32_perf_global_ctrl::fixed_ctr2::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_perf_global_ctrl::fixed_ctr2::get());
}

TEST_CASE("ia32_perf_global_ovf_ctrl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_perf_global_ovf_ctrl::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_perf_global_ovf_ctrl::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_perf_global_ovf_ctrl_clear_ovf_pmc0")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_perf_global_ovf_ctrl::clear_ovf_pmc0::set(true);
    CHECK(intel_x64::msrs::ia32_perf_global_ovf_ctrl::clear_ovf_pmc0::get());

    intel_x64::msrs::ia32_perf_global_ovf_ctrl::clear_ovf_pmc0::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_perf_global_ovf_ctrl::clear_ovf_pmc0::get());
}

TEST_CASE("ia32_perf_global_ovf_ctrl_clear_ovf_pmc1")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_perf_global_ovf_ctrl::clear_ovf_pmc1::set(true);
    CHECK(intel_x64::msrs::ia32_perf_global_ovf_ctrl::clear_ovf_pmc1::get());

    intel_x64::msrs::ia32_perf_global_ovf_ctrl::clear_ovf_pmc1::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_perf_global_ovf_ctrl::clear_ovf_pmc1::get());
}

TEST_CASE("ia32_perf_global_ovf_ctrl_clear_ovf_pmc2")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_perf_global_ovf_ctrl::clear_ovf_pmc2::set(true);
    CHECK(intel_x64::msrs::ia32_perf_global_ovf_ctrl::clear_ovf_pmc2::get());

    intel_x64::msrs::ia32_perf_global_ovf_ctrl::clear_ovf_pmc2::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_perf_global_ovf_ctrl::clear_ovf_pmc2::get());
}

TEST_CASE("ia32_perf_global_ovf_ctrl_clear_ovf_fixed_ctr0")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_perf_global_ovf_ctrl::clear_ovf_fixed_ctr0::set(true);
    CHECK(intel_x64::msrs::ia32_perf_global_ovf_ctrl::clear_ovf_fixed_ctr0::get());

    intel_x64::msrs::ia32_perf_global_ovf_ctrl::clear_ovf_fixed_ctr0::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_perf_global_ovf_ctrl::clear_ovf_fixed_ctr0::get());
}

TEST_CASE("ia32_perf_global_ovf_ctrl_clear_ovf_fixed_ctr1")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_perf_global_ovf_ctrl::clear_ovf_fixed_ctr1::set(true);
    CHECK(intel_x64::msrs::ia32_perf_global_ovf_ctrl::clear_ovf_fixed_ctr1::get());

    intel_x64::msrs::ia32_perf_global_ovf_ctrl::clear_ovf_fixed_ctr1::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_perf_global_ovf_ctrl::clear_ovf_fixed_ctr1::get());
}

TEST_CASE("ia32_perf_global_ovf_ctrl_clear_ovf_fixed_ctr2")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_perf_global_ovf_ctrl::clear_ovf_fixed_ctr2::set(true);
    CHECK(intel_x64::msrs::ia32_perf_global_ovf_ctrl::clear_ovf_fixed_ctr2::get());

    intel_x64::msrs::ia32_perf_global_ovf_ctrl::clear_ovf_fixed_ctr2::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_perf_global_ovf_ctrl::clear_ovf_fixed_ctr2::get());
}

TEST_CASE("ia32_perf_global_ovf_ctrl_clear_trace_topa_pmi")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_perf_global_ovf_ctrl::clear_trace_topa_pmi::set(true);
    CHECK(intel_x64::msrs::ia32_perf_global_ovf_ctrl::clear_trace_topa_pmi::get());

    intel_x64::msrs::ia32_perf_global_ovf_ctrl::clear_trace_topa_pmi::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_perf_global_ovf_ctrl::clear_trace_topa_pmi::get());
}

TEST_CASE("ia32_perf_global_ovf_ctrl_lbr_frz")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_perf_global_ovf_ctrl::lbr_frz::set(true);
    CHECK(intel_x64::msrs::ia32_perf_global_ovf_ctrl::lbr_frz::get());

    intel_x64::msrs::ia32_perf_global_ovf_ctrl::lbr_frz::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_perf_global_ovf_ctrl::lbr_frz::get());
}

TEST_CASE("ia32_perf_global_ovf_ctrl_ctr_frz")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_perf_global_ovf_ctrl::ctr_frz::set(true);
    CHECK(intel_x64::msrs::ia32_perf_global_ovf_ctrl::ctr_frz::get());

    intel_x64::msrs::ia32_perf_global_ovf_ctrl::ctr_frz::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_perf_global_ovf_ctrl::ctr_frz::get());
}

TEST_CASE("ia32_perf_global_ovf_ctrl_clear_ovf_uncore")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_perf_global_ovf_ctrl::clear_ovf_uncore::set(true);
    CHECK(intel_x64::msrs::ia32_perf_global_ovf_ctrl::clear_ovf_uncore::get());

    intel_x64::msrs::ia32_perf_global_ovf_ctrl::clear_ovf_uncore::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_perf_global_ovf_ctrl::clear_ovf_uncore::get());
}

TEST_CASE("ia32_perf_global_ovf_ctrl_clear_ovfbuf")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_perf_global_ovf_ctrl::clear_ovfbuf::set(true);
    CHECK(intel_x64::msrs::ia32_perf_global_ovf_ctrl::clear_ovfbuf::get());

    intel_x64::msrs::ia32_perf_global_ovf_ctrl::clear_ovfbuf::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_perf_global_ovf_ctrl::clear_ovfbuf::get());
}

TEST_CASE("ia32_perf_global_ovf_ctrl_clear_condchgd")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_perf_global_ovf_ctrl::clear_condchgd::set(true);
    CHECK(intel_x64::msrs::ia32_perf_global_ovf_ctrl::clear_condchgd::get());

    intel_x64::msrs::ia32_perf_global_ovf_ctrl::clear_condchgd::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_perf_global_ovf_ctrl::clear_condchgd::get());
}

TEST_CASE("ia32_perf_global_status_set")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_perf_global_status_set::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_perf_global_status_set::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_perf_global_status_set_ovf_pmc0")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_perf_global_status_set::ovf_pmc0::set(true);
    CHECK(intel_x64::msrs::ia32_perf_global_status_set::ovf_pmc0::get());

    intel_x64::msrs::ia32_perf_global_status_set::ovf_pmc0::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_perf_global_status_set::ovf_pmc0::get());
}

TEST_CASE("ia32_perf_global_status_set_ovf_pmc1")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_perf_global_status_set::ovf_pmc1::set(true);
    CHECK(intel_x64::msrs::ia32_perf_global_status_set::ovf_pmc1::get());

    intel_x64::msrs::ia32_perf_global_status_set::ovf_pmc1::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_perf_global_status_set::ovf_pmc1::get());
}

TEST_CASE("ia32_perf_global_status_set_ovf_pmc2")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_perf_global_status_set::ovf_pmc2::set(true);
    CHECK(intel_x64::msrs::ia32_perf_global_status_set::ovf_pmc2::get());

    intel_x64::msrs::ia32_perf_global_status_set::ovf_pmc2::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_perf_global_status_set::ovf_pmc2::get());
}

TEST_CASE("ia32_perf_global_status_set_ovf_fixed_ctr0")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_perf_global_status_set::ovf_fixed_ctr0::set(true);
    CHECK(intel_x64::msrs::ia32_perf_global_status_set::ovf_fixed_ctr0::get());

    intel_x64::msrs::ia32_perf_global_status_set::ovf_fixed_ctr0::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_perf_global_status_set::ovf_fixed_ctr0::get());
}

TEST_CASE("ia32_perf_global_status_set_ovf_fixed_ctr1")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_perf_global_status_set::ovf_fixed_ctr1::set(true);
    CHECK(intel_x64::msrs::ia32_perf_global_status_set::ovf_fixed_ctr1::get());

    intel_x64::msrs::ia32_perf_global_status_set::ovf_fixed_ctr1::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_perf_global_status_set::ovf_fixed_ctr1::get());
}

TEST_CASE("ia32_perf_global_status_set_ovf_fixed_ctr2")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_perf_global_status_set::ovf_fixed_ctr2::set(true);
    CHECK(intel_x64::msrs::ia32_perf_global_status_set::ovf_fixed_ctr2::get());

    intel_x64::msrs::ia32_perf_global_status_set::ovf_fixed_ctr2::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_perf_global_status_set::ovf_fixed_ctr2::get());
}

TEST_CASE("ia32_perf_global_status_set_trace_topa_pmi")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_perf_global_status_set::trace_topa_pmi::set(true);
    CHECK(intel_x64::msrs::ia32_perf_global_status_set::trace_topa_pmi::get());

    intel_x64::msrs::ia32_perf_global_status_set::trace_topa_pmi::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_perf_global_status_set::trace_topa_pmi::get());
}

TEST_CASE("ia32_perf_global_status_set_lbr_frz")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_perf_global_status_set::lbr_frz::set(true);
    CHECK(intel_x64::msrs::ia32_perf_global_status_set::lbr_frz::get());

    intel_x64::msrs::ia32_perf_global_status_set::lbr_frz::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_perf_global_status_set::lbr_frz::get());
}

TEST_CASE("ia32_perf_global_status_set_ctr_frz")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_perf_global_status_set::ctr_frz::set(true);
    CHECK(intel_x64::msrs::ia32_perf_global_status_set::ctr_frz::get());

    intel_x64::msrs::ia32_perf_global_status_set::ctr_frz::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_perf_global_status_set::ctr_frz::get());
}

TEST_CASE("ia32_perf_global_status_set_ovf_uncore")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_perf_global_status_set::ovf_uncore::set(true);
    CHECK(intel_x64::msrs::ia32_perf_global_status_set::ovf_uncore::get());

    intel_x64::msrs::ia32_perf_global_status_set::ovf_uncore::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_perf_global_status_set::ovf_uncore::get());
}

TEST_CASE("ia32_perf_global_status_set_ovfbuf")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_perf_global_status_set::ovfbuf::set(true);
    CHECK(intel_x64::msrs::ia32_perf_global_status_set::ovfbuf::get());

    intel_x64::msrs::ia32_perf_global_status_set::ovfbuf::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_perf_global_status_set::ovfbuf::get());
}

TEST_CASE("ia32_perf_global_inuse")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000392UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_perf_global_inuse::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_perf_global_inuse_perfevtsel0")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000392UL] = 0x0000000000000001ULL;
    CHECK(intel_x64::msrs::ia32_perf_global_inuse::perfevtsel0::get());

    g_msrs[0x00000392UL] = 0x0000000000000000ULL;
    CHECK_FALSE(intel_x64::msrs::ia32_perf_global_inuse::perfevtsel0::get());
}

TEST_CASE("ia32_perf_global_inuse_perfevtsel1")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000392UL] = 0x0000000000000002ULL;
    CHECK(intel_x64::msrs::ia32_perf_global_inuse::perfevtsel1::get());

    g_msrs[0x00000392UL] = 0x0000000000000000ULL;
    CHECK_FALSE(intel_x64::msrs::ia32_perf_global_inuse::perfevtsel1::get());
}

TEST_CASE("ia32_perf_global_inuse_perfevtsel2")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000392UL] = 0x0000000000000004ULL;
    CHECK(intel_x64::msrs::ia32_perf_global_inuse::perfevtsel2::get());

    g_msrs[0x00000392UL] = 0x0000000000000000ULL;
    CHECK_FALSE(intel_x64::msrs::ia32_perf_global_inuse::perfevtsel2::get());
}

TEST_CASE("ia32_perf_global_inuse_fixed_ctr0")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000392UL] = 0x0000000100000000ULL;
    CHECK(intel_x64::msrs::ia32_perf_global_inuse::fixed_ctr0::get());

    g_msrs[0x00000392UL] = 0x0000000000000000ULL;
    CHECK_FALSE(intel_x64::msrs::ia32_perf_global_inuse::fixed_ctr0::get());
}

TEST_CASE("ia32_perf_global_inuse_fixed_ctr1")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000392UL] = 0x0000000200000000ULL;
    CHECK(intel_x64::msrs::ia32_perf_global_inuse::fixed_ctr1::get());

    g_msrs[0x00000392UL] = 0x0000000000000000ULL;
    CHECK_FALSE(intel_x64::msrs::ia32_perf_global_inuse::fixed_ctr1::get());
}

TEST_CASE("ia32_perf_global_inuse_fixed_ctr2")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000392UL] = 0x0000000400000000ULL;
    CHECK(intel_x64::msrs::ia32_perf_global_inuse::fixed_ctr2::get());

    g_msrs[0x00000392UL] = 0x0000000000000000ULL;
    CHECK_FALSE(intel_x64::msrs::ia32_perf_global_inuse::fixed_ctr2::get());
}

TEST_CASE("ia32_perf_global_inuse_pmi")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000392UL] = 0x8000000000000000ULL;
    CHECK(intel_x64::msrs::ia32_perf_global_inuse::pmi::get());

    g_msrs[0x00000392UL] = 0x0000000000000000ULL;
    CHECK_FALSE(intel_x64::msrs::ia32_perf_global_inuse::pmi::get());
}

TEST_CASE("ia32_pebs_enable")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_pebs_enable::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_pebs_enable::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_pebs_enable_pebs")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_pebs_enable::pebs::set(true);
    CHECK(intel_x64::msrs::ia32_pebs_enable::pebs::get());

    intel_x64::msrs::ia32_pebs_enable::pebs::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_pebs_enable::pebs::get());
}

TEST_CASE("ia32_mc6_ctl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000418UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mc6_ctl::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc6_status")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000419UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mc6_status::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc6_addr")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000041AUL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mc6_addr::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc6_misc")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000041BUL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mc6_misc::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc7_ctl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000041CUL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mc7_ctl::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc7_status")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000041DUL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mc7_status::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc7_addr")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000041EUL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mc7_addr::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc7_misc")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000041FUL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mc7_misc::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc8_ctl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000420UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mc8_ctl::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc8_status")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000421UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mc8_status::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc8_addr")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000422UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mc8_addr::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc8_misc")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000423UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mc8_misc::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc9_ctl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000424UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mc9_ctl::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc9_status")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000425UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mc9_status::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc9_addr")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000426UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mc9_addr::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc9_misc")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000427UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mc9_misc::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc10_ctl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000428UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mc10_ctl::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc10_status")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000429UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mc10_status::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc10_addr")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000042AUL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mc10_addr::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc10_misc")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000042BUL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mc10_misc::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc11_ctl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000042CUL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mc11_ctl::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc11_status")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000042DUL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mc11_status::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc11_addr")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000042EUL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mc11_addr::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc11_misc")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000042FUL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mc11_misc::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc12_ctl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000430UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mc12_ctl::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc12_status")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000431UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mc12_status::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc12_addr")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000432UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mc12_addr::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc12_misc")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000433UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mc12_misc::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc13_ctl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000434UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mc13_ctl::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc13_status")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000435UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mc13_status::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc13_addr")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000436UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mc13_addr::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc13_misc")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000437UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mc13_misc::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc14_ctl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000438UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mc14_ctl::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc14_status")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000439UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mc14_status::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc14_addr")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000043AUL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mc14_addr::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc14_misc")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000043BUL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mc14_misc::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc15_ctl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000043CUL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mc15_ctl::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc15_status")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000043DUL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mc15_status::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc15_addr")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000043EUL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mc15_addr::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc15_misc")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000043FUL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mc15_misc::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc16_ctl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000440UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mc16_ctl::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc16_status")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000441UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mc16_status::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc16_addr")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000442UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mc16_addr::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc16_misc")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000443UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mc16_misc::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc17_ctl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000444UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mc17_ctl::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc17_status")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000445UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mc17_status::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc17_addr")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000446UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mc17_addr::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc17_misc")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000447UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mc17_misc::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc18_ctl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000448UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mc18_ctl::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc18_status")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000449UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mc18_status::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc18_addr")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000044AUL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mc18_addr::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc18_misc")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000044BUL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mc18_misc::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc19_ctl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000044CUL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mc19_ctl::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc19_status")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000044DUL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mc19_status::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc19_addr")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000044EUL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mc19_addr::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc19_misc")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000044FUL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mc19_misc::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc20_ctl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000450UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mc20_ctl::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc20_status")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000451UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mc20_status::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc20_addr")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000452UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mc20_addr::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc20_misc")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000453UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mc20_misc::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc21_ctl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000454UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mc21_ctl::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc21_status")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000455UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mc21_status::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc21_addr")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000456UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mc21_addr::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc21_misc")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000457UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mc21_misc::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc22_ctl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000458UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mc22_ctl::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc22_status")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000459UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mc22_status::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc22_addr")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000045AUL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mc22_addr::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc22_misc")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000045BUL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mc22_misc::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc23_ctl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000045CUL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mc23_ctl::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc23_status")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000045DUL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mc23_status::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc23_addr")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000045EUL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mc23_addr::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc23_misc")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000045FUL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mc23_misc::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc24_ctl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000460UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mc24_ctl::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc24_status")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000461UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mc24_status::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc24_addr")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000462UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mc24_addr::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc24_misc")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000463UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mc24_misc::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc25_ctl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000464UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mc25_ctl::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc25_status")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000465UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mc25_status::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc25_addr")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000466UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mc25_addr::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc25_misc")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000467UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mc25_misc::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc26_ctl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000468UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mc26_ctl::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc26_status")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000469UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mc26_status::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc26_addr")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000046AUL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mc26_addr::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc26_misc")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000046BUL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mc26_misc::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc27_ctl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000046CUL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mc27_ctl::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc27_status")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000046DUL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mc27_status::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc27_addr")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000046EUL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mc27_addr::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc27_misc")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000046FUL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mc27_misc::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc28_ctl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000470UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mc28_ctl::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc28_status")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000471UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mc28_status::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc28_addr")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000472UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mc28_addr::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc28_misc")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000473UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_mc28_misc::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_vmx_basic")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000480UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_vmx_basic::get() == 0xFFFFFFFFFFFFFFFFULL);

    intel_x64::msrs::ia32_vmx_basic::dump();
}

TEST_CASE("ia32_vmx_basic_revision_id")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000480UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_vmx_basic::revision_id::get() == 0x000000007FFFFFFFULL);
}

TEST_CASE("ia32_vmx_basic_vmxon_vmcs_region_size")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000480UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_vmx_basic::vmxon_vmcs_region_size::get() == 0x0000000000001FFFULL);
}

TEST_CASE("ia32_vmx_basic_physical_address_width")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000480UL] = 0x0001000000000000ULL;
    CHECK(intel_x64::msrs::ia32_vmx_basic::physical_address_width::get());

    g_msrs[0x00000480UL] = 0x0000000000000000ULL;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_basic::physical_address_width::get());
}

TEST_CASE("ia32_vmx_basic_dual_monitor_mode_support")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000480UL] = 0x0002000000000000ULL;
    CHECK(intel_x64::msrs::ia32_vmx_basic::dual_monitor_mode_support::get());

    g_msrs[0x00000480UL] = 0x0000000000000000ULL;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_basic::dual_monitor_mode_support::get());
}

TEST_CASE("ia32_vmx_basic_memory_type")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000480UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_vmx_basic::memory_type::get() == 0x000000000000000FULL);
}

TEST_CASE("ia32_vmx_basic_ins_outs_exit_information")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000480UL] = 0x0040000000000000ULL;
    CHECK(intel_x64::msrs::ia32_vmx_basic::ins_outs_exit_information::get());

    g_msrs[0x00000480UL] = 0x0000000000000000ULL;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_basic::ins_outs_exit_information::get());
}

TEST_CASE("ia32_vmx_basic_true_based_controls")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000480UL] = 0x0080000000000000ULL;
    CHECK(intel_x64::msrs::ia32_vmx_basic::true_based_controls::get());

    g_msrs[0x00000480UL] = 0x0000000000000000ULL;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_basic::true_based_controls::get());
}

TEST_CASE("ia32_vmx_pinbased_ctls")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000481UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_vmx_pinbased_ctls::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_vmx_pinbased_ctls_allowed_0_settings")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000481UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_vmx_pinbased_ctls::allowed_0_settings::get() == 0x00000000FFFFFFFFULL);
}

TEST_CASE("ia32_vmx_pinbased_ctls_allowed_1_settings")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000481UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_vmx_pinbased_ctls::allowed_1_settings::get() == 0x00000000FFFFFFFFULL);
}

TEST_CASE("ia32_vmx_procbased_ctls")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000482UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_vmx_procbased_ctls::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_vmx_procbased_ctls_allowed_0_settings")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000482UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_vmx_procbased_ctls::allowed_0_settings::get() == 0x00000000FFFFFFFFULL);
}

TEST_CASE("ia32_vmx_procbased_ctls_allowed_1_settings")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000482UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_vmx_procbased_ctls::allowed_1_settings::get() == 0x00000000FFFFFFFFULL);
}

TEST_CASE("ia32_vmx_exit_ctls")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000483UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_vmx_exit_ctls::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_vmx_exit_ctls_allowed_0_settings")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000483UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_vmx_exit_ctls::allowed_0_settings::get() == 0x00000000FFFFFFFFULL);
}

TEST_CASE("ia32_vmx_exit_ctls_allowed_1_settings")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000483UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_vmx_exit_ctls::allowed_1_settings::get() == 0x00000000FFFFFFFFULL);
}

TEST_CASE("ia32_vmx_entry_ctls")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000484UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_vmx_entry_ctls::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_vmx_entry_ctls_allowed_0_settings")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000484UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_vmx_entry_ctls::allowed_0_settings::get() == 0x00000000FFFFFFFFULL);
}

TEST_CASE("ia32_vmx_entry_ctls_allowed_1_settings")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000484UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_vmx_entry_ctls::allowed_1_settings::get() == 0x00000000FFFFFFFFULL);
}

TEST_CASE("ia32_vmx_misc")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000485UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_vmx_misc::get() == 0xFFFFFFFFFFFFFFFFULL);

    intel_x64::msrs::ia32_vmx_misc::dump();
}

TEST_CASE("ia32_vmx_misc_preemption_timer_decrement")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000485UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_vmx_misc::preemption_timer_decrement::get() == 0x000000000000001FULL);
}

TEST_CASE("ia32_vmx_misc_store_efer_lma_on_vm_exit")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000485UL] = 0x0000000000000020ULL;
    CHECK(intel_x64::msrs::ia32_vmx_misc::store_efer_lma_on_vm_exit::get());

    g_msrs[0x00000485UL] = 0x0000000000000000ULL;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_misc::store_efer_lma_on_vm_exit::get());
}

TEST_CASE("ia32_vmx_misc_activity_state_hlt_support")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000485UL] = 0x0000000000000040ULL;
    CHECK(intel_x64::msrs::ia32_vmx_misc::activity_state_hlt_support::get());

    g_msrs[0x00000485UL] = 0x0000000000000000ULL;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_misc::activity_state_hlt_support::get());
}

TEST_CASE("ia32_vmx_misc_activity_state_shutdown_support")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000485UL] = 0x0000000000000080ULL;
    CHECK(intel_x64::msrs::ia32_vmx_misc::activity_state_shutdown_support::get());

    g_msrs[0x00000485UL] = 0x0000000000000000ULL;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_misc::activity_state_shutdown_support::get());
}

TEST_CASE("ia32_vmx_misc_activity_state_wait_for_sipi_support")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000485UL] = 0x0000000000000100ULL;
    CHECK(intel_x64::msrs::ia32_vmx_misc::activity_state_wait_for_sipi_support::get());

    g_msrs[0x00000485UL] = 0x0000000000000000ULL;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_misc::activity_state_wait_for_sipi_support::get());
}

TEST_CASE("ia32_vmx_misc_processor_trace_support")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000485UL] = 0x0000000000004000ULL;
    CHECK(intel_x64::msrs::ia32_vmx_misc::processor_trace_support::get());

    g_msrs[0x00000485UL] = 0x0000000000000000ULL;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_misc::processor_trace_support::get());
}

TEST_CASE("ia32_vmx_misc_rdmsr_in_smm_support")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000485UL] = 0x0000000000008000ULL;
    CHECK(intel_x64::msrs::ia32_vmx_misc::rdmsr_in_smm_support::get());

    g_msrs[0x00000485UL] = 0x0000000000000000ULL;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_misc::rdmsr_in_smm_support::get());
}

TEST_CASE("ia32_vmx_misc_cr3_targets")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000485UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_vmx_misc::cr3_targets::get() == 0x00000000000001FFULL);
}

TEST_CASE("ia32_vmx_misc_max_num_msr_load_store_on_exit")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000485UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_vmx_misc::max_num_msr_load_store_on_exit::get() == 0x0000000000000007ULL);
}

TEST_CASE("ia32_vmx_misc_vmxoff_blocked_smi_support")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000485UL] = 0x0000000010000000ULL;
    CHECK(intel_x64::msrs::ia32_vmx_misc::vmxoff_blocked_smi_support::get());

    g_msrs[0x00000485UL] = 0x0000000000000000ULL;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_misc::vmxoff_blocked_smi_support::get());
}

TEST_CASE("ia32_vmx_misc_vmwrite_all_fields_support")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000485UL] = 0x0000000020000000ULL;
    CHECK(intel_x64::msrs::ia32_vmx_misc::vmwrite_all_fields_support::get());

    g_msrs[0x00000485UL] = 0x0000000000000000ULL;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_misc::vmwrite_all_fields_support::get());
}

TEST_CASE("ia32_vmx_misc_injection_with_instruction_length_of_zero")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000485UL] = 0x0000000040000000ULL;
    CHECK(intel_x64::msrs::ia32_vmx_misc::injection_with_instruction_length_of_zero::get());

    g_msrs[0x00000485UL] = 0x0000000000000000ULL;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_misc::injection_with_instruction_length_of_zero::get());
}

TEST_CASE("ia32_vmx_cr0_fixed0")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000486UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_vmx_cr0_fixed0::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_vmx_cr0_fixed1")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000487UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_vmx_cr0_fixed1::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_vmx_cr4_fixed0")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000488UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_vmx_cr4_fixed0::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_vmx_cr4_fixed1")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000489UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_vmx_cr4_fixed1::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_vmx_vmcs_enum")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000048AUL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_vmx_vmcs_enum::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_vmx_vmcs_enum_highest_index")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000048AUL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_vmx_vmcs_enum::highest_index::get() == 0x00000000000001FFULL);
}

TEST_CASE("ia32_vmx_procbased_ctls2")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = 0x00000000FFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_vmx_procbased_ctls2::get() == 0x00000000FFFFFFFFULL);

    intel_x64::msrs::ia32_vmx_procbased_ctls2::dump();

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = 0x0UL;
    CHECK(intel_x64::msrs::ia32_vmx_procbased_ctls2::get() == 0x0UL);

    intel_x64::msrs::ia32_vmx_procbased_ctls2::dump();

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = 0x00000000FFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_vmx_procbased_ctls2::allowed0() == 0xFFFFFFFFUL);
    CHECK(intel_x64::msrs::ia32_vmx_procbased_ctls2::allowed1() == 0x00000000UL);

    intel_x64::msrs::ia32_vmx_procbased_ctls2::dump();

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = 0xFFFFFFFF00000000ULL;
    CHECK(intel_x64::msrs::ia32_vmx_procbased_ctls2::allowed0() == 0x00000000UL);
    CHECK(intel_x64::msrs::ia32_vmx_procbased_ctls2::allowed1() == 0xFFFFFFFFUL);

    intel_x64::msrs::ia32_vmx_procbased_ctls2::dump();
}

TEST_CASE("ia32_vmx_procbased_ctls2_virtualize_apic_accesses")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    auto mask = intel_x64::msrs::ia32_vmx_procbased_ctls2::virtualize_apic_accesses::mask;

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = mask;
    CHECK(intel_x64::msrs::ia32_vmx_procbased_ctls2::virtualize_apic_accesses::get());

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = ~mask;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_procbased_ctls2::virtualize_apic_accesses::get());

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = mask | (mask << 32);
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_procbased_ctls2::virtualize_apic_accesses::is_allowed0());
    CHECK(intel_x64::msrs::ia32_vmx_procbased_ctls2::virtualize_apic_accesses::is_allowed1());

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = ~mask & ~(mask << 32);
    CHECK(intel_x64::msrs::ia32_vmx_procbased_ctls2::virtualize_apic_accesses::is_allowed0());
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_procbased_ctls2::virtualize_apic_accesses::is_allowed1());
}

TEST_CASE("ia32_vmx_procbased_ctls2_enable_ept")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    auto mask = intel_x64::msrs::ia32_vmx_procbased_ctls2::enable_ept::mask;

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = mask;
    CHECK(intel_x64::msrs::ia32_vmx_procbased_ctls2::enable_ept::get());

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = ~mask;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_procbased_ctls2::enable_ept::get());

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = mask | (mask << 32);
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_procbased_ctls2::enable_ept::is_allowed0());
    CHECK(intel_x64::msrs::ia32_vmx_procbased_ctls2::enable_ept::is_allowed1());

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = ~mask & ~(mask << 32);
    CHECK(intel_x64::msrs::ia32_vmx_procbased_ctls2::enable_ept::is_allowed0());
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_procbased_ctls2::enable_ept::is_allowed1());
}

TEST_CASE("ia32_vmx_procbased_ctls2_descriptor_table_exiting")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    auto mask = intel_x64::msrs::ia32_vmx_procbased_ctls2::descriptor_table_exiting::mask;

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = mask;
    CHECK(intel_x64::msrs::ia32_vmx_procbased_ctls2::descriptor_table_exiting::get());

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = ~mask;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_procbased_ctls2::descriptor_table_exiting::get());

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = mask | (mask << 32);
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_procbased_ctls2::descriptor_table_exiting::is_allowed0());
    CHECK(intel_x64::msrs::ia32_vmx_procbased_ctls2::descriptor_table_exiting::is_allowed1());

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = ~mask & ~(mask << 32);
    CHECK(intel_x64::msrs::ia32_vmx_procbased_ctls2::descriptor_table_exiting::is_allowed0());
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_procbased_ctls2::descriptor_table_exiting::is_allowed1());
}

TEST_CASE("ia32_vmx_procbased_ctls2_enable_rdtscp")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    auto mask = intel_x64::msrs::ia32_vmx_procbased_ctls2::enable_rdtscp::mask;

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = mask;
    CHECK(intel_x64::msrs::ia32_vmx_procbased_ctls2::enable_rdtscp::get());

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = ~mask;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_procbased_ctls2::enable_rdtscp::get());

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = mask | (mask << 32);
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_procbased_ctls2::enable_rdtscp::is_allowed0());
    CHECK(intel_x64::msrs::ia32_vmx_procbased_ctls2::enable_rdtscp::is_allowed1());

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = ~mask & ~(mask << 32);
    CHECK(intel_x64::msrs::ia32_vmx_procbased_ctls2::enable_rdtscp::is_allowed0());
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_procbased_ctls2::enable_rdtscp::is_allowed1());
}

TEST_CASE("ia32_vmx_procbased_ctls2_virtualize_x2apic_mode")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    auto mask = intel_x64::msrs::ia32_vmx_procbased_ctls2::virtualize_x2apic_mode::mask;

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = mask;
    CHECK(intel_x64::msrs::ia32_vmx_procbased_ctls2::virtualize_x2apic_mode::get());

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = ~mask;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_procbased_ctls2::virtualize_x2apic_mode::get());

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = mask | (mask << 32);
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_procbased_ctls2::virtualize_x2apic_mode::is_allowed0());
    CHECK(intel_x64::msrs::ia32_vmx_procbased_ctls2::virtualize_x2apic_mode::is_allowed1());

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = ~mask & ~(mask << 32);
    CHECK(intel_x64::msrs::ia32_vmx_procbased_ctls2::virtualize_x2apic_mode::is_allowed0());
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_procbased_ctls2::virtualize_x2apic_mode::is_allowed1());
}

TEST_CASE("ia32_vmx_procbased_ctls2_enable_vpid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    auto mask = intel_x64::msrs::ia32_vmx_procbased_ctls2::enable_vpid::mask;

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = mask;
    CHECK(intel_x64::msrs::ia32_vmx_procbased_ctls2::enable_vpid::get());

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = ~mask;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_procbased_ctls2::enable_vpid::get());

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = mask | (mask << 32);
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_procbased_ctls2::enable_vpid::is_allowed0());
    CHECK(intel_x64::msrs::ia32_vmx_procbased_ctls2::enable_vpid::is_allowed1());

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = ~mask & ~(mask << 32);
    CHECK(intel_x64::msrs::ia32_vmx_procbased_ctls2::enable_vpid::is_allowed0());
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_procbased_ctls2::enable_vpid::is_allowed1());
}

TEST_CASE("ia32_vmx_procbased_ctls2_wbinvd_exiting")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    auto mask = intel_x64::msrs::ia32_vmx_procbased_ctls2::wbinvd_exiting::mask;

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = mask;
    CHECK(intel_x64::msrs::ia32_vmx_procbased_ctls2::wbinvd_exiting::get());

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = ~mask;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_procbased_ctls2::wbinvd_exiting::get());

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = mask | (mask << 32);
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_procbased_ctls2::wbinvd_exiting::is_allowed0());
    CHECK(intel_x64::msrs::ia32_vmx_procbased_ctls2::wbinvd_exiting::is_allowed1());

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = ~mask & ~(mask << 32);
    CHECK(intel_x64::msrs::ia32_vmx_procbased_ctls2::wbinvd_exiting::is_allowed0());
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_procbased_ctls2::wbinvd_exiting::is_allowed1());
}

TEST_CASE("ia32_vmx_procbased_ctls2_unrestricted_guest")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    auto mask = intel_x64::msrs::ia32_vmx_procbased_ctls2::unrestricted_guest::mask;

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = mask;
    CHECK(intel_x64::msrs::ia32_vmx_procbased_ctls2::unrestricted_guest::get());

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = ~mask;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_procbased_ctls2::unrestricted_guest::get());

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = mask | (mask << 32);
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_procbased_ctls2::unrestricted_guest::is_allowed0());
    CHECK(intel_x64::msrs::ia32_vmx_procbased_ctls2::unrestricted_guest::is_allowed1());

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = ~mask & ~(mask << 32);
    CHECK(intel_x64::msrs::ia32_vmx_procbased_ctls2::unrestricted_guest::is_allowed0());
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_procbased_ctls2::unrestricted_guest::is_allowed1());
}

TEST_CASE("ia32_vmx_procbased_ctls2_apic_register_virtualization")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    auto mask = intel_x64::msrs::ia32_vmx_procbased_ctls2::apic_register_virtualization::mask;

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = mask;
    CHECK(intel_x64::msrs::ia32_vmx_procbased_ctls2::apic_register_virtualization::get());

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = ~mask;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_procbased_ctls2::apic_register_virtualization::get());

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = mask | (mask << 32);
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_procbased_ctls2::apic_register_virtualization::is_allowed0());
    CHECK(intel_x64::msrs::ia32_vmx_procbased_ctls2::apic_register_virtualization::is_allowed1());

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = ~mask & ~(mask << 32);
    CHECK(intel_x64::msrs::ia32_vmx_procbased_ctls2::apic_register_virtualization::is_allowed0());
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_procbased_ctls2::apic_register_virtualization::is_allowed1());
}

TEST_CASE("ia32_vmx_procbased_ctls2_virtual_interrupt_delivery")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    auto mask = intel_x64::msrs::ia32_vmx_procbased_ctls2::virtual_interrupt_delivery::mask;

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = mask;
    CHECK(intel_x64::msrs::ia32_vmx_procbased_ctls2::virtual_interrupt_delivery::get());

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = ~mask;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_procbased_ctls2::virtual_interrupt_delivery::get());

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = mask | (mask << 32);
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_procbased_ctls2::virtual_interrupt_delivery::is_allowed0());
    CHECK(intel_x64::msrs::ia32_vmx_procbased_ctls2::virtual_interrupt_delivery::is_allowed1());

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = ~mask & ~(mask << 32);
    CHECK(intel_x64::msrs::ia32_vmx_procbased_ctls2::virtual_interrupt_delivery::is_allowed0());
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_procbased_ctls2::virtual_interrupt_delivery::is_allowed1());
}

TEST_CASE("ia32_vmx_procbased_ctls2_pause_loop_exiting")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    auto mask = intel_x64::msrs::ia32_vmx_procbased_ctls2::pause_loop_exiting::mask;

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = mask;
    CHECK(intel_x64::msrs::ia32_vmx_procbased_ctls2::pause_loop_exiting::get());

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = ~mask;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_procbased_ctls2::pause_loop_exiting::get());

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = mask | (mask << 32);
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_procbased_ctls2::pause_loop_exiting::is_allowed0());
    CHECK(intel_x64::msrs::ia32_vmx_procbased_ctls2::pause_loop_exiting::is_allowed1());

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = ~mask & ~(mask << 32);
    CHECK(intel_x64::msrs::ia32_vmx_procbased_ctls2::pause_loop_exiting::is_allowed0());
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_procbased_ctls2::pause_loop_exiting::is_allowed1());
}

TEST_CASE("ia32_vmx_procbased_ctls2_rdrand_exiting")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    auto mask = intel_x64::msrs::ia32_vmx_procbased_ctls2::rdrand_exiting::mask;

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = mask;
    CHECK(intel_x64::msrs::ia32_vmx_procbased_ctls2::rdrand_exiting::get());

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = ~mask;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_procbased_ctls2::rdrand_exiting::get());

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = mask | (mask << 32);
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_procbased_ctls2::rdrand_exiting::is_allowed0());
    CHECK(intel_x64::msrs::ia32_vmx_procbased_ctls2::rdrand_exiting::is_allowed1());

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = ~mask & ~(mask << 32);
    CHECK(intel_x64::msrs::ia32_vmx_procbased_ctls2::rdrand_exiting::is_allowed0());
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_procbased_ctls2::rdrand_exiting::is_allowed1());
}

TEST_CASE("ia32_vmx_procbased_ctls2_enable_invpcid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    auto mask = intel_x64::msrs::ia32_vmx_procbased_ctls2::enable_invpcid::mask;

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = mask;
    CHECK(intel_x64::msrs::ia32_vmx_procbased_ctls2::enable_invpcid::get());

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = ~mask;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_procbased_ctls2::enable_invpcid::get());

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = mask | (mask << 32);
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_procbased_ctls2::enable_invpcid::is_allowed0());
    CHECK(intel_x64::msrs::ia32_vmx_procbased_ctls2::enable_invpcid::is_allowed1());

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = ~mask & ~(mask << 32);
    CHECK(intel_x64::msrs::ia32_vmx_procbased_ctls2::enable_invpcid::is_allowed0());
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_procbased_ctls2::enable_invpcid::is_allowed1());
}

TEST_CASE("ia32_vmx_procbased_ctls2_enable_vm_functions")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    auto mask = intel_x64::msrs::ia32_vmx_procbased_ctls2::enable_vm_functions::mask;

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = mask;
    CHECK(intel_x64::msrs::ia32_vmx_procbased_ctls2::enable_vm_functions::get());

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = ~mask;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_procbased_ctls2::enable_vm_functions::get());

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = mask | (mask << 32);
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_procbased_ctls2::enable_vm_functions::is_allowed0());
    CHECK(intel_x64::msrs::ia32_vmx_procbased_ctls2::enable_vm_functions::is_allowed1());

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = ~mask & ~(mask << 32);
    CHECK(intel_x64::msrs::ia32_vmx_procbased_ctls2::enable_vm_functions::is_allowed0());
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_procbased_ctls2::enable_vm_functions::is_allowed1());
}

TEST_CASE("ia32_vmx_procbased_ctls2_vmcs_shadowing")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    auto mask = intel_x64::msrs::ia32_vmx_procbased_ctls2::vmcs_shadowing::mask;

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = mask;
    CHECK(intel_x64::msrs::ia32_vmx_procbased_ctls2::vmcs_shadowing::get());

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = ~mask;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_procbased_ctls2::vmcs_shadowing::get());

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = mask | (mask << 32);
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_procbased_ctls2::vmcs_shadowing::is_allowed0());
    CHECK(intel_x64::msrs::ia32_vmx_procbased_ctls2::vmcs_shadowing::is_allowed1());

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = ~mask & ~(mask << 32);
    CHECK(intel_x64::msrs::ia32_vmx_procbased_ctls2::vmcs_shadowing::is_allowed0());
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_procbased_ctls2::vmcs_shadowing::is_allowed1());
}

TEST_CASE("ia32_vmx_procbased_ctls2_enable_encls_exiting")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    auto mask = intel_x64::msrs::ia32_vmx_procbased_ctls2::enable_encls_exiting::mask;

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = mask;
    CHECK(intel_x64::msrs::ia32_vmx_procbased_ctls2::enable_encls_exiting::get());

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = ~mask;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_procbased_ctls2::enable_encls_exiting::get());

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = mask | (mask << 32);
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_procbased_ctls2::enable_encls_exiting::is_allowed0());
    CHECK(intel_x64::msrs::ia32_vmx_procbased_ctls2::enable_encls_exiting::is_allowed1());

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = ~mask & ~(mask << 32);
    CHECK(intel_x64::msrs::ia32_vmx_procbased_ctls2::enable_encls_exiting::is_allowed0());
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_procbased_ctls2::enable_encls_exiting::is_allowed1());
}

TEST_CASE("ia32_vmx_procbased_ctls2_rdseed_exiting")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    auto mask = intel_x64::msrs::ia32_vmx_procbased_ctls2::rdseed_exiting::mask;

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = mask;
    CHECK(intel_x64::msrs::ia32_vmx_procbased_ctls2::rdseed_exiting::get());

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = ~mask;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_procbased_ctls2::rdseed_exiting::get());

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = mask | (mask << 32);
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_procbased_ctls2::rdseed_exiting::is_allowed0());
    CHECK(intel_x64::msrs::ia32_vmx_procbased_ctls2::rdseed_exiting::is_allowed1());

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = ~mask & ~(mask << 32);
    CHECK(intel_x64::msrs::ia32_vmx_procbased_ctls2::rdseed_exiting::is_allowed0());
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_procbased_ctls2::rdseed_exiting::is_allowed1());
}

TEST_CASE("ia32_vmx_procbased_ctls2_enable_pml")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    auto mask = intel_x64::msrs::ia32_vmx_procbased_ctls2::enable_pml::mask;

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = mask;
    CHECK(intel_x64::msrs::ia32_vmx_procbased_ctls2::enable_pml::get());

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = ~mask;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_procbased_ctls2::enable_pml::get());

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = mask | (mask << 32);
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_procbased_ctls2::enable_pml::is_allowed0());
    CHECK(intel_x64::msrs::ia32_vmx_procbased_ctls2::enable_pml::is_allowed1());

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = ~mask & ~(mask << 32);
    CHECK(intel_x64::msrs::ia32_vmx_procbased_ctls2::enable_pml::is_allowed0());
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_procbased_ctls2::enable_pml::is_allowed1());
}

TEST_CASE("ia32_vmx_procbased_ctls2_ept_violation_ve")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    auto mask = intel_x64::msrs::ia32_vmx_procbased_ctls2::ept_violation_ve::mask;

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = mask;
    CHECK(intel_x64::msrs::ia32_vmx_procbased_ctls2::ept_violation_ve::get());

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = ~mask;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_procbased_ctls2::ept_violation_ve::get());

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = mask | (mask << 32);
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_procbased_ctls2::ept_violation_ve::is_allowed0());
    CHECK(intel_x64::msrs::ia32_vmx_procbased_ctls2::ept_violation_ve::is_allowed1());

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = ~mask & ~(mask << 32);
    CHECK(intel_x64::msrs::ia32_vmx_procbased_ctls2::ept_violation_ve::is_allowed0());
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_procbased_ctls2::ept_violation_ve::is_allowed1());
}

TEST_CASE("ia32_vmx_procbased_ctls2_pt_conceal_nonroot_operation")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    auto mask = intel_x64::msrs::ia32_vmx_procbased_ctls2::pt_conceal_nonroot_operation::mask;

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = mask;
    CHECK(intel_x64::msrs::ia32_vmx_procbased_ctls2::pt_conceal_nonroot_operation::get());

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = ~mask;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_procbased_ctls2::pt_conceal_nonroot_operation::get());

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = mask | (mask << 32);
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_procbased_ctls2::pt_conceal_nonroot_operation::is_allowed0());
    CHECK(intel_x64::msrs::ia32_vmx_procbased_ctls2::pt_conceal_nonroot_operation::is_allowed1());

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = ~mask & ~(mask << 32);
    CHECK(intel_x64::msrs::ia32_vmx_procbased_ctls2::pt_conceal_nonroot_operation::is_allowed0());
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_procbased_ctls2::pt_conceal_nonroot_operation::is_allowed1());
}

TEST_CASE("ia32_vmx_procbased_ctls2_enable_xsaves_xrstors")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    auto mask = intel_x64::msrs::ia32_vmx_procbased_ctls2::enable_xsaves_xrstors::mask;

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = mask;
    CHECK(intel_x64::msrs::ia32_vmx_procbased_ctls2::enable_xsaves_xrstors::get());

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = ~mask;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_procbased_ctls2::enable_xsaves_xrstors::get());

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = mask | (mask << 32);
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_procbased_ctls2::enable_xsaves_xrstors::is_allowed0());
    CHECK(intel_x64::msrs::ia32_vmx_procbased_ctls2::enable_xsaves_xrstors::is_allowed1());

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = ~mask & ~(mask << 32);
    CHECK(intel_x64::msrs::ia32_vmx_procbased_ctls2::enable_xsaves_xrstors::is_allowed0());
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_procbased_ctls2::enable_xsaves_xrstors::is_allowed1());
}

TEST_CASE("ia32_vmx_procbased_ctls2_ept_mode_based_control")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    auto mask = intel_x64::msrs::ia32_vmx_procbased_ctls2::ept_mode_based_control::mask;

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = mask;
    CHECK(intel_x64::msrs::ia32_vmx_procbased_ctls2::ept_mode_based_control::get());

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = ~mask;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_procbased_ctls2::ept_mode_based_control::get());

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = mask | (mask << 32);
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_procbased_ctls2::ept_mode_based_control::is_allowed0());
    CHECK(intel_x64::msrs::ia32_vmx_procbased_ctls2::ept_mode_based_control::is_allowed1());

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = ~mask & ~(mask << 32);
    CHECK(intel_x64::msrs::ia32_vmx_procbased_ctls2::ept_mode_based_control::is_allowed0());
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_procbased_ctls2::ept_mode_based_control::is_allowed1());
}

TEST_CASE("ia32_vmx_procbased_ctls2_use_tsc_scaling")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    auto mask = intel_x64::msrs::ia32_vmx_procbased_ctls2::use_tsc_scaling::mask;

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = mask;
    CHECK(intel_x64::msrs::ia32_vmx_procbased_ctls2::use_tsc_scaling::get());

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = ~mask;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_procbased_ctls2::use_tsc_scaling::get());

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = mask | (mask << 32);
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_procbased_ctls2::use_tsc_scaling::is_allowed0());
    CHECK(intel_x64::msrs::ia32_vmx_procbased_ctls2::use_tsc_scaling::is_allowed1());

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = ~mask & ~(mask << 32);
    CHECK(intel_x64::msrs::ia32_vmx_procbased_ctls2::use_tsc_scaling::is_allowed0());
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_procbased_ctls2::use_tsc_scaling::is_allowed1());
}

TEST_CASE("ia32_vmx_ept_vpid_cap")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000048CUL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_vmx_ept_vpid_cap::get() == 0xFFFFFFFFFFFFFFFFULL);

    intel_x64::msrs::ia32_vmx_ept_vpid_cap::dump();
}

TEST_CASE("ia32_vmx_ept_vpid_cap_execute_only_translation")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000048CUL] = 0x0000000000000001ULL;
    CHECK(intel_x64::msrs::ia32_vmx_ept_vpid_cap::execute_only_translation::get());

    g_msrs[0x0000048CUL] = 0x0000000000000000ULL;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_ept_vpid_cap::execute_only_translation::get());
}

TEST_CASE("ia32_vmx_ept_vpid_cap_page_walk_length_of_4")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000048CUL] = 0x0000000000000040ULL;
    CHECK(intel_x64::msrs::ia32_vmx_ept_vpid_cap::page_walk_length_of_4::get());

    g_msrs[0x0000048CUL] = 0x0000000000000000ULL;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_ept_vpid_cap::page_walk_length_of_4::get());
}

TEST_CASE("ia32_vmx_ept_vpid_cap_memory_type_uncacheable_supported")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000048CUL] = 0x0000000000000100ULL;
    CHECK(intel_x64::msrs::ia32_vmx_ept_vpid_cap::memory_type_uncacheable_supported::get());

    g_msrs[0x0000048CUL] = 0x0000000000000000ULL;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_ept_vpid_cap::memory_type_uncacheable_supported::get());
}

TEST_CASE("ia32_vmx_ept_vpid_cap_memory_type_write_back_supported")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000048CUL] = 0x0000000000004000ULL;
    CHECK(intel_x64::msrs::ia32_vmx_ept_vpid_cap::memory_type_write_back_supported::get());

    g_msrs[0x0000048CUL] = 0x0000000000000000ULL;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_ept_vpid_cap::memory_type_write_back_supported::get());
}

TEST_CASE("ia32_vmx_ept_vpid_cap_pde_2mb_support")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000048CUL] = 0x0000000000010000ULL;
    CHECK(intel_x64::msrs::ia32_vmx_ept_vpid_cap::pde_2mb_support::get());

    g_msrs[0x0000048CUL] = 0x0000000000000000ULL;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_ept_vpid_cap::pde_2mb_support::get());
}

TEST_CASE("ia32_vmx_ept_vpid_cap_pdpte_1gb_support")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000048CUL] = 0x0000000000020000ULL;
    CHECK(intel_x64::msrs::ia32_vmx_ept_vpid_cap::pdpte_1gb_support::get());

    g_msrs[0x0000048CUL] = 0x0000000000000000ULL;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_ept_vpid_cap::pdpte_1gb_support::get());
}

TEST_CASE("ia32_vmx_ept_vpid_cap_invept_support")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000048CUL] = 0x0000000000100000ULL;
    CHECK(intel_x64::msrs::ia32_vmx_ept_vpid_cap::invept_support::get());

    g_msrs[0x0000048CUL] = 0x0000000000000000ULL;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_ept_vpid_cap::invept_support::get());
}

TEST_CASE("ia32_vmx_ept_vpid_cap_accessed_dirty_support")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000048CUL] = 0x0000000000200000ULL;
    CHECK(intel_x64::msrs::ia32_vmx_ept_vpid_cap::accessed_dirty_support::get());

    g_msrs[0x0000048CUL] = 0x0000000000000000ULL;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_ept_vpid_cap::accessed_dirty_support::get());
}

TEST_CASE("ia32_vmx_ept_vpid_cap_invept_single_context_support")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000048CUL] = 0x0000000002000000ULL;
    CHECK(intel_x64::msrs::ia32_vmx_ept_vpid_cap::invept_single_context_support::get());

    g_msrs[0x0000048CUL] = 0x0000000000000000ULL;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_ept_vpid_cap::invept_single_context_support::get());
}

TEST_CASE("ia32_vmx_ept_vpid_cap_invept_all_context_support")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000048CUL] = 0x0000000004000000ULL;
    CHECK(intel_x64::msrs::ia32_vmx_ept_vpid_cap::invept_all_context_support::get());

    g_msrs[0x0000048CUL] = 0x0000000000000000ULL;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_ept_vpid_cap::invept_all_context_support::get());
}

TEST_CASE("ia32_vmx_ept_vpid_cap_invvpid_support")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000048CUL] = 0x0000000100000000ULL;
    CHECK(intel_x64::msrs::ia32_vmx_ept_vpid_cap::invvpid_support::get());

    g_msrs[0x0000048CUL] = 0x0000000000000000ULL;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_ept_vpid_cap::invvpid_support::get());
}

TEST_CASE("ia32_vmx_ept_vpid_cap_invvpid_individual_address_support")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000048CUL] = 0x0000010000000000ULL;
    CHECK(intel_x64::msrs::ia32_vmx_ept_vpid_cap::invvpid_individual_address_support::get());

    g_msrs[0x0000048CUL] = 0x0000000000000000ULL;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_ept_vpid_cap::invvpid_individual_address_support::get());
}

TEST_CASE("ia32_vmx_ept_vpid_cap_invvpid_single_context_support")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000048CUL] = 0x0000020000000000ULL;
    CHECK(intel_x64::msrs::ia32_vmx_ept_vpid_cap::invvpid_single_context_support::get());

    g_msrs[0x0000048CUL] = 0x0000000000000000ULL;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_ept_vpid_cap::invvpid_single_context_support::get());
}

TEST_CASE("ia32_vmx_ept_vpid_cap_invvpid_all_context_support")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000048CUL] = 0x0000040000000000ULL;
    CHECK(intel_x64::msrs::ia32_vmx_ept_vpid_cap::invvpid_all_context_support::get());

    g_msrs[0x0000048CUL] = 0x0000000000000000ULL;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_ept_vpid_cap::invvpid_all_context_support::get());
}

TEST_CASE("ia32_vmx_ept_vpid_cap_invvpid_single_context_retaining_globals_support")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000048CUL] = 0x0000080000000000ULL;
    CHECK(intel_x64::msrs::ia32_vmx_ept_vpid_cap::invvpid_single_context_retaining_globals_support::get());

    g_msrs[0x0000048CUL] = 0x0000000000000000ULL;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_ept_vpid_cap::invvpid_single_context_retaining_globals_support::get());
}

TEST_CASE("ia32_vmx_true_pinbased_ctls")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[intel_x64::msrs::ia32_vmx_true_pinbased_ctls::addr] = 0x00000000FFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_vmx_true_pinbased_ctls::get() == 0x00000000FFFFFFFFULL);

    intel_x64::msrs::ia32_vmx_true_pinbased_ctls::dump();

    g_msrs[intel_x64::msrs::ia32_vmx_true_pinbased_ctls::addr] = 0x0UL;
    CHECK(intel_x64::msrs::ia32_vmx_true_pinbased_ctls::get() == 0x0UL);

    intel_x64::msrs::ia32_vmx_true_pinbased_ctls::dump();

    g_msrs[intel_x64::msrs::ia32_vmx_true_pinbased_ctls::addr] = 0x00000000FFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_vmx_true_pinbased_ctls::allowed0() == 0xFFFFFFFFUL);
    CHECK(intel_x64::msrs::ia32_vmx_true_pinbased_ctls::allowed1() == 0x00000000UL);

    intel_x64::msrs::ia32_vmx_true_pinbased_ctls::dump();

    g_msrs[intel_x64::msrs::ia32_vmx_true_pinbased_ctls::addr] = 0xFFFFFFFF00000000ULL;
    CHECK(intel_x64::msrs::ia32_vmx_true_pinbased_ctls::allowed0() == 0x00000000UL);
    CHECK(intel_x64::msrs::ia32_vmx_true_pinbased_ctls::allowed1() == 0xFFFFFFFFUL);

    intel_x64::msrs::ia32_vmx_true_pinbased_ctls::dump();
}

TEST_CASE("ia32_vmx_true_pinbased_ctls_external_interrupt_exiting")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    auto mask = intel_x64::msrs::ia32_vmx_true_pinbased_ctls::external_interrupt_exiting::mask;

    g_msrs[intel_x64::msrs::ia32_vmx_true_pinbased_ctls::addr] = mask;
    CHECK(intel_x64::msrs::ia32_vmx_true_pinbased_ctls::external_interrupt_exiting::get());

    g_msrs[intel_x64::msrs::ia32_vmx_true_pinbased_ctls::addr] = ~mask;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_pinbased_ctls::external_interrupt_exiting::get());

    g_msrs[intel_x64::msrs::ia32_vmx_true_pinbased_ctls::addr] = mask | (mask << 32);
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_pinbased_ctls::external_interrupt_exiting::is_allowed0());
    CHECK(intel_x64::msrs::ia32_vmx_true_pinbased_ctls::external_interrupt_exiting::is_allowed1());

    g_msrs[intel_x64::msrs::ia32_vmx_true_pinbased_ctls::addr] = ~mask & ~(mask << 32);
    CHECK(intel_x64::msrs::ia32_vmx_true_pinbased_ctls::external_interrupt_exiting::is_allowed0());
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_pinbased_ctls::external_interrupt_exiting::is_allowed1());
}

TEST_CASE("ia32_vmx_true_pinbased_ctls_nmi_exiting")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    auto mask = intel_x64::msrs::ia32_vmx_true_pinbased_ctls::nmi_exiting::mask;

    g_msrs[intel_x64::msrs::ia32_vmx_true_pinbased_ctls::addr] = mask;
    CHECK(intel_x64::msrs::ia32_vmx_true_pinbased_ctls::nmi_exiting::get());

    g_msrs[intel_x64::msrs::ia32_vmx_true_pinbased_ctls::addr] = ~mask;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_pinbased_ctls::nmi_exiting::get());

    g_msrs[intel_x64::msrs::ia32_vmx_true_pinbased_ctls::addr] = mask | (mask << 32);
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_pinbased_ctls::nmi_exiting::is_allowed0());
    CHECK(intel_x64::msrs::ia32_vmx_true_pinbased_ctls::nmi_exiting::is_allowed1());

    g_msrs[intel_x64::msrs::ia32_vmx_true_pinbased_ctls::addr] = ~mask & ~(mask << 32);
    CHECK(intel_x64::msrs::ia32_vmx_true_pinbased_ctls::nmi_exiting::is_allowed0());
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_pinbased_ctls::nmi_exiting::is_allowed1());
}

TEST_CASE("ia32_vmx_true_pinbased_ctls_virtual_nmis")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    auto mask = intel_x64::msrs::ia32_vmx_true_pinbased_ctls::virtual_nmis::mask;

    g_msrs[intel_x64::msrs::ia32_vmx_true_pinbased_ctls::addr] = mask;
    CHECK(intel_x64::msrs::ia32_vmx_true_pinbased_ctls::virtual_nmis::get());

    g_msrs[intel_x64::msrs::ia32_vmx_true_pinbased_ctls::addr] = ~mask;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_pinbased_ctls::virtual_nmis::get());

    g_msrs[intel_x64::msrs::ia32_vmx_true_pinbased_ctls::addr] = mask | (mask << 32);
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_pinbased_ctls::virtual_nmis::is_allowed0());
    CHECK(intel_x64::msrs::ia32_vmx_true_pinbased_ctls::virtual_nmis::is_allowed1());

    g_msrs[intel_x64::msrs::ia32_vmx_true_pinbased_ctls::addr] = ~mask & ~(mask << 32);
    CHECK(intel_x64::msrs::ia32_vmx_true_pinbased_ctls::virtual_nmis::is_allowed0());
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_pinbased_ctls::virtual_nmis::is_allowed1());
}

TEST_CASE("ia32_vmx_true_pinbased_ctls_activate_vmx_preemption_timer")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    auto mask = intel_x64::msrs::ia32_vmx_true_pinbased_ctls::activate_vmx_preemption_timer::mask;

    g_msrs[intel_x64::msrs::ia32_vmx_true_pinbased_ctls::addr] = mask;
    CHECK(intel_x64::msrs::ia32_vmx_true_pinbased_ctls::activate_vmx_preemption_timer::get());

    g_msrs[intel_x64::msrs::ia32_vmx_true_pinbased_ctls::addr] = ~mask;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_pinbased_ctls::activate_vmx_preemption_timer::get());

    g_msrs[intel_x64::msrs::ia32_vmx_true_pinbased_ctls::addr] = mask | (mask << 32);
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_pinbased_ctls::activate_vmx_preemption_timer::is_allowed0());
    CHECK(intel_x64::msrs::ia32_vmx_true_pinbased_ctls::activate_vmx_preemption_timer::is_allowed1());

    g_msrs[intel_x64::msrs::ia32_vmx_true_pinbased_ctls::addr] = ~mask & ~(mask << 32);
    CHECK(intel_x64::msrs::ia32_vmx_true_pinbased_ctls::activate_vmx_preemption_timer::is_allowed0());
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_pinbased_ctls::activate_vmx_preemption_timer::is_allowed1());
}

TEST_CASE("ia32_vmx_true_pinbased_ctls_process_posted_interrupts")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    auto mask = intel_x64::msrs::ia32_vmx_true_pinbased_ctls::process_posted_interrupts::mask;

    g_msrs[intel_x64::msrs::ia32_vmx_true_pinbased_ctls::addr] = mask;
    CHECK(intel_x64::msrs::ia32_vmx_true_pinbased_ctls::process_posted_interrupts::get());

    g_msrs[intel_x64::msrs::ia32_vmx_true_pinbased_ctls::addr] = ~mask;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_pinbased_ctls::process_posted_interrupts::get());

    g_msrs[intel_x64::msrs::ia32_vmx_true_pinbased_ctls::addr] = mask | (mask << 32);
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_pinbased_ctls::process_posted_interrupts::is_allowed0());
    CHECK(intel_x64::msrs::ia32_vmx_true_pinbased_ctls::process_posted_interrupts::is_allowed1());

    g_msrs[intel_x64::msrs::ia32_vmx_true_pinbased_ctls::addr] = ~mask & ~(mask << 32);
    CHECK(intel_x64::msrs::ia32_vmx_true_pinbased_ctls::process_posted_interrupts::is_allowed0());
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_pinbased_ctls::process_posted_interrupts::is_allowed1());
}

TEST_CASE("ia32_vmx_true_procbased_ctls")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = 0x00000000FFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_vmx_true_procbased_ctls::get() == 0x00000000FFFFFFFFULL);

    intel_x64::msrs::ia32_vmx_true_procbased_ctls::dump();

    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = 0x0UL;
    CHECK(intel_x64::msrs::ia32_vmx_true_procbased_ctls::get() == 0x0UL);

    intel_x64::msrs::ia32_vmx_true_procbased_ctls::dump();

    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = 0x00000000FFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_vmx_true_procbased_ctls::allowed0() == 0xFFFFFFFFUL);
    CHECK(intel_x64::msrs::ia32_vmx_true_procbased_ctls::allowed1() == 0x00000000UL);

    intel_x64::msrs::ia32_vmx_true_procbased_ctls::dump();

    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = 0xFFFFFFFF00000000ULL;
    CHECK(intel_x64::msrs::ia32_vmx_true_procbased_ctls::allowed0() == 0x00000000UL);
    CHECK(intel_x64::msrs::ia32_vmx_true_procbased_ctls::allowed1() == 0xFFFFFFFFUL);

    intel_x64::msrs::ia32_vmx_true_procbased_ctls::dump();
}

TEST_CASE("ia32_vmx_true_procbased_ctls_interrupt_window_exiting")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    auto mask = intel_x64::msrs::ia32_vmx_true_procbased_ctls::interrupt_window_exiting::mask;

    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = mask;
    CHECK(intel_x64::msrs::ia32_vmx_true_procbased_ctls::interrupt_window_exiting::get());

    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = ~mask;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_procbased_ctls::interrupt_window_exiting::get());

    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = mask | (mask << 32);
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_procbased_ctls::interrupt_window_exiting::is_allowed0());
    CHECK(intel_x64::msrs::ia32_vmx_true_procbased_ctls::interrupt_window_exiting::is_allowed1());

    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = ~mask & ~(mask << 32);
    CHECK(intel_x64::msrs::ia32_vmx_true_procbased_ctls::interrupt_window_exiting::is_allowed0());
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_procbased_ctls::interrupt_window_exiting::is_allowed1());
}

TEST_CASE("ia32_vmx_true_procbased_ctls_use_tsc_offsetting")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    auto mask = intel_x64::msrs::ia32_vmx_true_procbased_ctls::use_tsc_offsetting::mask;

    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = mask;
    CHECK(intel_x64::msrs::ia32_vmx_true_procbased_ctls::use_tsc_offsetting::get());

    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = ~mask;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_procbased_ctls::use_tsc_offsetting::get());

    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = mask | (mask << 32);
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_procbased_ctls::use_tsc_offsetting::is_allowed0());
    CHECK(intel_x64::msrs::ia32_vmx_true_procbased_ctls::use_tsc_offsetting::is_allowed1());

    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = ~mask & ~(mask << 32);
    CHECK(intel_x64::msrs::ia32_vmx_true_procbased_ctls::use_tsc_offsetting::is_allowed0());
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_procbased_ctls::use_tsc_offsetting::is_allowed1());
}

TEST_CASE("ia32_vmx_true_procbased_ctls_hlt_exiting")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    auto mask = intel_x64::msrs::ia32_vmx_true_procbased_ctls::hlt_exiting::mask;

    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = mask;
    CHECK(intel_x64::msrs::ia32_vmx_true_procbased_ctls::hlt_exiting::get());

    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = ~mask;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_procbased_ctls::hlt_exiting::get());

    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = mask | (mask << 32);
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_procbased_ctls::hlt_exiting::is_allowed0());
    CHECK(intel_x64::msrs::ia32_vmx_true_procbased_ctls::hlt_exiting::is_allowed1());

    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = ~mask & ~(mask << 32);
    CHECK(intel_x64::msrs::ia32_vmx_true_procbased_ctls::hlt_exiting::is_allowed0());
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_procbased_ctls::hlt_exiting::is_allowed1());
}

TEST_CASE("ia32_vmx_true_procbased_ctls_invlpg_exiting")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    auto mask = intel_x64::msrs::ia32_vmx_true_procbased_ctls::invlpg_exiting::mask;

    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = mask;
    CHECK(intel_x64::msrs::ia32_vmx_true_procbased_ctls::invlpg_exiting::get());

    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = ~mask;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_procbased_ctls::invlpg_exiting::get());

    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = mask | (mask << 32);
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_procbased_ctls::invlpg_exiting::is_allowed0());
    CHECK(intel_x64::msrs::ia32_vmx_true_procbased_ctls::invlpg_exiting::is_allowed1());

    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = ~mask & ~(mask << 32);
    CHECK(intel_x64::msrs::ia32_vmx_true_procbased_ctls::invlpg_exiting::is_allowed0());
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_procbased_ctls::invlpg_exiting::is_allowed1());
}

TEST_CASE("ia32_vmx_true_procbased_ctls_mwait_exiting")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    auto mask = intel_x64::msrs::ia32_vmx_true_procbased_ctls::mwait_exiting::mask;

    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = mask;
    CHECK(intel_x64::msrs::ia32_vmx_true_procbased_ctls::mwait_exiting::get());

    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = ~mask;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_procbased_ctls::mwait_exiting::get());

    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = mask | (mask << 32);
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_procbased_ctls::mwait_exiting::is_allowed0());
    CHECK(intel_x64::msrs::ia32_vmx_true_procbased_ctls::mwait_exiting::is_allowed1());

    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = ~mask & ~(mask << 32);
    CHECK(intel_x64::msrs::ia32_vmx_true_procbased_ctls::mwait_exiting::is_allowed0());
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_procbased_ctls::mwait_exiting::is_allowed1());
}

TEST_CASE("ia32_vmx_true_procbased_ctls_rdpmc_exiting")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    auto mask = intel_x64::msrs::ia32_vmx_true_procbased_ctls::rdpmc_exiting::mask;

    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = mask;
    CHECK(intel_x64::msrs::ia32_vmx_true_procbased_ctls::rdpmc_exiting::get());

    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = ~mask;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_procbased_ctls::rdpmc_exiting::get());

    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = mask | (mask << 32);
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_procbased_ctls::rdpmc_exiting::is_allowed0());
    CHECK(intel_x64::msrs::ia32_vmx_true_procbased_ctls::rdpmc_exiting::is_allowed1());

    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = ~mask & ~(mask << 32);
    CHECK(intel_x64::msrs::ia32_vmx_true_procbased_ctls::rdpmc_exiting::is_allowed0());
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_procbased_ctls::rdpmc_exiting::is_allowed1());
}

TEST_CASE("ia32_vmx_true_procbased_ctls_rdtsc_exiting")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    auto mask = intel_x64::msrs::ia32_vmx_true_procbased_ctls::rdtsc_exiting::mask;

    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = mask;
    CHECK(intel_x64::msrs::ia32_vmx_true_procbased_ctls::rdtsc_exiting::get());

    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = ~mask;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_procbased_ctls::rdtsc_exiting::get());

    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = mask | (mask << 32);
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_procbased_ctls::rdtsc_exiting::is_allowed0());
    CHECK(intel_x64::msrs::ia32_vmx_true_procbased_ctls::rdtsc_exiting::is_allowed1());

    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = ~mask & ~(mask << 32);
    CHECK(intel_x64::msrs::ia32_vmx_true_procbased_ctls::rdtsc_exiting::is_allowed0());
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_procbased_ctls::rdtsc_exiting::is_allowed1());
}

TEST_CASE("ia32_vmx_true_procbased_ctls_cr3_load_exiting")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    auto mask = intel_x64::msrs::ia32_vmx_true_procbased_ctls::cr3_load_exiting::mask;

    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = mask;
    CHECK(intel_x64::msrs::ia32_vmx_true_procbased_ctls::cr3_load_exiting::get());

    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = ~mask;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_procbased_ctls::cr3_load_exiting::get());

    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = mask | (mask << 32);
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_procbased_ctls::cr3_load_exiting::is_allowed0());
    CHECK(intel_x64::msrs::ia32_vmx_true_procbased_ctls::cr3_load_exiting::is_allowed1());

    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = ~mask & ~(mask << 32);
    CHECK(intel_x64::msrs::ia32_vmx_true_procbased_ctls::cr3_load_exiting::is_allowed0());
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_procbased_ctls::cr3_load_exiting::is_allowed1());
}

TEST_CASE("ia32_vmx_true_procbased_ctls_cr3_store_exiting")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    auto mask = intel_x64::msrs::ia32_vmx_true_procbased_ctls::cr3_store_exiting::mask;

    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = mask;
    CHECK(intel_x64::msrs::ia32_vmx_true_procbased_ctls::cr3_store_exiting::get());

    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = ~mask;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_procbased_ctls::cr3_store_exiting::get());

    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = mask | (mask << 32);
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_procbased_ctls::cr3_store_exiting::is_allowed0());
    CHECK(intel_x64::msrs::ia32_vmx_true_procbased_ctls::cr3_store_exiting::is_allowed1());

    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = ~mask & ~(mask << 32);
    CHECK(intel_x64::msrs::ia32_vmx_true_procbased_ctls::cr3_store_exiting::is_allowed0());
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_procbased_ctls::cr3_store_exiting::is_allowed1());
}

TEST_CASE("ia32_vmx_true_procbased_ctls_cr8_load_exiting")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    auto mask = intel_x64::msrs::ia32_vmx_true_procbased_ctls::cr8_load_exiting::mask;

    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = mask;
    CHECK(intel_x64::msrs::ia32_vmx_true_procbased_ctls::cr8_load_exiting::get());

    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = ~mask;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_procbased_ctls::cr8_load_exiting::get());

    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = mask | (mask << 32);
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_procbased_ctls::cr8_load_exiting::is_allowed0());
    CHECK(intel_x64::msrs::ia32_vmx_true_procbased_ctls::cr8_load_exiting::is_allowed1());

    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = ~mask & ~(mask << 32);
    CHECK(intel_x64::msrs::ia32_vmx_true_procbased_ctls::cr8_load_exiting::is_allowed0());
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_procbased_ctls::cr8_load_exiting::is_allowed1());
}

TEST_CASE("ia32_vmx_true_procbased_ctls_cr8_store_exiting")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    auto mask = intel_x64::msrs::ia32_vmx_true_procbased_ctls::cr8_store_exiting::mask;

    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = mask;
    CHECK(intel_x64::msrs::ia32_vmx_true_procbased_ctls::cr8_store_exiting::get());

    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = ~mask;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_procbased_ctls::cr8_store_exiting::get());

    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = mask | (mask << 32);
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_procbased_ctls::cr8_store_exiting::is_allowed0());
    CHECK(intel_x64::msrs::ia32_vmx_true_procbased_ctls::cr8_store_exiting::is_allowed1());

    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = ~mask & ~(mask << 32);
    CHECK(intel_x64::msrs::ia32_vmx_true_procbased_ctls::cr8_store_exiting::is_allowed0());
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_procbased_ctls::cr8_store_exiting::is_allowed1());
}

TEST_CASE("ia32_vmx_true_procbased_ctls_use_tpr_shadow")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    auto mask = intel_x64::msrs::ia32_vmx_true_procbased_ctls::use_tpr_shadow::mask;

    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = mask;
    CHECK(intel_x64::msrs::ia32_vmx_true_procbased_ctls::use_tpr_shadow::get());

    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = ~mask;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_procbased_ctls::use_tpr_shadow::get());

    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = mask | (mask << 32);
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_procbased_ctls::use_tpr_shadow::is_allowed0());
    CHECK(intel_x64::msrs::ia32_vmx_true_procbased_ctls::use_tpr_shadow::is_allowed1());

    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = ~mask & ~(mask << 32);
    CHECK(intel_x64::msrs::ia32_vmx_true_procbased_ctls::use_tpr_shadow::is_allowed0());
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_procbased_ctls::use_tpr_shadow::is_allowed1());
}

TEST_CASE("ia32_vmx_true_procbased_ctls_nmi_window_exiting")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    auto mask = intel_x64::msrs::ia32_vmx_true_procbased_ctls::nmi_window_exiting::mask;

    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = mask;
    CHECK(intel_x64::msrs::ia32_vmx_true_procbased_ctls::nmi_window_exiting::get());

    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = ~mask;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_procbased_ctls::nmi_window_exiting::get());

    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = mask | (mask << 32);
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_procbased_ctls::nmi_window_exiting::is_allowed0());
    CHECK(intel_x64::msrs::ia32_vmx_true_procbased_ctls::nmi_window_exiting::is_allowed1());

    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = ~mask & ~(mask << 32);
    CHECK(intel_x64::msrs::ia32_vmx_true_procbased_ctls::nmi_window_exiting::is_allowed0());
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_procbased_ctls::nmi_window_exiting::is_allowed1());
}

TEST_CASE("ia32_vmx_true_procbased_ctls_mov_dr_exiting")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    auto mask = intel_x64::msrs::ia32_vmx_true_procbased_ctls::mov_dr_exiting::mask;

    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = mask;
    CHECK(intel_x64::msrs::ia32_vmx_true_procbased_ctls::mov_dr_exiting::get());

    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = ~mask;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_procbased_ctls::mov_dr_exiting::get());

    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = mask | (mask << 32);
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_procbased_ctls::mov_dr_exiting::is_allowed0());
    CHECK(intel_x64::msrs::ia32_vmx_true_procbased_ctls::mov_dr_exiting::is_allowed1());

    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = ~mask & ~(mask << 32);
    CHECK(intel_x64::msrs::ia32_vmx_true_procbased_ctls::mov_dr_exiting::is_allowed0());
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_procbased_ctls::mov_dr_exiting::is_allowed1());
}

TEST_CASE("ia32_vmx_true_procbased_ctls_unconditional_io_exiting")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    auto mask = intel_x64::msrs::ia32_vmx_true_procbased_ctls::unconditional_io_exiting::mask;

    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = mask;
    CHECK(intel_x64::msrs::ia32_vmx_true_procbased_ctls::unconditional_io_exiting::get());

    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = ~mask;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_procbased_ctls::unconditional_io_exiting::get());

    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = mask | (mask << 32);
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_procbased_ctls::unconditional_io_exiting::is_allowed0());
    CHECK(intel_x64::msrs::ia32_vmx_true_procbased_ctls::unconditional_io_exiting::is_allowed1());

    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = ~mask & ~(mask << 32);
    CHECK(intel_x64::msrs::ia32_vmx_true_procbased_ctls::unconditional_io_exiting::is_allowed0());
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_procbased_ctls::unconditional_io_exiting::is_allowed1());
}

TEST_CASE("ia32_vmx_true_procbased_ctls_use_io_bitmaps")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    auto mask = intel_x64::msrs::ia32_vmx_true_procbased_ctls::use_io_bitmaps::mask;

    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = mask;
    CHECK(intel_x64::msrs::ia32_vmx_true_procbased_ctls::use_io_bitmaps::get());

    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = ~mask;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_procbased_ctls::use_io_bitmaps::get());

    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = mask | (mask << 32);
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_procbased_ctls::use_io_bitmaps::is_allowed0());
    CHECK(intel_x64::msrs::ia32_vmx_true_procbased_ctls::use_io_bitmaps::is_allowed1());

    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = ~mask & ~(mask << 32);
    CHECK(intel_x64::msrs::ia32_vmx_true_procbased_ctls::use_io_bitmaps::is_allowed0());
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_procbased_ctls::use_io_bitmaps::is_allowed1());
}

TEST_CASE("ia32_vmx_true_procbased_ctls_monitor_trap_flag")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    auto mask = intel_x64::msrs::ia32_vmx_true_procbased_ctls::monitor_trap_flag::mask;

    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = mask;
    CHECK(intel_x64::msrs::ia32_vmx_true_procbased_ctls::monitor_trap_flag::get());

    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = ~mask;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_procbased_ctls::monitor_trap_flag::get());

    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = mask | (mask << 32);
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_procbased_ctls::monitor_trap_flag::is_allowed0());
    CHECK(intel_x64::msrs::ia32_vmx_true_procbased_ctls::monitor_trap_flag::is_allowed1());

    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = ~mask & ~(mask << 32);
    CHECK(intel_x64::msrs::ia32_vmx_true_procbased_ctls::monitor_trap_flag::is_allowed0());
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_procbased_ctls::monitor_trap_flag::is_allowed1());
}

TEST_CASE("ia32_vmx_true_procbased_ctls_use_msr_bitmap")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    auto mask = intel_x64::msrs::ia32_vmx_true_procbased_ctls::use_msr_bitmap::mask;

    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = mask;
    CHECK(intel_x64::msrs::ia32_vmx_true_procbased_ctls::use_msr_bitmap::get());

    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = ~mask;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_procbased_ctls::use_msr_bitmap::get());

    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = mask | (mask << 32);
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_procbased_ctls::use_msr_bitmap::is_allowed0());
    CHECK(intel_x64::msrs::ia32_vmx_true_procbased_ctls::use_msr_bitmap::is_allowed1());

    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = ~mask & ~(mask << 32);
    CHECK(intel_x64::msrs::ia32_vmx_true_procbased_ctls::use_msr_bitmap::is_allowed0());
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_procbased_ctls::use_msr_bitmap::is_allowed1());
}

TEST_CASE("ia32_vmx_true_procbased_ctls_monitor_exiting")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    auto mask = intel_x64::msrs::ia32_vmx_true_procbased_ctls::monitor_exiting::mask;

    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = mask;
    CHECK(intel_x64::msrs::ia32_vmx_true_procbased_ctls::monitor_exiting::get());

    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = ~mask;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_procbased_ctls::monitor_exiting::get());

    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = mask | (mask << 32);
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_procbased_ctls::monitor_exiting::is_allowed0());
    CHECK(intel_x64::msrs::ia32_vmx_true_procbased_ctls::monitor_exiting::is_allowed1());

    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = ~mask & ~(mask << 32);
    CHECK(intel_x64::msrs::ia32_vmx_true_procbased_ctls::monitor_exiting::is_allowed0());
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_procbased_ctls::monitor_exiting::is_allowed1());
}

TEST_CASE("ia32_vmx_true_procbased_ctls_pause_exiting")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    auto mask = intel_x64::msrs::ia32_vmx_true_procbased_ctls::pause_exiting::mask;

    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = mask;
    CHECK(intel_x64::msrs::ia32_vmx_true_procbased_ctls::pause_exiting::get());

    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = ~mask;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_procbased_ctls::pause_exiting::get());

    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = mask | (mask << 32);
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_procbased_ctls::pause_exiting::is_allowed0());
    CHECK(intel_x64::msrs::ia32_vmx_true_procbased_ctls::pause_exiting::is_allowed1());

    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = ~mask & ~(mask << 32);
    CHECK(intel_x64::msrs::ia32_vmx_true_procbased_ctls::pause_exiting::is_allowed0());
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_procbased_ctls::pause_exiting::is_allowed1());
}

TEST_CASE("ia32_vmx_true_procbased_ctls_activate_secondary_controls")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    auto mask = intel_x64::msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask;

    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = mask;
    CHECK(intel_x64::msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::get());

    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = ~mask;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::get());

    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = mask | (mask << 32);
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::is_allowed0());
    CHECK(intel_x64::msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::is_allowed1());

    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = ~mask & ~(mask << 32);
    CHECK(intel_x64::msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::is_allowed0());
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::is_allowed1());
}

TEST_CASE("ia32_vmx_true_exit_ctls")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[intel_x64::msrs::ia32_vmx_true_exit_ctls::addr] = 0x00000000FFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_vmx_true_exit_ctls::get() == 0x00000000FFFFFFFFULL);

    intel_x64::msrs::ia32_vmx_true_exit_ctls::dump();

    g_msrs[intel_x64::msrs::ia32_vmx_true_exit_ctls::addr] = 0x0UL;
    CHECK(intel_x64::msrs::ia32_vmx_true_exit_ctls::get() == 0x0UL);

    intel_x64::msrs::ia32_vmx_true_exit_ctls::dump();

    g_msrs[intel_x64::msrs::ia32_vmx_true_exit_ctls::addr] = 0x00000000FFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_vmx_true_exit_ctls::allowed0() == 0xFFFFFFFFUL);
    CHECK(intel_x64::msrs::ia32_vmx_true_exit_ctls::allowed1() == 0x00000000UL);

    intel_x64::msrs::ia32_vmx_true_exit_ctls::dump();

    g_msrs[intel_x64::msrs::ia32_vmx_true_exit_ctls::addr] = 0xFFFFFFFF00000000ULL;
    CHECK(intel_x64::msrs::ia32_vmx_true_exit_ctls::allowed0() == 0x00000000UL);
    CHECK(intel_x64::msrs::ia32_vmx_true_exit_ctls::allowed1() == 0xFFFFFFFFUL);

    intel_x64::msrs::ia32_vmx_true_exit_ctls::dump();
}

TEST_CASE("ia32_vmx_true_exit_ctls_save_debug_controls")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    auto mask = intel_x64::msrs::ia32_vmx_true_exit_ctls::save_debug_controls::mask;

    g_msrs[intel_x64::msrs::ia32_vmx_true_exit_ctls::addr] = mask;
    CHECK(intel_x64::msrs::ia32_vmx_true_exit_ctls::save_debug_controls::get());

    g_msrs[intel_x64::msrs::ia32_vmx_true_exit_ctls::addr] = ~mask;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_exit_ctls::save_debug_controls::get());

    g_msrs[intel_x64::msrs::ia32_vmx_true_exit_ctls::addr] = mask | (mask << 32);
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_exit_ctls::save_debug_controls::is_allowed0());
    CHECK(intel_x64::msrs::ia32_vmx_true_exit_ctls::save_debug_controls::is_allowed1());

    g_msrs[intel_x64::msrs::ia32_vmx_true_exit_ctls::addr] = ~mask & ~(mask << 32);
    CHECK(intel_x64::msrs::ia32_vmx_true_exit_ctls::save_debug_controls::is_allowed0());
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_exit_ctls::save_debug_controls::is_allowed1());
}

TEST_CASE("ia32_vmx_true_exit_ctls_host_address_space_size")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    auto mask = intel_x64::msrs::ia32_vmx_true_exit_ctls::host_address_space_size::mask;

    g_msrs[intel_x64::msrs::ia32_vmx_true_exit_ctls::addr] = mask;
    CHECK(intel_x64::msrs::ia32_vmx_true_exit_ctls::host_address_space_size::get());

    g_msrs[intel_x64::msrs::ia32_vmx_true_exit_ctls::addr] = ~mask;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_exit_ctls::host_address_space_size::get());

    g_msrs[intel_x64::msrs::ia32_vmx_true_exit_ctls::addr] = mask | (mask << 32);
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_exit_ctls::host_address_space_size::is_allowed0());
    CHECK(intel_x64::msrs::ia32_vmx_true_exit_ctls::host_address_space_size::is_allowed1());

    g_msrs[intel_x64::msrs::ia32_vmx_true_exit_ctls::addr] = ~mask & ~(mask << 32);
    CHECK(intel_x64::msrs::ia32_vmx_true_exit_ctls::host_address_space_size::is_allowed0());
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_exit_ctls::host_address_space_size::is_allowed1());
}

TEST_CASE("ia32_vmx_true_exit_ctls_load_ia32_perf_global_ctrl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    auto mask = intel_x64::msrs::ia32_vmx_true_exit_ctls::load_ia32_perf_global_ctrl::mask;

    g_msrs[intel_x64::msrs::ia32_vmx_true_exit_ctls::addr] = mask;
    CHECK(intel_x64::msrs::ia32_vmx_true_exit_ctls::load_ia32_perf_global_ctrl::get());

    g_msrs[intel_x64::msrs::ia32_vmx_true_exit_ctls::addr] = ~mask;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_exit_ctls::load_ia32_perf_global_ctrl::get());

    g_msrs[intel_x64::msrs::ia32_vmx_true_exit_ctls::addr] = mask | (mask << 32);
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_exit_ctls::load_ia32_perf_global_ctrl::is_allowed0());
    CHECK(intel_x64::msrs::ia32_vmx_true_exit_ctls::load_ia32_perf_global_ctrl::is_allowed1());

    g_msrs[intel_x64::msrs::ia32_vmx_true_exit_ctls::addr] = ~mask & ~(mask << 32);
    CHECK(intel_x64::msrs::ia32_vmx_true_exit_ctls::load_ia32_perf_global_ctrl::is_allowed0());
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_exit_ctls::load_ia32_perf_global_ctrl::is_allowed1());
}

TEST_CASE("ia32_vmx_true_exit_ctls_acknowledge_interrupt_on_exit")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    auto mask = intel_x64::msrs::ia32_vmx_true_exit_ctls::acknowledge_interrupt_on_exit::mask;

    g_msrs[intel_x64::msrs::ia32_vmx_true_exit_ctls::addr] = mask;
    CHECK(intel_x64::msrs::ia32_vmx_true_exit_ctls::acknowledge_interrupt_on_exit::get());

    g_msrs[intel_x64::msrs::ia32_vmx_true_exit_ctls::addr] = ~mask;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_exit_ctls::acknowledge_interrupt_on_exit::get());

    g_msrs[intel_x64::msrs::ia32_vmx_true_exit_ctls::addr] = mask | (mask << 32);
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_exit_ctls::acknowledge_interrupt_on_exit::is_allowed0());
    CHECK(intel_x64::msrs::ia32_vmx_true_exit_ctls::acknowledge_interrupt_on_exit::is_allowed1());

    g_msrs[intel_x64::msrs::ia32_vmx_true_exit_ctls::addr] = ~mask & ~(mask << 32);
    CHECK(intel_x64::msrs::ia32_vmx_true_exit_ctls::acknowledge_interrupt_on_exit::is_allowed0());
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_exit_ctls::acknowledge_interrupt_on_exit::is_allowed1());
}

TEST_CASE("ia32_vmx_true_exit_ctls_save_ia32_pat")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    auto mask = intel_x64::msrs::ia32_vmx_true_exit_ctls::save_ia32_pat::mask;

    g_msrs[intel_x64::msrs::ia32_vmx_true_exit_ctls::addr] = mask;
    CHECK(intel_x64::msrs::ia32_vmx_true_exit_ctls::save_ia32_pat::get());

    g_msrs[intel_x64::msrs::ia32_vmx_true_exit_ctls::addr] = ~mask;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_exit_ctls::save_ia32_pat::get());

    g_msrs[intel_x64::msrs::ia32_vmx_true_exit_ctls::addr] = mask | (mask << 32);
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_exit_ctls::save_ia32_pat::is_allowed0());
    CHECK(intel_x64::msrs::ia32_vmx_true_exit_ctls::save_ia32_pat::is_allowed1());

    g_msrs[intel_x64::msrs::ia32_vmx_true_exit_ctls::addr] = ~mask & ~(mask << 32);
    CHECK(intel_x64::msrs::ia32_vmx_true_exit_ctls::save_ia32_pat::is_allowed0());
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_exit_ctls::save_ia32_pat::is_allowed1());
}

TEST_CASE("ia32_vmx_true_exit_ctls_load_ia32_pat")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    auto mask = intel_x64::msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::mask;

    g_msrs[intel_x64::msrs::ia32_vmx_true_exit_ctls::addr] = mask;
    CHECK(intel_x64::msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::get());

    g_msrs[intel_x64::msrs::ia32_vmx_true_exit_ctls::addr] = ~mask;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::get());

    g_msrs[intel_x64::msrs::ia32_vmx_true_exit_ctls::addr] = mask | (mask << 32);
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::is_allowed0());
    CHECK(intel_x64::msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::is_allowed1());

    g_msrs[intel_x64::msrs::ia32_vmx_true_exit_ctls::addr] = ~mask & ~(mask << 32);
    CHECK(intel_x64::msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::is_allowed0());
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::is_allowed1());
}

TEST_CASE("ia32_vmx_true_exit_ctls_save_ia32_efer")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    auto mask = intel_x64::msrs::ia32_vmx_true_exit_ctls::save_ia32_efer::mask;

    g_msrs[intel_x64::msrs::ia32_vmx_true_exit_ctls::addr] = mask;
    CHECK(intel_x64::msrs::ia32_vmx_true_exit_ctls::save_ia32_efer::get());

    g_msrs[intel_x64::msrs::ia32_vmx_true_exit_ctls::addr] = ~mask;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_exit_ctls::save_ia32_efer::get());

    g_msrs[intel_x64::msrs::ia32_vmx_true_exit_ctls::addr] = mask | (mask << 32);
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_exit_ctls::save_ia32_efer::is_allowed0());
    CHECK(intel_x64::msrs::ia32_vmx_true_exit_ctls::save_ia32_efer::is_allowed1());

    g_msrs[intel_x64::msrs::ia32_vmx_true_exit_ctls::addr] = ~mask & ~(mask << 32);
    CHECK(intel_x64::msrs::ia32_vmx_true_exit_ctls::save_ia32_efer::is_allowed0());
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_exit_ctls::save_ia32_efer::is_allowed1());
}

TEST_CASE("ia32_vmx_true_exit_ctls_load_ia32_efer")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    auto mask = intel_x64::msrs::ia32_vmx_true_exit_ctls::load_ia32_efer::mask;

    g_msrs[intel_x64::msrs::ia32_vmx_true_exit_ctls::addr] = mask;
    CHECK(intel_x64::msrs::ia32_vmx_true_exit_ctls::load_ia32_efer::get());

    g_msrs[intel_x64::msrs::ia32_vmx_true_exit_ctls::addr] = ~mask;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_exit_ctls::load_ia32_efer::get());

    g_msrs[intel_x64::msrs::ia32_vmx_true_exit_ctls::addr] = mask | (mask << 32);
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_exit_ctls::load_ia32_efer::is_allowed0());
    CHECK(intel_x64::msrs::ia32_vmx_true_exit_ctls::load_ia32_efer::is_allowed1());

    g_msrs[intel_x64::msrs::ia32_vmx_true_exit_ctls::addr] = ~mask & ~(mask << 32);
    CHECK(intel_x64::msrs::ia32_vmx_true_exit_ctls::load_ia32_efer::is_allowed0());
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_exit_ctls::load_ia32_efer::is_allowed1());
}

TEST_CASE("ia32_vmx_true_exit_ctls_save_vmx_preemption_timer_value")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    auto mask = intel_x64::msrs::ia32_vmx_true_exit_ctls::save_vmx_preemption_timer_value::mask;

    g_msrs[intel_x64::msrs::ia32_vmx_true_exit_ctls::addr] = mask;
    CHECK(intel_x64::msrs::ia32_vmx_true_exit_ctls::save_vmx_preemption_timer_value::get());

    g_msrs[intel_x64::msrs::ia32_vmx_true_exit_ctls::addr] = ~mask;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_exit_ctls::save_vmx_preemption_timer_value::get());

    g_msrs[intel_x64::msrs::ia32_vmx_true_exit_ctls::addr] = mask | (mask << 32);
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_exit_ctls::save_vmx_preemption_timer_value::is_allowed0());
    CHECK(intel_x64::msrs::ia32_vmx_true_exit_ctls::save_vmx_preemption_timer_value::is_allowed1());

    g_msrs[intel_x64::msrs::ia32_vmx_true_exit_ctls::addr] = ~mask & ~(mask << 32);
    CHECK(intel_x64::msrs::ia32_vmx_true_exit_ctls::save_vmx_preemption_timer_value::is_allowed0());
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_exit_ctls::save_vmx_preemption_timer_value::is_allowed1());
}

TEST_CASE("ia32_vmx_true_exit_ctls_clear_ia32_bndcfgs")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    auto mask = intel_x64::msrs::ia32_vmx_true_exit_ctls::clear_ia32_bndcfgs::mask;

    g_msrs[intel_x64::msrs::ia32_vmx_true_exit_ctls::addr] = mask;
    CHECK(intel_x64::msrs::ia32_vmx_true_exit_ctls::clear_ia32_bndcfgs::get());

    g_msrs[intel_x64::msrs::ia32_vmx_true_exit_ctls::addr] = ~mask;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_exit_ctls::clear_ia32_bndcfgs::get());

    g_msrs[intel_x64::msrs::ia32_vmx_true_exit_ctls::addr] = mask | (mask << 32);
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_exit_ctls::clear_ia32_bndcfgs::is_allowed0());
    CHECK(intel_x64::msrs::ia32_vmx_true_exit_ctls::clear_ia32_bndcfgs::is_allowed1());

    g_msrs[intel_x64::msrs::ia32_vmx_true_exit_ctls::addr] = ~mask & ~(mask << 32);
    CHECK(intel_x64::msrs::ia32_vmx_true_exit_ctls::clear_ia32_bndcfgs::is_allowed0());
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_exit_ctls::clear_ia32_bndcfgs::is_allowed1());
}

TEST_CASE("ia32_vmx_true_entry_ctls")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[intel_x64::msrs::ia32_vmx_true_entry_ctls::addr] = 0x00000000FFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_vmx_true_entry_ctls::get() == 0x00000000FFFFFFFFULL);

    intel_x64::msrs::ia32_vmx_true_entry_ctls::dump();

    g_msrs[intel_x64::msrs::ia32_vmx_true_entry_ctls::addr] = 0x0UL;
    CHECK(intel_x64::msrs::ia32_vmx_true_entry_ctls::get() == 0x0UL);

    intel_x64::msrs::ia32_vmx_true_entry_ctls::dump();

    g_msrs[intel_x64::msrs::ia32_vmx_true_entry_ctls::addr] = 0x00000000FFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_vmx_true_entry_ctls::allowed0() == 0xFFFFFFFFUL);
    CHECK(intel_x64::msrs::ia32_vmx_true_entry_ctls::allowed1() == 0x00000000UL);

    intel_x64::msrs::ia32_vmx_true_entry_ctls::dump();

    g_msrs[intel_x64::msrs::ia32_vmx_true_entry_ctls::addr] = 0xFFFFFFFF00000000ULL;
    CHECK(intel_x64::msrs::ia32_vmx_true_entry_ctls::allowed0() == 0x00000000UL);
    CHECK(intel_x64::msrs::ia32_vmx_true_entry_ctls::allowed1() == 0xFFFFFFFFUL);

    intel_x64::msrs::ia32_vmx_true_entry_ctls::dump();
}

TEST_CASE("ia32_vmx_true_entry_ctls_load_debug_controls")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    auto mask = intel_x64::msrs::ia32_vmx_true_entry_ctls::load_debug_controls::mask;

    g_msrs[intel_x64::msrs::ia32_vmx_true_entry_ctls::addr] = mask;
    CHECK(intel_x64::msrs::ia32_vmx_true_entry_ctls::load_debug_controls::get());

    g_msrs[intel_x64::msrs::ia32_vmx_true_entry_ctls::addr] = ~mask;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_entry_ctls::load_debug_controls::get());

    g_msrs[intel_x64::msrs::ia32_vmx_true_entry_ctls::addr] = mask | (mask << 32);
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_entry_ctls::load_debug_controls::is_allowed0());
    CHECK(intel_x64::msrs::ia32_vmx_true_entry_ctls::load_debug_controls::is_allowed1());

    g_msrs[intel_x64::msrs::ia32_vmx_true_entry_ctls::addr] = ~mask & ~(mask << 32);
    CHECK(intel_x64::msrs::ia32_vmx_true_entry_ctls::load_debug_controls::is_allowed0());
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_entry_ctls::load_debug_controls::is_allowed1());
}

TEST_CASE("ia32_vmx_true_entry_ctls_ia_32e_mode_guest")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    auto mask = intel_x64::msrs::ia32_vmx_true_entry_ctls::ia_32e_mode_guest::mask;

    g_msrs[intel_x64::msrs::ia32_vmx_true_entry_ctls::addr] = mask;
    CHECK(intel_x64::msrs::ia32_vmx_true_entry_ctls::ia_32e_mode_guest::get());

    g_msrs[intel_x64::msrs::ia32_vmx_true_entry_ctls::addr] = ~mask;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_entry_ctls::ia_32e_mode_guest::get());

    g_msrs[intel_x64::msrs::ia32_vmx_true_entry_ctls::addr] = mask | (mask << 32);
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_entry_ctls::ia_32e_mode_guest::is_allowed0());
    CHECK(intel_x64::msrs::ia32_vmx_true_entry_ctls::ia_32e_mode_guest::is_allowed1());

    g_msrs[intel_x64::msrs::ia32_vmx_true_entry_ctls::addr] = ~mask & ~(mask << 32);
    CHECK(intel_x64::msrs::ia32_vmx_true_entry_ctls::ia_32e_mode_guest::is_allowed0());
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_entry_ctls::ia_32e_mode_guest::is_allowed1());
}

TEST_CASE("ia32_vmx_true_entry_ctls_entry_to_smm")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    auto mask = intel_x64::msrs::ia32_vmx_true_entry_ctls::entry_to_smm::mask;

    g_msrs[intel_x64::msrs::ia32_vmx_true_entry_ctls::addr] = mask;
    CHECK(intel_x64::msrs::ia32_vmx_true_entry_ctls::entry_to_smm::get());

    g_msrs[intel_x64::msrs::ia32_vmx_true_entry_ctls::addr] = ~mask;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_entry_ctls::entry_to_smm::get());

    g_msrs[intel_x64::msrs::ia32_vmx_true_entry_ctls::addr] = mask | (mask << 32);
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_entry_ctls::entry_to_smm::is_allowed0());
    CHECK(intel_x64::msrs::ia32_vmx_true_entry_ctls::entry_to_smm::is_allowed1());

    g_msrs[intel_x64::msrs::ia32_vmx_true_entry_ctls::addr] = ~mask & ~(mask << 32);
    CHECK(intel_x64::msrs::ia32_vmx_true_entry_ctls::entry_to_smm::is_allowed0());
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_entry_ctls::entry_to_smm::is_allowed1());
}

TEST_CASE("ia32_vmx_true_entry_ctls_deactivate_dual_monitor_treatment")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    auto mask = intel_x64::msrs::ia32_vmx_true_entry_ctls::deactivate_dual_monitor_treatment::mask;

    g_msrs[intel_x64::msrs::ia32_vmx_true_entry_ctls::addr] = mask;
    CHECK(intel_x64::msrs::ia32_vmx_true_entry_ctls::deactivate_dual_monitor_treatment::get());

    g_msrs[intel_x64::msrs::ia32_vmx_true_entry_ctls::addr] = ~mask;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_entry_ctls::deactivate_dual_monitor_treatment::get());

    g_msrs[intel_x64::msrs::ia32_vmx_true_entry_ctls::addr] = mask | (mask << 32);
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_entry_ctls::deactivate_dual_monitor_treatment::is_allowed0());
    CHECK(intel_x64::msrs::ia32_vmx_true_entry_ctls::deactivate_dual_monitor_treatment::is_allowed1());

    g_msrs[intel_x64::msrs::ia32_vmx_true_entry_ctls::addr] = ~mask & ~(mask << 32);
    CHECK(intel_x64::msrs::ia32_vmx_true_entry_ctls::deactivate_dual_monitor_treatment::is_allowed0());
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_entry_ctls::deactivate_dual_monitor_treatment::is_allowed1());
}

TEST_CASE("ia32_vmx_true_entry_ctls_load_ia32_perf_global_ctrl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    auto mask = intel_x64::msrs::ia32_vmx_true_entry_ctls::load_ia32_perf_global_ctrl::mask;

    g_msrs[intel_x64::msrs::ia32_vmx_true_entry_ctls::addr] = mask;
    CHECK(intel_x64::msrs::ia32_vmx_true_entry_ctls::load_ia32_perf_global_ctrl::get());

    g_msrs[intel_x64::msrs::ia32_vmx_true_entry_ctls::addr] = ~mask;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_entry_ctls::load_ia32_perf_global_ctrl::get());

    g_msrs[intel_x64::msrs::ia32_vmx_true_entry_ctls::addr] = mask | (mask << 32);
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_entry_ctls::load_ia32_perf_global_ctrl::is_allowed0());
    CHECK(intel_x64::msrs::ia32_vmx_true_entry_ctls::load_ia32_perf_global_ctrl::is_allowed1());

    g_msrs[intel_x64::msrs::ia32_vmx_true_entry_ctls::addr] = ~mask & ~(mask << 32);
    CHECK(intel_x64::msrs::ia32_vmx_true_entry_ctls::load_ia32_perf_global_ctrl::is_allowed0());
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_entry_ctls::load_ia32_perf_global_ctrl::is_allowed1());
}

TEST_CASE("ia32_vmx_true_entry_ctls_load_ia32_pat")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    auto mask = intel_x64::msrs::ia32_vmx_true_entry_ctls::load_ia32_pat::mask;

    g_msrs[intel_x64::msrs::ia32_vmx_true_entry_ctls::addr] = mask;
    CHECK(intel_x64::msrs::ia32_vmx_true_entry_ctls::load_ia32_pat::get());

    g_msrs[intel_x64::msrs::ia32_vmx_true_entry_ctls::addr] = ~mask;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_entry_ctls::load_ia32_pat::get());

    g_msrs[intel_x64::msrs::ia32_vmx_true_entry_ctls::addr] = mask | (mask << 32);
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_entry_ctls::load_ia32_pat::is_allowed0());
    CHECK(intel_x64::msrs::ia32_vmx_true_entry_ctls::load_ia32_pat::is_allowed1());

    g_msrs[intel_x64::msrs::ia32_vmx_true_entry_ctls::addr] = ~mask & ~(mask << 32);
    CHECK(intel_x64::msrs::ia32_vmx_true_entry_ctls::load_ia32_pat::is_allowed0());
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_entry_ctls::load_ia32_pat::is_allowed1());
}

TEST_CASE("ia32_vmx_true_entry_ctls_load_ia32_efer")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    auto mask = intel_x64::msrs::ia32_vmx_true_entry_ctls::load_ia32_efer::mask;

    g_msrs[intel_x64::msrs::ia32_vmx_true_entry_ctls::addr] = mask;
    CHECK(intel_x64::msrs::ia32_vmx_true_entry_ctls::load_ia32_efer::get());

    g_msrs[intel_x64::msrs::ia32_vmx_true_entry_ctls::addr] = ~mask;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_entry_ctls::load_ia32_efer::get());

    g_msrs[intel_x64::msrs::ia32_vmx_true_entry_ctls::addr] = mask | (mask << 32);
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_entry_ctls::load_ia32_efer::is_allowed0());
    CHECK(intel_x64::msrs::ia32_vmx_true_entry_ctls::load_ia32_efer::is_allowed1());

    g_msrs[intel_x64::msrs::ia32_vmx_true_entry_ctls::addr] = ~mask & ~(mask << 32);
    CHECK(intel_x64::msrs::ia32_vmx_true_entry_ctls::load_ia32_efer::is_allowed0());
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_entry_ctls::load_ia32_efer::is_allowed1());
}

TEST_CASE("ia32_vmx_true_entry_ctls_load_ia32_bndcfgs")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    auto mask = intel_x64::msrs::ia32_vmx_true_entry_ctls::load_ia32_bndcfgs::mask;

    g_msrs[intel_x64::msrs::ia32_vmx_true_entry_ctls::addr] = mask;
    CHECK(intel_x64::msrs::ia32_vmx_true_entry_ctls::load_ia32_bndcfgs::get());

    g_msrs[intel_x64::msrs::ia32_vmx_true_entry_ctls::addr] = ~mask;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_entry_ctls::load_ia32_bndcfgs::get());

    g_msrs[intel_x64::msrs::ia32_vmx_true_entry_ctls::addr] = mask | (mask << 32);
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_entry_ctls::load_ia32_bndcfgs::is_allowed0());
    CHECK(intel_x64::msrs::ia32_vmx_true_entry_ctls::load_ia32_bndcfgs::is_allowed1());

    g_msrs[intel_x64::msrs::ia32_vmx_true_entry_ctls::addr] = ~mask & ~(mask << 32);
    CHECK(intel_x64::msrs::ia32_vmx_true_entry_ctls::load_ia32_bndcfgs::is_allowed0());
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_true_entry_ctls::load_ia32_bndcfgs::is_allowed1());
}

TEST_CASE("ia32_vmx_vmfunc")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[intel_x64::msrs::ia32_vmx_vmfunc::addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_vmx_vmfunc::get() == 0xFFFFFFFFFFFFFFFFULL);

    g_msrs[intel_x64::msrs::ia32_vmx_vmfunc::addr] = 0x0UL;
    CHECK(intel_x64::msrs::ia32_vmx_vmfunc::get() == 0x0UL);
}

TEST_CASE("ia32_vmx_vmfunc_eptp_switching")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[intel_x64::msrs::ia32_vmx_vmfunc::addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_vmx_vmfunc::eptp_switching::is_allowed1());

    g_msrs[intel_x64::msrs::ia32_vmx_vmfunc::addr] = 0xFFFFFFFFFFFFFFFEULL;
    CHECK_FALSE(intel_x64::msrs::ia32_vmx_vmfunc::eptp_switching::is_allowed1());
}

TEST_CASE("ia32_a_pmc0")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_a_pmc0::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_a_pmc0::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_a_pmc1")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_a_pmc1::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_a_pmc1::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_a_pmc2")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_a_pmc2::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_a_pmc2::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_a_pmc3")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_a_pmc3::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_a_pmc3::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_a_pmc4")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_a_pmc4::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_a_pmc4::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_a_pmc5")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_a_pmc5::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_a_pmc5::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_a_pmc6")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_a_pmc6::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_a_pmc6::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_a_pmc7")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_a_pmc7::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_a_pmc7::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mcg_ext_ctl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mcg_ext_ctl::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_mcg_ext_ctl::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mcg_ext_ctl_lmce_en")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_mcg_ext_ctl::lmce_en::set(true);
    CHECK(intel_x64::msrs::ia32_mcg_ext_ctl::lmce_en::get());

    intel_x64::msrs::ia32_mcg_ext_ctl::lmce_en::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_mcg_ext_ctl::lmce_en::get());
}

TEST_CASE("ia32_sgx_svn_sinit")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000500UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_sgx_svn_sinit::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_sgx_svn_sinit_lock")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000500UL] = 0x0000000000000001ULL;
    CHECK(intel_x64::msrs::ia32_sgx_svn_sinit::lock::get());

    g_msrs[0x00000500UL] = 0x0000000000000000ULL;
    CHECK_FALSE(intel_x64::msrs::ia32_sgx_svn_sinit::lock::get());
}

TEST_CASE("ia32_sgx_svn_sinit_sgx_svn_sinit")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000500UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_sgx_svn_sinit::sgx_svn_sinit::get() == 0x00000000000000FFULL);
}

TEST_CASE("ia32_rtit_output_base")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_rtit_output_base::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_rtit_output_base::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_rtit_output_base_base_phys_address")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_rtit_output_base::base_phys_address::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_rtit_output_base::base_phys_address::get() == 0x00FFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_rtit_output_mask_ptrs")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_rtit_output_mask_ptrs::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_rtit_output_mask_ptrs::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_rtit_output_mask_ptrs_mask_table_offset")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_rtit_output_mask_ptrs::mask_table_offset::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_rtit_output_mask_ptrs::mask_table_offset::get() == 0x0000000001FFFFFFULL);
}

TEST_CASE("ia32_rtit_output_mask_ptrs_output_offset")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_rtit_output_mask_ptrs::output_offset::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_rtit_output_mask_ptrs::output_offset::get() == 0x00000000FFFFFFFFULL);
}

TEST_CASE("ia32_rtit_ctl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_rtit_ctl::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_rtit_ctl::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_rtit_ctl_traceen")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_rtit_ctl::traceen::set(true);
    CHECK(intel_x64::msrs::ia32_rtit_ctl::traceen::get());

    intel_x64::msrs::ia32_rtit_ctl::traceen::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_rtit_ctl::traceen::get());
}

TEST_CASE("ia32_rtit_ctl_cycen")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_rtit_ctl::cycen::set(true);
    CHECK(intel_x64::msrs::ia32_rtit_ctl::cycen::get());

    intel_x64::msrs::ia32_rtit_ctl::cycen::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_rtit_ctl::cycen::get());
}

TEST_CASE("ia32_rtit_ctl_os")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_rtit_ctl::os::set(true);
    CHECK(intel_x64::msrs::ia32_rtit_ctl::os::get());

    intel_x64::msrs::ia32_rtit_ctl::os::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_rtit_ctl::os::get());
}

TEST_CASE("ia32_rtit_ctl_user")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_rtit_ctl::user::set(true);
    CHECK(intel_x64::msrs::ia32_rtit_ctl::user::get());

    intel_x64::msrs::ia32_rtit_ctl::user::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_rtit_ctl::user::get());
}

TEST_CASE("ia32_rtit_ctl_fabricen")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_rtit_ctl::fabricen::set(true);
    CHECK(intel_x64::msrs::ia32_rtit_ctl::fabricen::get());

    intel_x64::msrs::ia32_rtit_ctl::fabricen::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_rtit_ctl::fabricen::get());
}

TEST_CASE("ia32_rtit_ctl_cr3_filter")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_rtit_ctl::cr3_filter::set(true);
    CHECK(intel_x64::msrs::ia32_rtit_ctl::cr3_filter::get());

    intel_x64::msrs::ia32_rtit_ctl::cr3_filter::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_rtit_ctl::cr3_filter::get());
}

TEST_CASE("ia32_rtit_ctl_topa")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_rtit_ctl::topa::set(true);
    CHECK(intel_x64::msrs::ia32_rtit_ctl::topa::get());

    intel_x64::msrs::ia32_rtit_ctl::topa::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_rtit_ctl::topa::get());
}

TEST_CASE("ia32_rtit_ctl_mtcen")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_rtit_ctl::mtcen::set(true);
    CHECK(intel_x64::msrs::ia32_rtit_ctl::mtcen::get());

    intel_x64::msrs::ia32_rtit_ctl::mtcen::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_rtit_ctl::mtcen::get());
}

TEST_CASE("ia32_rtit_ctl_tscen")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_rtit_ctl::tscen::set(true);
    CHECK(intel_x64::msrs::ia32_rtit_ctl::tscen::get());

    intel_x64::msrs::ia32_rtit_ctl::tscen::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_rtit_ctl::tscen::get());
}

TEST_CASE("ia32_rtit_ctl_disretc")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_rtit_ctl::disretc::set(true);
    CHECK(intel_x64::msrs::ia32_rtit_ctl::disretc::get());

    intel_x64::msrs::ia32_rtit_ctl::disretc::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_rtit_ctl::disretc::get());
}

TEST_CASE("ia32_rtit_ctl_branchen")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_rtit_ctl::branchen::set(true);
    CHECK(intel_x64::msrs::ia32_rtit_ctl::branchen::get());

    intel_x64::msrs::ia32_rtit_ctl::branchen::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_rtit_ctl::branchen::get());
}

TEST_CASE("ia32_rtit_ctl_mtcfreq")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_rtit_ctl::mtcfreq::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_rtit_ctl::mtcfreq::get() == 0x000000000000000FULL);
}

TEST_CASE("ia32_rtit_ctl_cycthresh")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_rtit_ctl::cycthresh::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_rtit_ctl::cycthresh::get() == 0x000000000000000FULL);
}

TEST_CASE("ia32_rtit_ctl_psbfreq")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_rtit_ctl::psbfreq::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_rtit_ctl::psbfreq::get() == 0x000000000000000FULL);
}

TEST_CASE("ia32_rtit_ctl_addr0_cfg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_rtit_ctl::addr0_cfg::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_rtit_ctl::addr0_cfg::get() == 0x000000000000000FULL);
}

TEST_CASE("ia32_rtit_ctl_addr1_cfg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_rtit_ctl::addr1_cfg::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_rtit_ctl::addr1_cfg::get() == 0x000000000000000FULL);
}

TEST_CASE("ia32_rtit_ctl_addr2_cfg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_rtit_ctl::addr2_cfg::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_rtit_ctl::addr2_cfg::get() == 0x000000000000000FULL);
}

TEST_CASE("ia32_rtit_ctl_addr3_cfg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_rtit_ctl::addr3_cfg::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_rtit_ctl::addr3_cfg::get() == 0x000000000000000FULL);
}

TEST_CASE("ia32_rtit_status")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_rtit_status::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_rtit_status::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_rtit_status_filteren")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000571UL] = 0x0000000000000001ULL;
    CHECK(intel_x64::msrs::ia32_rtit_status::filteren::get());

    g_msrs[0x00000571UL] = 0x0000000000000000ULL;
    CHECK_FALSE(intel_x64::msrs::ia32_rtit_status::filteren::get());
}

TEST_CASE("ia32_rtit_status_contexen")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000571UL] = 0x0000000000000002ULL;
    CHECK(intel_x64::msrs::ia32_rtit_status::contexen::get());

    g_msrs[0x00000571UL] = 0x0000000000000000ULL;
    CHECK_FALSE(intel_x64::msrs::ia32_rtit_status::contexen::get());
}

TEST_CASE("ia32_rtit_status_triggeren")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000571UL] = 0x0000000000000004ULL;
    CHECK(intel_x64::msrs::ia32_rtit_status::triggeren::get());

    g_msrs[0x00000571UL] = 0x0000000000000000ULL;
    CHECK_FALSE(intel_x64::msrs::ia32_rtit_status::triggeren::get());
}

TEST_CASE("ia32_rtit_status_error")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_rtit_status::error::set(true);
    CHECK(intel_x64::msrs::ia32_rtit_status::error::get());

    intel_x64::msrs::ia32_rtit_status::error::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_rtit_status::error::get());
}

TEST_CASE("ia32_rtit_status_stopped")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_rtit_status::stopped::set(true);
    CHECK(intel_x64::msrs::ia32_rtit_status::stopped::get());

    intel_x64::msrs::ia32_rtit_status::stopped::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_rtit_status::stopped::get());
}

TEST_CASE("ia32_rtit_status_packetbytecnt")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_rtit_status::packetbytecnt::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_rtit_status::packetbytecnt::get() == 0x000000000001FFFFULL);
}

TEST_CASE("ia32_rtit_cr3_match")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_rtit_cr3_match::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_rtit_cr3_match::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_rtit_cr3_match_cr3")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_rtit_cr3_match::cr3::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_rtit_cr3_match::cr3::get() == 0x07FFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_rtit_addr0_a")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_rtit_addr0_a::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_rtit_addr0_a::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_rtit_addr0_a_virtual_address")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_rtit_addr0_a::virtual_address::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_rtit_addr0_a::virtual_address::get() == 0x0000FFFFFFFFFFFFULL);
}

TEST_CASE("ia32_rtit_addr0_a_signext_va")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_rtit_addr0_a::signext_va::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_rtit_addr0_a::signext_va::get() == 0x000000000000FFFFULL);
}

TEST_CASE("ia32_rtit_addr0_b")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_rtit_addr0_b::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_rtit_addr0_b::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_rtit_addr0_b_virtual_address")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_rtit_addr0_b::virtual_address::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_rtit_addr0_b::virtual_address::get() == 0x0000FFFFFFFFFFFFULL);
}

TEST_CASE("ia32_rtit_addr0_b_signext_va")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_rtit_addr0_b::signext_va::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_rtit_addr0_b::signext_va::get() == 0x000000000000FFFFULL);
}

TEST_CASE("ia32_rtit_addr1_a")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_rtit_addr1_a::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_rtit_addr1_a::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_rtit_addr1_a_virtual_address")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_rtit_addr1_a::virtual_address::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_rtit_addr1_a::virtual_address::get() == 0x0000FFFFFFFFFFFFULL);
}

TEST_CASE("ia32_rtit_addr1_a_signext_va")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_rtit_addr1_a::signext_va::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_rtit_addr1_a::signext_va::get() == 0x000000000000FFFFULL);
}

TEST_CASE("ia32_rtit_addr1_b")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_rtit_addr1_b::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_rtit_addr1_b::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_rtit_addr1_b_virtual_address")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_rtit_addr1_b::virtual_address::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_rtit_addr1_b::virtual_address::get() == 0x0000FFFFFFFFFFFFULL);
}

TEST_CASE("ia32_rtit_addr1_b_signext_va")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_rtit_addr1_b::signext_va::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_rtit_addr1_b::signext_va::get() == 0x000000000000FFFFULL);
}

TEST_CASE("ia32_rtit_addr2_a")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_rtit_addr2_a::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_rtit_addr2_a::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_rtit_addr2_a_virtual_address")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_rtit_addr2_a::virtual_address::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_rtit_addr2_a::virtual_address::get() == 0x0000FFFFFFFFFFFFULL);
}

TEST_CASE("ia32_rtit_addr2_a_signext_va")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_rtit_addr2_a::signext_va::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_rtit_addr2_a::signext_va::get() == 0x000000000000FFFFULL);
}

TEST_CASE("ia32_rtit_addr2_b")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_rtit_addr2_b::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_rtit_addr2_b::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_rtit_addr2_b_virtual_address")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_rtit_addr2_b::virtual_address::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_rtit_addr2_b::virtual_address::get() == 0x0000FFFFFFFFFFFFULL);
}

TEST_CASE("ia32_rtit_addr2_b_signext_va")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_rtit_addr2_b::signext_va::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_rtit_addr2_b::signext_va::get() == 0x000000000000FFFFULL);
}

TEST_CASE("ia32_rtit_addr3_a")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_rtit_addr3_a::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_rtit_addr3_a::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_rtit_addr3_a_virtual_address")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_rtit_addr3_a::virtual_address::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_rtit_addr3_a::virtual_address::get() == 0x0000FFFFFFFFFFFFULL);
}

TEST_CASE("ia32_rtit_addr3_a_signext_va")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_rtit_addr3_a::signext_va::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_rtit_addr3_a::signext_va::get() == 0x000000000000FFFFULL);
}

TEST_CASE("ia32_rtit_addr3_b")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_rtit_addr3_b::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_rtit_addr3_b::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_rtit_addr3_b_virtual_address")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_rtit_addr3_b::virtual_address::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_rtit_addr3_b::virtual_address::get() == 0x0000FFFFFFFFFFFFULL);
}

TEST_CASE("ia32_rtit_addr3_b_signext_va")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_rtit_addr3_b::signext_va::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_rtit_addr3_b::signext_va::get() == 0x000000000000FFFFULL);
}

TEST_CASE("ia32_ds_area")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_ds_area::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_ds_area::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_tsc_deadline")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_tsc_deadline::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_tsc_deadline::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_pm_enable")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_pm_enable::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_pm_enable::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_pm_enable_hwp")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_pm_enable::hwp::set(true);
    CHECK(intel_x64::msrs::ia32_pm_enable::hwp::get());

    intel_x64::msrs::ia32_pm_enable::hwp::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_pm_enable::hwp::get());
}

TEST_CASE("ia32_hwp_capabilities")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000771UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_hwp_capabilities::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_hwp_capabilities_highest_perf")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000771UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_hwp_capabilities::highest_perf::get() == 0x00000000000000FFULL);
}

TEST_CASE("ia32_hwp_capabilities_guaranteed_perf")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000771UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_hwp_capabilities::guaranteed_perf::get() == 0x00000000000000FFULL);
}

TEST_CASE("ia32_hwp_capabilities_most_efficient_perf")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000771UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_hwp_capabilities::most_efficient_perf::get() == 0x00000000000000FFULL);
}

TEST_CASE("ia32_hwp_capabilities_lowest_perf")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000771UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_hwp_capabilities::lowest_perf::get() == 0x00000000000000FFULL);
}

TEST_CASE("ia32_hwp_request_pkg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_hwp_request_pkg::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_hwp_request_pkg::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_hwp_request_pkg_min_perf")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_hwp_request_pkg::min_perf::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_hwp_request_pkg::min_perf::get() == 0x00000000000000FFULL);
}

TEST_CASE("ia32_hwp_request_pkg_max_perf")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_hwp_request_pkg::max_perf::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_hwp_request_pkg::max_perf::get() == 0x00000000000000FFULL);
}

TEST_CASE("ia32_hwp_request_pkg_desired_perf")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_hwp_request_pkg::desired_perf::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_hwp_request_pkg::desired_perf::get() == 0x00000000000000FFULL);
}

TEST_CASE("ia32_hwp_request_pkg_energy_perf_pref")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_hwp_request_pkg::energy_perf_pref::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_hwp_request_pkg::energy_perf_pref::get() == 0x00000000000000FFULL);
}

TEST_CASE("ia32_hwp_request_pkg_activity_window")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_hwp_request_pkg::activity_window::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_hwp_request_pkg::activity_window::get() == 0x00000000000003FFULL);
}

TEST_CASE("ia32_hwp_interrupt")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_hwp_interrupt::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_hwp_interrupt::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_hwp_interrupt_perf_change")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_hwp_interrupt::perf_change::set(true);
    CHECK(intel_x64::msrs::ia32_hwp_interrupt::perf_change::get());

    intel_x64::msrs::ia32_hwp_interrupt::perf_change::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_hwp_interrupt::perf_change::get());
}

TEST_CASE("ia32_hwp_interrupt_excursion_min")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_hwp_interrupt::excursion_min::set(true);
    CHECK(intel_x64::msrs::ia32_hwp_interrupt::excursion_min::get());

    intel_x64::msrs::ia32_hwp_interrupt::excursion_min::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_hwp_interrupt::excursion_min::get());
}

TEST_CASE("ia32_hwp_request")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_hwp_request::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_hwp_request::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_hwp_request_min_perf")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_hwp_request::min_perf::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_hwp_request::min_perf::get() == 0x00000000000000FFULL);
}

TEST_CASE("ia32_hwp_request_max_perf")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_hwp_request::max_perf::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_hwp_request::max_perf::get() == 0x00000000000000FFULL);
}

TEST_CASE("ia32_hwp_request_desired_perf")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_hwp_request::desired_perf::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_hwp_request::desired_perf::get() == 0x00000000000000FFULL);
}

TEST_CASE("ia32_hwp_request_energy_perf_pref")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_hwp_request::energy_perf_pref::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_hwp_request::energy_perf_pref::get() == 0x00000000000000FFULL);
}

TEST_CASE("ia32_hwp_request_activity_window")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_hwp_request::activity_window::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_hwp_request::activity_window::get() == 0x00000000000003FFULL);
}

TEST_CASE("ia32_hwp_request_package_control")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_hwp_request::package_control::set(true);
    CHECK(intel_x64::msrs::ia32_hwp_request::package_control::get());

    intel_x64::msrs::ia32_hwp_request::package_control::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_hwp_request::package_control::get());
}

TEST_CASE("ia32_hwp_status")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_hwp_status::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_hwp_status::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_hwp_status_perf_change")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_hwp_status::perf_change::set(true);
    CHECK(intel_x64::msrs::ia32_hwp_status::perf_change::get());

    intel_x64::msrs::ia32_hwp_status::perf_change::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_hwp_status::perf_change::get());
}

TEST_CASE("ia32_hwp_status_excursion_to_min")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_hwp_status::excursion_to_min::set(true);
    CHECK(intel_x64::msrs::ia32_hwp_status::excursion_to_min::get());

    intel_x64::msrs::ia32_hwp_status::excursion_to_min::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_hwp_status::excursion_to_min::get());
}

TEST_CASE("ia32_x2apic_apicid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000802UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_x2apic_apicid::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_x2apic_version")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000803UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_x2apic_version::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_x2apic_tpr")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_x2apic_tpr::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_x2apic_tpr::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_x2apic_ppr")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000080AUL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_x2apic_ppr::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_x2apic_eoi")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_x2apic_eoi::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(g_msrs[0x0000080BUL] == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_x2apic_ldr")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000080DUL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_x2apic_ldr::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_x2apic_sivr")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_x2apic_sivr::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_x2apic_sivr::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_x2apic_isr0")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000810UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_x2apic_isr0::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_x2apic_isr1")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000811UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_x2apic_isr1::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_x2apic_isr2")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000812UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_x2apic_isr2::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_x2apic_isr3")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000813UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_x2apic_isr3::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_x2apic_isr4")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000814UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_x2apic_isr4::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_x2apic_isr5")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000815UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_x2apic_isr5::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_x2apic_isr6")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000816UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_x2apic_isr6::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_x2apic_isr7")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000817UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_x2apic_isr7::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_x2apic_tmr0")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000818UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_x2apic_tmr0::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_x2apic_tmr1")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000819UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_x2apic_tmr1::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_x2apic_tmr2")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000081AUL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_x2apic_tmr2::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_x2apic_tmr3")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000081BUL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_x2apic_tmr3::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_x2apic_tmr4")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000081CUL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_x2apic_tmr4::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_x2apic_tmr5")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000081DUL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_x2apic_tmr5::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_x2apic_tmr6")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000081EUL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_x2apic_tmr6::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_x2apic_tmr7")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000081FUL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_x2apic_tmr7::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_x2apic_irr0")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000820UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_x2apic_irr0::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_x2apic_irr1")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000821UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_x2apic_irr1::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_x2apic_irr2")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000822UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_x2apic_irr2::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_x2apic_irr3")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000823UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_x2apic_irr3::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_x2apic_irr4")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000824UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_x2apic_irr4::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_x2apic_irr5")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000825UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_x2apic_irr5::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_x2apic_irr6")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000826UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_x2apic_irr6::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_x2apic_irr7")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000827UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_x2apic_irr7::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_x2apic_esr")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_x2apic_esr::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_x2apic_esr::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_x2apic_lvt_cmci")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_x2apic_lvt_cmci::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_x2apic_lvt_cmci::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_x2apic_icr")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_x2apic_icr::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_x2apic_icr::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_x2apic_lvt_timer")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_x2apic_lvt_timer::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_x2apic_lvt_timer::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_x2apic_lvt_thermal")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_x2apic_lvt_thermal::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_x2apic_lvt_thermal::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_x2apic_lvt_pmi")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_x2apic_lvt_pmi::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_x2apic_lvt_pmi::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_x2apic_lvt_lint0")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_x2apic_lvt_lint0::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_x2apic_lvt_lint0::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_x2apic_lvt_lint1")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_x2apic_lvt_lint1::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_x2apic_lvt_lint1::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_x2apic_lvt_error")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_x2apic_lvt_error::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_x2apic_lvt_error::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_x2apic_init_count")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_x2apic_init_count::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_x2apic_init_count::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_x2apic_cur_count")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000839UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_x2apic_cur_count::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_x2apic_div_conf")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_x2apic_div_conf::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_x2apic_div_conf::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_x2apic_self_ipi")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_x2apic_self_ipi::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(g_msrs[0x0000083FUL] == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_debug_interface")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_debug_interface::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_debug_interface::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_debug_interface_enable")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_debug_interface::enable::set(true);
    CHECK(intel_x64::msrs::ia32_debug_interface::enable::get());

    intel_x64::msrs::ia32_debug_interface::enable::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_debug_interface::enable::get());
}

TEST_CASE("ia32_debug_interface_lock")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_debug_interface::lock::set(true);
    CHECK(intel_x64::msrs::ia32_debug_interface::lock::get());

    intel_x64::msrs::ia32_debug_interface::lock::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_debug_interface::lock::get());
}

TEST_CASE("ia32_debug_interface_debug_occurred")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_debug_interface::debug_occurred::set(true);
    CHECK(intel_x64::msrs::ia32_debug_interface::debug_occurred::get());

    intel_x64::msrs::ia32_debug_interface::debug_occurred::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_debug_interface::debug_occurred::get());
}

TEST_CASE("ia32_l3_qos_cfg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_l3_qos_cfg::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_l3_qos_cfg::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_l3_qos_cfg_enable")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_l3_qos_cfg::enable::set(true);
    CHECK(intel_x64::msrs::ia32_l3_qos_cfg::enable::get());

    intel_x64::msrs::ia32_l3_qos_cfg::enable::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_l3_qos_cfg::enable::get());
}

TEST_CASE("ia32_qm_evtsel")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_qm_evtsel::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_qm_evtsel::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_qm_evtsel_event_id")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_qm_evtsel::event_id::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_qm_evtsel::event_id::get() == 0x00000000000000FFULL);
}

TEST_CASE("ia32_qm_evtsel_resource_monitoring_id")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_qm_evtsel::resource_monitoring_id::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_qm_evtsel::resource_monitoring_id::get() == 0x00000000FFFFFFFFULL);
}

TEST_CASE("ia32_qm_ctr")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000C8EUL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_qm_ctr::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_qm_ctr_resource_monitored_data")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000C8EUL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_qm_ctr::resource_monitored_data::get() == 0x3FFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_qm_ctr_unavailable")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000C8EUL] = 0x4000000000000000ULL;
    CHECK(intel_x64::msrs::ia32_qm_ctr::unavailable::get());

    g_msrs[0x00000C8EUL] = 0x0000000000000000ULL;
    CHECK_FALSE(intel_x64::msrs::ia32_qm_ctr::unavailable::get());
}

TEST_CASE("ia32_qm_ctr_error")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000C8EUL] = 0x8000000000000000ULL;
    CHECK(intel_x64::msrs::ia32_qm_ctr::error::get());

    g_msrs[0x00000C8EUL] = 0x0000000000000000ULL;
    CHECK_FALSE(intel_x64::msrs::ia32_qm_ctr::error::get());
}

TEST_CASE("ia32_pqr_assoc")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_pqr_assoc::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_pqr_assoc::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_pqr_assoc_resource_monitoring_id")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_pqr_assoc::resource_monitoring_id::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_pqr_assoc::resource_monitoring_id::get() == 0x00000000FFFFFFFFULL);
}

TEST_CASE("ia32_pqr_assoc_cos")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_pqr_assoc::cos::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_pqr_assoc::cos::get() == 0x00000000FFFFFFFFULL);
}

TEST_CASE("ia32_bndcfgs")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_bndcfgs::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_bndcfgs::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_bndcfgs_en")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_bndcfgs::en::set(true);
    CHECK(intel_x64::msrs::ia32_bndcfgs::en::get());

    intel_x64::msrs::ia32_bndcfgs::en::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_bndcfgs::en::get());
}

TEST_CASE("ia32_bndcfgs_bndpreserve")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_bndcfgs::bndpreserve::set(true);
    CHECK(intel_x64::msrs::ia32_bndcfgs::bndpreserve::get());

    intel_x64::msrs::ia32_bndcfgs::bndpreserve::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_bndcfgs::bndpreserve::get());
}

TEST_CASE("ia32_bndcfgs_base_address")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_bndcfgs::base_address::set(true);
    CHECK(intel_x64::msrs::ia32_bndcfgs::base_address::get());

    intel_x64::msrs::ia32_bndcfgs::base_address::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_bndcfgs::base_address::get());
}

TEST_CASE("ia32_xss")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_xss::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_xss::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_xss_trace_packet")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_xss::trace_packet::set(true);
    CHECK(intel_x64::msrs::ia32_xss::trace_packet::get());

    intel_x64::msrs::ia32_xss::trace_packet::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_xss::trace_packet::get());
}

TEST_CASE("ia32_pkg_hdc_ctl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_pkg_hdc_ctl::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_pkg_hdc_ctl::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_pkg_hdc_ctl_hdc_pkg_enable")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_pkg_hdc_ctl::hdc_pkg_enable::set(true);
    CHECK(intel_x64::msrs::ia32_pkg_hdc_ctl::hdc_pkg_enable::get());

    intel_x64::msrs::ia32_pkg_hdc_ctl::hdc_pkg_enable::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_pkg_hdc_ctl::hdc_pkg_enable::get());
}

TEST_CASE("ia32_pm_ctl1")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_pm_ctl1::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_pm_ctl1::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_pm_ctl1_hdc_allow_block")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_pm_ctl1::hdc_allow_block::set(true);
    CHECK(intel_x64::msrs::ia32_pm_ctl1::hdc_allow_block::get());

    intel_x64::msrs::ia32_pm_ctl1::hdc_allow_block::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_pm_ctl1::hdc_allow_block::get());
}

TEST_CASE("ia32_thread_stall")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000DB2UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(intel_x64::msrs::ia32_thread_stall::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_thread_stall_stall_cycle_cnt")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_thread_stall::stall_cycle_cnt::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_thread_stall::stall_cycle_cnt::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_efer")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_efer::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_efer::get() == 0xFFFFFFFFFFFFFFFFULL);

    intel_x64::msrs::ia32_efer::dump();
}

TEST_CASE("ia32_efer_sce")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_efer::sce::set(true);
    CHECK(intel_x64::msrs::ia32_efer::sce::get());

    intel_x64::msrs::ia32_efer::sce::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_efer::sce::get());
}

TEST_CASE("ia32_efer_lme")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_efer::lme::set(true);
    CHECK(intel_x64::msrs::ia32_efer::lme::get());

    intel_x64::msrs::ia32_efer::lme::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_efer::lme::get());
}

TEST_CASE("ia32_efer_lma")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_efer::lma::set(true);
    CHECK(intel_x64::msrs::ia32_efer::lma::get());

    intel_x64::msrs::ia32_efer::lma::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_efer::lma::get());
}

TEST_CASE("ia32_efer_nxe")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_efer::nxe::set(true);
    CHECK(intel_x64::msrs::ia32_efer::nxe::get());

    intel_x64::msrs::ia32_efer::nxe::set(false);
    CHECK_FALSE(intel_x64::msrs::ia32_efer::nxe::get());
}

TEST_CASE("ia32_efer_reserved")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_efer::reserved::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_efer::reserved::get() == 0xFFFFFFFFFFFFF2FEULL);
}

TEST_CASE("ia32_fs_base")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_fs_base::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_fs_base::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_gs_base")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_gs_base::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(intel_x64::msrs::ia32_gs_base::get() == 0xFFFFFFFFFFFFFFFFULL);
}

#endif
