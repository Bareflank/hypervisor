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

#include <catch/catch.hpp>

#include <map>
#include <intrinsics.h>

using namespace x64;

std::map<msrs::field_type, msrs::value_type> g_msrs;

extern "C" uint64_t
_read_msr(uint32_t addr) noexcept
{ return g_msrs[addr]; }

extern "C" void
_write_msr(uint32_t addr, uint64_t val) noexcept
{ g_msrs[addr] = val; }

TEST_CASE("general_msr_access")
{
    intel_x64::msrs::set(0x1UL, 100UL);
    CHECK(intel_x64::msrs::get(gsl::narrow_cast<uint32_t>(0x1UL)) == 100UL);
}

TEST_CASE("ia32_monitor_filter_size")
{
    using namespace intel_x64::msrs::ia32_monitor_filter_size;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_platform_id")
{
    using namespace intel_x64::msrs::ia32_platform_id;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_platform_id_platform_id")
{
    using namespace intel_x64::msrs::ia32_platform_id;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(platform_id::get() == (platform_id::mask >> platform_id::from));
    CHECK(platform_id::get(platform_id::mask) == (platform_id::mask >> platform_id::from));
}

TEST_CASE("ia32_feature_control")
{
    using namespace intel_x64::msrs::ia32_feature_control;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_feature_control_lock_bit")
{
    using namespace intel_x64::msrs::ia32_feature_control;

    lock_bit::enable();
    CHECK(lock_bit::is_enabled());
    lock_bit::disable();
    CHECK(lock_bit::is_disabled());

    lock_bit::enable(lock_bit::mask);
    CHECK(lock_bit::is_enabled(lock_bit::mask));
    lock_bit::disable(0x0);
    CHECK(lock_bit::is_disabled(0x0));
}

TEST_CASE("ia32_feature_control_enable_vmx_inside_smx")
{
    using namespace intel_x64::msrs::ia32_feature_control;

    enable_vmx_inside_smx::enable();
    CHECK(enable_vmx_inside_smx::is_enabled());
    enable_vmx_inside_smx::disable();
    CHECK(enable_vmx_inside_smx::is_disabled());

    enable_vmx_inside_smx::enable(enable_vmx_inside_smx::mask);
    CHECK(enable_vmx_inside_smx::is_enabled(enable_vmx_inside_smx::mask));
    enable_vmx_inside_smx::disable(0x0);
    CHECK(enable_vmx_inside_smx::is_disabled(0x0));
}

TEST_CASE("ia32_feature_control_enable_vmx_outside_smx")
{
    using namespace intel_x64::msrs::ia32_feature_control;

    enable_vmx_outside_smx::enable();
    CHECK(enable_vmx_outside_smx::is_enabled());
    enable_vmx_outside_smx::disable();
    CHECK(enable_vmx_outside_smx::is_disabled());

    enable_vmx_outside_smx::enable(enable_vmx_outside_smx::mask);
    CHECK(enable_vmx_outside_smx::is_enabled(enable_vmx_outside_smx::mask));
    enable_vmx_outside_smx::disable(0x0);
    CHECK(enable_vmx_outside_smx::is_disabled(0x0));
}

TEST_CASE("ia32_feature_control_senter_local_function_enable")
{
    using namespace intel_x64::msrs::ia32_feature_control;

    senter_local_function_enable::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(senter_local_function_enable::get() == (senter_local_function_enable::mask >> senter_local_function_enable::from));

    senter_local_function_enable::set(senter_local_function_enable::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(senter_local_function_enable::get(senter_local_function_enable::mask) == (senter_local_function_enable::mask >> senter_local_function_enable::from));
}

TEST_CASE("ia32_feature_control_senter_global_function_enables")
{
    using namespace intel_x64::msrs::ia32_feature_control;

    senter_global_function_enables::enable();
    CHECK(senter_global_function_enables::is_enabled());
    senter_global_function_enables::disable();
    CHECK(senter_global_function_enables::is_disabled());

    senter_global_function_enables::enable(senter_global_function_enables::mask);
    CHECK(senter_global_function_enables::is_enabled(senter_global_function_enables::mask));
    senter_global_function_enables::disable(0x0);
    CHECK(senter_global_function_enables::is_disabled(0x0));
}

TEST_CASE("ia32_feature_control_sgx_launch_control_enable")
{
    using namespace intel_x64::msrs::ia32_feature_control;

    sgx_launch_control_enable::enable();
    CHECK(sgx_launch_control_enable::is_enabled());
    sgx_launch_control_enable::disable();
    CHECK(sgx_launch_control_enable::is_disabled());

    sgx_launch_control_enable::enable(sgx_launch_control_enable::mask);
    CHECK(sgx_launch_control_enable::is_enabled(sgx_launch_control_enable::mask));
    sgx_launch_control_enable::disable(0x0);
    CHECK(sgx_launch_control_enable::is_disabled(0x0));
}

TEST_CASE("ia32_feature_control_sgx_global_enable")
{
    using namespace intel_x64::msrs::ia32_feature_control;

    sgx_global_enable::enable();
    CHECK(sgx_global_enable::is_enabled());
    sgx_global_enable::disable();
    CHECK(sgx_global_enable::is_disabled());

    sgx_global_enable::enable(sgx_global_enable::mask);
    CHECK(sgx_global_enable::is_enabled(sgx_global_enable::mask));
    sgx_global_enable::disable(0x0);
    CHECK(sgx_global_enable::is_disabled(0x0));
}

TEST_CASE("ia32_feature_control_lmce")
{
    using namespace intel_x64::msrs::ia32_feature_control;

    lmce::enable();
    CHECK(lmce::is_enabled());
    lmce::disable();
    CHECK(lmce::is_disabled());

    lmce::enable(lmce::mask);
    CHECK(lmce::is_enabled(lmce::mask));
    lmce::disable(0x0);
    CHECK(lmce::is_disabled(0x0));
}

TEST_CASE("ia32_tsc_adjust")
{
    using namespace intel_x64::msrs::ia32_tsc_adjust;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_tsc_adjust_thread_adjust")
{
    using namespace intel_x64::msrs::ia32_tsc_adjust;

    thread_adjust::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(thread_adjust::get() == (thread_adjust::mask >> thread_adjust::from));

    thread_adjust::set(thread_adjust::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(thread_adjust::get(thread_adjust::mask) == (thread_adjust::mask >> thread_adjust::from));
}

TEST_CASE("ia32_bios_updt_trig")
{
    using namespace intel_x64::msrs::ia32_bios_updt_trig;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(g_msrs[addr] == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_bios_sign_id")
{
    using namespace intel_x64::msrs::ia32_bios_sign_id;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_bios_sign_id_bios_sign_id")
{
    using namespace intel_x64::msrs::ia32_bios_sign_id;

    bios_sign_id::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(bios_sign_id::get() == (bios_sign_id::mask >> bios_sign_id::from));

    bios_sign_id::set(bios_sign_id::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(bios_sign_id::get(bios_sign_id::mask) == (bios_sign_id::mask >> bios_sign_id::from));
}

TEST_CASE("ia32_sgxlepubkeyhash0")
{
    using namespace intel_x64::msrs::ia32_sgxlepubkeyhash0;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_sgxlepubkeyhash1")
{
    using namespace intel_x64::msrs::ia32_sgxlepubkeyhash1;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_sgxlepubkeyhash2")
{
    using namespace intel_x64::msrs::ia32_sgxlepubkeyhash2;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_sgxlepubkeyhash3")
{
    using namespace intel_x64::msrs::ia32_sgxlepubkeyhash3;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_smm_monitor_ctl")
{
    using namespace intel_x64::msrs::ia32_smm_monitor_ctl;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_smm_monitor_ctl_valid")
{
    using namespace intel_x64::msrs::ia32_smm_monitor_ctl;

    valid::enable();
    CHECK(valid::is_enabled());
    valid::disable();
    CHECK(valid::is_disabled());

    valid::enable(valid::mask);
    CHECK(valid::is_enabled(valid::mask));
    valid::disable(0x0);
    CHECK(valid::is_disabled(0x0));
}

TEST_CASE("ia32_smm_monitor_ctl_vmxoff")
{
    using namespace intel_x64::msrs::ia32_smm_monitor_ctl;

    vmxoff::enable();
    CHECK(vmxoff::is_enabled());
    vmxoff::disable();
    CHECK(vmxoff::is_disabled());

    vmxoff::enable(vmxoff::mask);
    CHECK(vmxoff::is_enabled(vmxoff::mask));
    vmxoff::disable(0x0);
    CHECK(vmxoff::is_disabled(0x0));
}

TEST_CASE("ia32_smm_monitor_ctl_mseg_base")
{
    using namespace intel_x64::msrs::ia32_smm_monitor_ctl;

    mseg_base::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(mseg_base::get() == (mseg_base::mask >> mseg_base::from));

    mseg_base::set(mseg_base::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(mseg_base::get(mseg_base::mask) == (mseg_base::mask >> mseg_base::from));
}

TEST_CASE("ia32_smbase")
{
    using namespace intel_x64::msrs::ia32_smbase;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_pmc0")
{
    using namespace intel_x64::msrs::ia32_pmc0;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_pmc1")
{
    using namespace intel_x64::msrs::ia32_pmc1;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_pmc2")
{
    using namespace intel_x64::msrs::ia32_pmc2;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_pmc3")
{
    using namespace intel_x64::msrs::ia32_pmc3;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_pmc4")
{
    using namespace intel_x64::msrs::ia32_pmc4;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_pmc5")
{
    using namespace intel_x64::msrs::ia32_pmc5;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_pmc6")
{
    using namespace intel_x64::msrs::ia32_pmc6;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_pmc7")
{
    using namespace intel_x64::msrs::ia32_pmc7;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_sysenter_cs")
{
    using namespace intel_x64::msrs::ia32_sysenter_cs;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_sysenter_esp")
{
    using namespace intel_x64::msrs::ia32_sysenter_esp;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_sysenter_eip")
{
    using namespace intel_x64::msrs::ia32_sysenter_eip;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_perfevtsel0")
{
    using namespace intel_x64::msrs::ia32_perfevtsel0;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_perfevtsel0_event_select")
{
    using namespace intel_x64::msrs::ia32_perfevtsel0;

    event_select::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(event_select::get() == (event_select::mask >> event_select::from));

    event_select::set(event_select::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(event_select::get(event_select::mask) == (event_select::mask >> event_select::from));
}

TEST_CASE("ia32_perfevtsel0_umask")
{
    using namespace intel_x64::msrs::ia32_perfevtsel0;

    umask::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(umask::get() == (umask::mask >> umask::from));

    umask::set(umask::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(umask::get(umask::mask) == (umask::mask >> umask::from));
}

TEST_CASE("ia32_perfevtsel0_usr")
{
    using namespace intel_x64::msrs::ia32_perfevtsel0;

    usr::enable();
    CHECK(usr::is_enabled());
    usr::disable();
    CHECK(usr::is_disabled());

    usr::enable(usr::mask);
    CHECK(usr::is_enabled(usr::mask));
    usr::disable(0x0);
    CHECK(usr::is_disabled(0x0));
}

TEST_CASE("ia32_perfevtsel0_os")
{
    using namespace intel_x64::msrs::ia32_perfevtsel0;

    os::enable();
    CHECK(os::is_enabled());
    os::disable();
    CHECK(os::is_disabled());

    os::enable(os::mask);
    CHECK(os::is_enabled(os::mask));
    os::disable(0x0);
    CHECK(os::is_disabled(0x0));
}

TEST_CASE("ia32_perfevtsel0_edge")
{
    using namespace intel_x64::msrs::ia32_perfevtsel0;

    edge::enable();
    CHECK(edge::is_enabled());
    edge::disable();
    CHECK(edge::is_disabled());

    edge::enable(edge::mask);
    CHECK(edge::is_enabled(edge::mask));
    edge::disable(0x0);
    CHECK(edge::is_disabled(0x0));
}

TEST_CASE("ia32_perfevtsel0_pc")
{
    using namespace intel_x64::msrs::ia32_perfevtsel0;

    pc::enable();
    CHECK(pc::is_enabled());
    pc::disable();
    CHECK(pc::is_disabled());

    pc::enable(pc::mask);
    CHECK(pc::is_enabled(pc::mask));
    pc::disable(0x0);
    CHECK(pc::is_disabled(0x0));
}

TEST_CASE("ia32_perfevtsel0_interrupt")
{
    using namespace intel_x64::msrs;

    ia32_perfevtsel0::interrupt::enable();
    CHECK(ia32_perfevtsel0::interrupt::is_enabled());
    ia32_perfevtsel0::interrupt::disable();
    CHECK(ia32_perfevtsel0::interrupt::is_disabled());

    ia32_perfevtsel0::interrupt::enable(ia32_perfevtsel0::interrupt::mask);
    CHECK(ia32_perfevtsel0::interrupt::is_enabled(ia32_perfevtsel0::interrupt::mask));
    ia32_perfevtsel0::interrupt::disable(0x0);
    CHECK(ia32_perfevtsel0::interrupt::is_disabled(0x0));
}

TEST_CASE("ia32_perfevtsel0_anythread")
{
    using namespace intel_x64::msrs::ia32_perfevtsel0;

    anythread::enable();
    CHECK(anythread::is_enabled());
    anythread::disable();
    CHECK(anythread::is_disabled());

    anythread::enable(anythread::mask);
    CHECK(anythread::is_enabled(anythread::mask));
    anythread::disable(0x0);
    CHECK(anythread::is_disabled(0x0));
}

TEST_CASE("ia32_perfevtsel0_en")
{
    using namespace intel_x64::msrs::ia32_perfevtsel0;

    en::enable();
    CHECK(en::is_enabled());
    en::disable();
    CHECK(en::is_disabled());

    en::enable(en::mask);
    CHECK(en::is_enabled(en::mask));
    en::disable(0x0);
    CHECK(en::is_disabled(0x0));
}

TEST_CASE("ia32_perfevtsel0_inv")
{
    using namespace intel_x64::msrs::ia32_perfevtsel0;

    inv::enable();
    CHECK(inv::is_enabled());
    inv::disable();
    CHECK(inv::is_disabled());

    inv::enable(inv::mask);
    CHECK(inv::is_enabled(inv::mask));
    inv::disable(0x0);
    CHECK(inv::is_disabled(0x0));
}

TEST_CASE("ia32_perfevtsel0_cmask")
{
    using namespace intel_x64::msrs::ia32_perfevtsel0;

    cmask::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(cmask::get() == (cmask::mask >> cmask::from));

    cmask::set(cmask::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(cmask::get(cmask::mask) == (cmask::mask >> cmask::from));
}

TEST_CASE("ia32_perfevtsel1")
{
    using namespace intel_x64::msrs::ia32_perfevtsel1;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_perfevtsel2")
{
    using namespace intel_x64::msrs::ia32_perfevtsel2;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_perfevtsel3")
{
    using namespace intel_x64::msrs::ia32_perfevtsel3;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_perf_status")
{
    using namespace intel_x64::msrs::ia32_perf_status;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_perf_status_state_value")
{
    using namespace intel_x64::msrs::ia32_perf_status;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(state_value::get() == (state_value::mask >> state_value::from));
    CHECK(state_value::get(state_value::mask) == (state_value::mask >> state_value::from));
}

TEST_CASE("ia32_perf_ctl")
{
    using namespace intel_x64::msrs::ia32_perf_ctl;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_perf_ctl_state_value")
{
    using namespace intel_x64::msrs::ia32_perf_ctl;

    state_value::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(state_value::get() == (state_value::mask >> state_value::from));

    state_value::set(state_value::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(state_value::get(state_value::mask) == (state_value::mask >> state_value::from));
}

TEST_CASE("ia32_perf_ctl_ida_engage")
{
    using namespace intel_x64::msrs::ia32_perf_ctl;

    ida_engage::enable();
    CHECK(ida_engage::is_enabled());
    ida_engage::disable();
    CHECK(ida_engage::is_disabled());

    ida_engage::enable(ida_engage::mask);
    CHECK(ida_engage::is_enabled(ida_engage::mask));
    ida_engage::disable(0x0);
    CHECK(ida_engage::is_disabled(0x0));
}

TEST_CASE("ia32_clock_modulation")
{
    using namespace intel_x64::msrs::ia32_clock_modulation;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_clock_modulation_ext_duty_cycle")
{
    using namespace intel_x64::msrs::ia32_clock_modulation;

    ext_duty_cycle::enable();
    CHECK(ext_duty_cycle::is_enabled());
    ext_duty_cycle::disable();
    CHECK(ext_duty_cycle::is_disabled());

    ext_duty_cycle::enable(ext_duty_cycle::mask);
    CHECK(ext_duty_cycle::is_enabled(ext_duty_cycle::mask));
    ext_duty_cycle::disable(0x0);
    CHECK(ext_duty_cycle::is_disabled(0x0));
}

TEST_CASE("ia32_clock_modulation_duty_cycle_values")
{
    using namespace intel_x64::msrs::ia32_clock_modulation;

    duty_cycle_values::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(duty_cycle_values::get() == (duty_cycle_values::mask >> duty_cycle_values::from));

    duty_cycle_values::set(duty_cycle_values::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(duty_cycle_values::get(duty_cycle_values::mask) == (duty_cycle_values::mask >> duty_cycle_values::from));
}

TEST_CASE("ia32_clock_modulation_enable_modulation")
{
    using namespace intel_x64::msrs::ia32_clock_modulation;

    enable_modulation::enable();
    CHECK(enable_modulation::is_enabled());
    enable_modulation::disable();
    CHECK(enable_modulation::is_disabled());

    enable_modulation::enable(enable_modulation::mask);
    CHECK(enable_modulation::is_enabled(enable_modulation::mask));
    enable_modulation::disable(0x0);
    CHECK(enable_modulation::is_disabled(0x0));
}

TEST_CASE("ia32_therm_interrupt")
{
    using namespace intel_x64::msrs::ia32_therm_interrupt;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_therm_interrupt_high_temp")
{
    using namespace intel_x64::msrs::ia32_therm_interrupt;

    high_temp::enable();
    CHECK(high_temp::is_enabled());
    high_temp::disable();
    CHECK(high_temp::is_disabled());

    high_temp::enable(high_temp::mask);
    CHECK(high_temp::is_enabled(high_temp::mask));
    high_temp::disable(0x0);
    CHECK(high_temp::is_disabled(0x0));
}

TEST_CASE("ia32_therm_interrupt_low_temp")
{
    using namespace intel_x64::msrs::ia32_therm_interrupt;

    low_temp::enable();
    CHECK(low_temp::is_enabled());
    low_temp::disable();
    CHECK(low_temp::is_disabled());

    low_temp::enable(low_temp::mask);
    CHECK(low_temp::is_enabled(low_temp::mask));
    low_temp::disable(0x0);
    CHECK(low_temp::is_disabled(0x0));
}

TEST_CASE("ia32_therm_interrupt_prochot")
{
    using namespace intel_x64::msrs::ia32_therm_interrupt;

    prochot::enable();
    CHECK(prochot::is_enabled());
    prochot::disable();
    CHECK(prochot::is_disabled());

    prochot::enable(prochot::mask);
    CHECK(prochot::is_enabled(prochot::mask));
    prochot::disable(0x0);
    CHECK(prochot::is_disabled(0x0));
}

TEST_CASE("ia32_therm_interrupt_forcepr")
{
    using namespace intel_x64::msrs::ia32_therm_interrupt;

    forcepr::enable();
    CHECK(forcepr::is_enabled());
    forcepr::disable();
    CHECK(forcepr::is_disabled());

    forcepr::enable(forcepr::mask);
    CHECK(forcepr::is_enabled(forcepr::mask));
    forcepr::disable(0x0);
    CHECK(forcepr::is_disabled(0x0));
}

TEST_CASE("ia32_therm_interrupt_crit_temp")
{
    using namespace intel_x64::msrs::ia32_therm_interrupt;

    crit_temp::enable();
    CHECK(crit_temp::is_enabled());
    crit_temp::disable();
    CHECK(crit_temp::is_disabled());

    crit_temp::enable(crit_temp::mask);
    CHECK(crit_temp::is_enabled(crit_temp::mask));
    crit_temp::disable(0x0);
    CHECK(crit_temp::is_disabled(0x0));
}

TEST_CASE("ia32_therm_interrupt_threshold_1_enable")
{
    using namespace intel_x64::msrs::ia32_therm_interrupt;

    threshold_1_enable::enable();
    CHECK(threshold_1_enable::is_enabled());
    threshold_1_enable::disable();
    CHECK(threshold_1_enable::is_disabled());

    threshold_1_enable::enable(threshold_1_enable::mask);
    CHECK(threshold_1_enable::is_enabled(threshold_1_enable::mask));
    threshold_1_enable::disable(0x0);
    CHECK(threshold_1_enable::is_disabled(0x0));
}

TEST_CASE("ia32_therm_interrupt_threshold_1_value")
{
    using namespace intel_x64::msrs::ia32_therm_interrupt;

    threshold_1_value::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(threshold_1_value::get() == (threshold_1_value::mask >> threshold_1_value::from));

    threshold_1_value::set(threshold_1_value::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(threshold_1_value::get(threshold_1_value::mask) == (threshold_1_value::mask >> threshold_1_value::from));
}

TEST_CASE("ia32_therm_interrupt_threshold_2_enable")
{
    using namespace intel_x64::msrs::ia32_therm_interrupt;

    threshold_2_enable::enable();
    CHECK(threshold_2_enable::is_enabled());
    threshold_2_enable::disable();
    CHECK(threshold_2_enable::is_disabled());

    threshold_2_enable::enable(threshold_2_enable::mask);
    CHECK(threshold_2_enable::is_enabled(threshold_2_enable::mask));
    threshold_2_enable::disable(0x0);
    CHECK(threshold_2_enable::is_disabled(0x0));
}

TEST_CASE("ia32_therm_interrupt_threshold_2_value")
{
    using namespace intel_x64::msrs::ia32_therm_interrupt;

    threshold_2_value::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(threshold_2_value::get() == (threshold_2_value::mask >> threshold_2_value::from));

    threshold_2_value::set(threshold_2_value::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(threshold_2_value::get(threshold_2_value::mask) == (threshold_2_value::mask >> threshold_2_value::from));
}

TEST_CASE("ia32_therm_interrupt_power_limit")
{
    using namespace intel_x64::msrs::ia32_therm_interrupt;

    power_limit::enable();
    CHECK(power_limit::is_enabled());
    power_limit::disable();
    CHECK(power_limit::is_disabled());

    power_limit::enable(power_limit::mask);
    CHECK(power_limit::is_enabled(power_limit::mask));
    power_limit::disable(0x0);
    CHECK(power_limit::is_disabled(0x0));
}

TEST_CASE("ia32_therm_status")
{
    using namespace intel_x64::msrs::ia32_therm_status;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_therm_status_therm_status")
{
    using namespace intel_x64::msrs::ia32_therm_status;

    g_msrs[addr] = therm_status::mask;
    CHECK(therm_status::is_enabled());
    g_msrs[addr] = 0x0;
    CHECK(therm_status::is_disabled());

    g_msrs[addr] = therm_status::mask;
    CHECK(therm_status::is_enabled(therm_status::mask));
    g_msrs[addr] = 0x0;
    CHECK(therm_status::is_disabled(0x0));
}

TEST_CASE("ia32_therm_status_thermal_status_log")
{
    using namespace intel_x64::msrs::ia32_therm_status;

    thermal_status_log::enable();
    CHECK(thermal_status_log::is_enabled());
    thermal_status_log::disable();
    CHECK(thermal_status_log::is_disabled());

    thermal_status_log::enable(thermal_status_log::mask);
    CHECK(thermal_status_log::is_enabled(thermal_status_log::mask));
    thermal_status_log::disable(0x0);
    CHECK(thermal_status_log::is_disabled(0x0));
}

TEST_CASE("ia32_therm_status_forcepr_event")
{
    using namespace intel_x64::msrs::ia32_therm_status;

    g_msrs[addr] = forcepr_event::mask;
    CHECK(forcepr_event::is_enabled());
    g_msrs[addr] = 0x0;
    CHECK(forcepr_event::is_disabled());

    g_msrs[addr] = forcepr_event::mask;
    CHECK(forcepr_event::is_enabled(forcepr_event::mask));
    g_msrs[addr] = 0x0;
    CHECK(forcepr_event::is_disabled(0x0));
}

TEST_CASE("ia32_therm_status_forcepr_log")
{
    using namespace intel_x64::msrs::ia32_therm_status;

    forcepr_log::enable();
    CHECK(forcepr_log::is_enabled());
    forcepr_log::disable();
    CHECK(forcepr_log::is_disabled());

    forcepr_log::enable(forcepr_log::mask);
    CHECK(forcepr_log::is_enabled(forcepr_log::mask));
    forcepr_log::disable(0x0);
    CHECK(forcepr_log::is_disabled(0x0));
}

TEST_CASE("ia32_therm_status_crit_temp_status")
{
    using namespace intel_x64::msrs::ia32_therm_status;

    g_msrs[addr] = crit_temp_status::mask;
    CHECK(crit_temp_status::is_enabled());
    g_msrs[addr] = 0x0;
    CHECK(crit_temp_status::is_disabled());

    g_msrs[addr] = crit_temp_status::mask;
    CHECK(crit_temp_status::is_enabled(crit_temp_status::mask));
    g_msrs[addr] = 0x0;
    CHECK(crit_temp_status::is_disabled(0x0));
}

TEST_CASE("ia32_therm_status_crit_temp_log")
{
    using namespace intel_x64::msrs::ia32_therm_status;

    crit_temp_log::enable();
    CHECK(crit_temp_log::is_enabled());
    crit_temp_log::disable();
    CHECK(crit_temp_log::is_disabled());

    crit_temp_log::enable(crit_temp_log::mask);
    CHECK(crit_temp_log::is_enabled(crit_temp_log::mask));
    crit_temp_log::disable(0x0);
    CHECK(crit_temp_log::is_disabled(0x0));
}

TEST_CASE("ia32_therm_status_therm_threshold1_status")
{
    using namespace intel_x64::msrs::ia32_therm_status;

    g_msrs[addr] = therm_threshold1_status::mask;
    CHECK(therm_threshold1_status::is_enabled());
    g_msrs[addr] = 0x0;
    CHECK(therm_threshold1_status::is_disabled());

    g_msrs[addr] = therm_threshold1_status::mask;
    CHECK(therm_threshold1_status::is_enabled(therm_threshold1_status::mask));
    g_msrs[addr] = 0x0;
    CHECK(therm_threshold1_status::is_disabled(0x0));
}

TEST_CASE("ia32_therm_status_therm_threshold1_log")
{
    using namespace intel_x64::msrs::ia32_therm_status;

    therm_threshold1_log::enable();
    CHECK(therm_threshold1_log::is_enabled());
    therm_threshold1_log::disable();
    CHECK(therm_threshold1_log::is_disabled());

    therm_threshold1_log::enable(therm_threshold1_log::mask);
    CHECK(therm_threshold1_log::is_enabled(therm_threshold1_log::mask));
    therm_threshold1_log::disable(0x0);
    CHECK(therm_threshold1_log::is_disabled(0x0));
}

TEST_CASE("ia32_therm_status_therm_threshold2_status")
{
    using namespace intel_x64::msrs::ia32_therm_status;

    g_msrs[addr] = therm_threshold2_status::mask;
    CHECK(therm_threshold2_status::is_enabled());
    g_msrs[addr] = 0x0;
    CHECK(therm_threshold2_status::is_disabled());

    g_msrs[addr] = therm_threshold2_status::mask;
    CHECK(therm_threshold2_status::is_enabled(therm_threshold2_status::mask));
    g_msrs[addr] = 0x0;
    CHECK(therm_threshold2_status::is_disabled(0x0));
}

TEST_CASE("ia32_therm_status_therm_threshold2_log")
{
    using namespace intel_x64::msrs::ia32_therm_status;

    therm_threshold2_log::enable();
    CHECK(therm_threshold2_log::is_enabled());
    therm_threshold2_log::disable();
    CHECK(therm_threshold2_log::is_disabled());

    therm_threshold2_log::enable(therm_threshold2_log::mask);
    CHECK(therm_threshold2_log::is_enabled(therm_threshold2_log::mask));
    therm_threshold2_log::disable(0x0);
    CHECK(therm_threshold2_log::is_disabled(0x0));
}

TEST_CASE("ia32_therm_status_power_limit_status")
{
    using namespace intel_x64::msrs::ia32_therm_status;

    g_msrs[addr] = power_limit_status::mask;
    CHECK(power_limit_status::is_enabled());
    g_msrs[addr] = 0x0;
    CHECK(power_limit_status::is_disabled());

    g_msrs[addr] = power_limit_status::mask;
    CHECK(power_limit_status::is_enabled(power_limit_status::mask));
    g_msrs[addr] = 0x0;
    CHECK(power_limit_status::is_disabled(0x0));
}

TEST_CASE("ia32_therm_status_power_limit_log")
{
    using namespace intel_x64::msrs::ia32_therm_status;

    power_limit_log::enable();
    CHECK(power_limit_log::is_enabled());
    power_limit_log::disable();
    CHECK(power_limit_log::is_disabled());

    power_limit_log::enable(power_limit_log::mask);
    CHECK(power_limit_log::is_enabled(power_limit_log::mask));
    power_limit_log::disable(0x0);
    CHECK(power_limit_log::is_disabled(0x0));
}

TEST_CASE("ia32_therm_status_current_limit_status")
{
    using namespace intel_x64::msrs::ia32_therm_status;

    g_msrs[addr] = current_limit_status::mask;
    CHECK(current_limit_status::is_enabled());
    g_msrs[addr] = 0x0;
    CHECK(current_limit_status::is_disabled());

    g_msrs[addr] = current_limit_status::mask;
    CHECK(current_limit_status::is_enabled(current_limit_status::mask));
    g_msrs[addr] = 0x0;
    CHECK(current_limit_status::is_disabled(0x0));
}

TEST_CASE("ia32_therm_status_current_limit_log")
{
    using namespace intel_x64::msrs::ia32_therm_status;

    current_limit_log::enable();
    CHECK(current_limit_log::is_enabled());
    current_limit_log::disable();
    CHECK(current_limit_log::is_disabled());

    current_limit_log::enable(current_limit_log::mask);
    CHECK(current_limit_log::is_enabled(current_limit_log::mask));
    current_limit_log::disable(0x0);
    CHECK(current_limit_log::is_disabled(0x0));
}

TEST_CASE("ia32_therm_status_cross_domain_status")
{
    using namespace intel_x64::msrs::ia32_therm_status;

    g_msrs[addr] = cross_domain_status::mask;
    CHECK(cross_domain_status::is_enabled());
    g_msrs[addr] = 0x0;
    CHECK(cross_domain_status::is_disabled());

    g_msrs[addr] = cross_domain_status::mask;
    CHECK(cross_domain_status::is_enabled(cross_domain_status::mask));
    g_msrs[addr] = 0x0;
    CHECK(cross_domain_status::is_disabled(0x0));
}

TEST_CASE("ia32_therm_status_cross_domain_log")
{
    using namespace intel_x64::msrs::ia32_therm_status;

    cross_domain_log::enable();
    CHECK(cross_domain_log::is_enabled());
    cross_domain_log::disable();
    CHECK(cross_domain_log::is_disabled());

    cross_domain_log::enable(cross_domain_log::mask);
    CHECK(cross_domain_log::is_enabled(cross_domain_log::mask));
    cross_domain_log::disable(0x0);
    CHECK(cross_domain_log::is_disabled(0x0));
}

TEST_CASE("ia32_therm_status_digital_readout")
{
    using namespace intel_x64::msrs::ia32_therm_status;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(digital_readout::get() == (digital_readout::mask >> digital_readout::from));
    CHECK(digital_readout::get(digital_readout::mask) == (digital_readout::mask >> digital_readout::from));
}

TEST_CASE("ia32_therm_status_resolution_celcius")
{
    using namespace intel_x64::msrs::ia32_therm_status;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(resolution_celcius::get() == (resolution_celcius::mask >> resolution_celcius::from));
    CHECK(resolution_celcius::get(resolution_celcius::mask) == (resolution_celcius::mask >> resolution_celcius::from));
}

TEST_CASE("ia32_therm_status_reading_valid")
{
    using namespace intel_x64::msrs::ia32_therm_status;

    g_msrs[addr] = reading_valid::mask;
    CHECK(reading_valid::is_enabled());
    g_msrs[addr] = 0x0;
    CHECK(reading_valid::is_disabled());

    g_msrs[addr] = reading_valid::mask;
    CHECK(reading_valid::is_enabled(reading_valid::mask));
    g_msrs[addr] = 0x0;
    CHECK(reading_valid::is_disabled(0x0));
}

TEST_CASE("ia32_misc_enable")
{
    using namespace intel_x64::msrs::ia32_misc_enable;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_misc_enable_fast_strings")
{
    using namespace intel_x64::msrs::ia32_misc_enable;

    fast_strings::enable();
    CHECK(fast_strings::is_enabled());
    fast_strings::disable();
    CHECK(fast_strings::is_disabled());

    fast_strings::enable(fast_strings::mask);
    CHECK(fast_strings::is_enabled(fast_strings::mask));
    fast_strings::disable(0x0);
    CHECK(fast_strings::is_disabled(0x0));
}

TEST_CASE("ia32_misc_enable_auto_therm_control")
{
    using namespace intel_x64::msrs::ia32_misc_enable;

    auto_therm_control::enable();
    CHECK(auto_therm_control::is_enabled());
    auto_therm_control::disable();
    CHECK(auto_therm_control::is_disabled());

    auto_therm_control::enable(auto_therm_control::mask);
    CHECK(auto_therm_control::is_enabled(auto_therm_control::mask));
    auto_therm_control::disable(0x0);
    CHECK(auto_therm_control::is_disabled(0x0));
}

TEST_CASE("ia32_misc_enable_perf_monitor")
{
    using namespace intel_x64::msrs::ia32_misc_enable;

    g_msrs[addr] = perf_monitor::mask;
    CHECK(perf_monitor::is_enabled());
    g_msrs[addr] = 0x0;
    CHECK(perf_monitor::is_disabled());

    g_msrs[addr] = perf_monitor::mask;
    CHECK(perf_monitor::is_enabled(perf_monitor::mask));
    g_msrs[addr] = 0x0;
    CHECK(perf_monitor::is_disabled(0x0));
}

TEST_CASE("ia32_misc_enable_branch_trace_storage")
{
    using namespace intel_x64::msrs::ia32_misc_enable;

    g_msrs[addr] = branch_trace_storage::mask;
    CHECK(branch_trace_storage::is_enabled());
    g_msrs[addr] = 0x0;
    CHECK(branch_trace_storage::is_disabled());

    g_msrs[addr] = branch_trace_storage::mask;
    CHECK(branch_trace_storage::is_enabled(branch_trace_storage::mask));
    g_msrs[addr] = 0x0;
    CHECK(branch_trace_storage::is_disabled(0x0));
}

TEST_CASE("ia32_misc_enable_processor_sampling")
{
    using namespace intel_x64::msrs::ia32_misc_enable;

    g_msrs[addr] = processor_sampling::mask;
    CHECK(processor_sampling::is_enabled());
    g_msrs[addr] = 0x0;
    CHECK(processor_sampling::is_disabled());

    g_msrs[addr] = processor_sampling::mask;
    CHECK(processor_sampling::is_enabled(processor_sampling::mask));
    g_msrs[addr] = 0x0;
    CHECK(processor_sampling::is_disabled(0x0));
}

TEST_CASE("ia32_misc_enable_intel_speedstep")
{
    using namespace intel_x64::msrs::ia32_misc_enable;

    intel_speedstep::enable();
    CHECK(intel_speedstep::is_enabled());
    intel_speedstep::disable();
    CHECK(intel_speedstep::is_disabled());

    intel_speedstep::enable(intel_speedstep::mask);
    CHECK(intel_speedstep::is_enabled(intel_speedstep::mask));
    intel_speedstep::disable(0x0);
    CHECK(intel_speedstep::is_disabled(0x0));
}

TEST_CASE("ia32_misc_enable_monitor_fsm")
{
    using namespace intel_x64::msrs::ia32_misc_enable;

    monitor_fsm::enable();
    CHECK(monitor_fsm::is_enabled());
    monitor_fsm::disable();
    CHECK(monitor_fsm::is_disabled());

    monitor_fsm::enable(monitor_fsm::mask);
    CHECK(monitor_fsm::is_enabled(monitor_fsm::mask));
    monitor_fsm::disable(0x0);
    CHECK(monitor_fsm::is_disabled(0x0));
}

TEST_CASE("ia32_misc_enable_limit_cpuid_maxval")
{
    using namespace intel_x64::msrs::ia32_misc_enable;

    limit_cpuid_maxval::enable();
    CHECK(limit_cpuid_maxval::is_enabled());
    limit_cpuid_maxval::disable();
    CHECK(limit_cpuid_maxval::is_disabled());

    limit_cpuid_maxval::enable(limit_cpuid_maxval::mask);
    CHECK(limit_cpuid_maxval::is_enabled(limit_cpuid_maxval::mask));
    limit_cpuid_maxval::disable(0x0);
    CHECK(limit_cpuid_maxval::is_disabled(0x0));
}

TEST_CASE("ia32_misc_enable_xtpr_message")
{
    using namespace intel_x64::msrs::ia32_misc_enable;

    xtpr_message::enable();
    CHECK(xtpr_message::is_enabled());
    xtpr_message::disable();
    CHECK(xtpr_message::is_disabled());

    xtpr_message::enable(xtpr_message::mask);
    CHECK(xtpr_message::is_enabled(xtpr_message::mask));
    xtpr_message::disable(0x0);
    CHECK(xtpr_message::is_disabled(0x0));
}

TEST_CASE("ia32_misc_enable_xd_bit")
{
    using namespace intel_x64::msrs::ia32_misc_enable;

    xd_bit::enable();
    CHECK(xd_bit::is_enabled());
    xd_bit::disable();
    CHECK(xd_bit::is_disabled());

    xd_bit::enable(xd_bit::mask);
    CHECK(xd_bit::is_enabled(xd_bit::mask));
    xd_bit::disable(0x0);
    CHECK(xd_bit::is_disabled(0x0));
}

TEST_CASE("ia32_energy_perf_bias")
{
    using namespace intel_x64::msrs::ia32_energy_perf_bias;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_energy_perf_bias_power_policy")
{
    using namespace intel_x64::msrs::ia32_energy_perf_bias;

    power_policy::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(power_policy::get() == (power_policy::mask >> power_policy::from));

    power_policy::set(power_policy::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(power_policy::get(power_policy::mask) == (power_policy::mask >> power_policy::from));
}

TEST_CASE("ia32_package_therm_status")
{
    using namespace intel_x64::msrs::ia32_package_therm_status;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_package_therm_status_pkg_therm_status")
{
    using namespace intel_x64::msrs::ia32_package_therm_status;

    g_msrs[addr] = pkg_therm_status::mask;
    CHECK(pkg_therm_status::is_enabled());
    g_msrs[addr] = 0x0;
    CHECK(pkg_therm_status::is_disabled());

    g_msrs[addr] = pkg_therm_status::mask;
    CHECK(pkg_therm_status::is_enabled(pkg_therm_status::mask));
    g_msrs[addr] = 0x0;
    CHECK(pkg_therm_status::is_disabled(0x0));
}

TEST_CASE("ia32_package_therm_status_pkg_therm_log")
{
    using namespace intel_x64::msrs::ia32_package_therm_status;

    pkg_therm_log::enable();
    CHECK(pkg_therm_log::is_enabled());
    pkg_therm_log::disable();
    CHECK(pkg_therm_log::is_disabled());

    pkg_therm_log::enable(pkg_therm_log::mask);
    CHECK(pkg_therm_log::is_enabled(pkg_therm_log::mask));
    pkg_therm_log::disable(0x0);
    CHECK(pkg_therm_log::is_disabled(0x0));
}

TEST_CASE("ia32_package_therm_status_pkg_prochot_event")
{
    using namespace intel_x64::msrs::ia32_package_therm_status;

    g_msrs[addr] = pkg_prochot_event::mask;
    CHECK(pkg_prochot_event::is_enabled());
    g_msrs[addr] = 0x0;
    CHECK(pkg_prochot_event::is_disabled());

    g_msrs[addr] = pkg_prochot_event::mask;
    CHECK(pkg_prochot_event::is_enabled(pkg_prochot_event::mask));
    g_msrs[addr] = 0x0;
    CHECK(pkg_prochot_event::is_disabled(0x0));
}

TEST_CASE("ia32_package_therm_status_pkg_prochot_log")
{
    using namespace intel_x64::msrs::ia32_package_therm_status;

    pkg_prochot_log::enable();
    CHECK(pkg_prochot_log::is_enabled());
    pkg_prochot_log::disable();
    CHECK(pkg_prochot_log::is_disabled());

    pkg_prochot_log::enable(pkg_prochot_log::mask);
    CHECK(pkg_prochot_log::is_enabled(pkg_prochot_log::mask));
    pkg_prochot_log::disable(0x0);
    CHECK(pkg_prochot_log::is_disabled(0x0));
}

TEST_CASE("ia32_package_therm_status_pkg_crit_temp_status")
{
    using namespace intel_x64::msrs::ia32_package_therm_status;

    g_msrs[addr] = pkg_crit_temp_status::mask;
    CHECK(pkg_crit_temp_status::is_enabled());
    g_msrs[addr] = 0x0;
    CHECK(pkg_crit_temp_status::is_disabled());

    g_msrs[addr] = pkg_crit_temp_status::mask;
    CHECK(pkg_crit_temp_status::is_enabled(pkg_crit_temp_status::mask));
    g_msrs[addr] = 0x0;
    CHECK(pkg_crit_temp_status::is_disabled(0x0));
}

TEST_CASE("ia32_package_therm_status_pkg_crit_temp_log")
{
    using namespace intel_x64::msrs::ia32_package_therm_status;

    pkg_crit_temp_log::enable();
    CHECK(pkg_crit_temp_log::is_enabled());
    pkg_crit_temp_log::disable();
    CHECK(pkg_crit_temp_log::is_disabled());

    pkg_crit_temp_log::enable(pkg_crit_temp_log::mask);
    CHECK(pkg_crit_temp_log::is_enabled(pkg_crit_temp_log::mask));
    pkg_crit_temp_log::disable(0x0);
    CHECK(pkg_crit_temp_log::is_disabled(0x0));
}

TEST_CASE("ia32_package_therm_status_pkg_therm_thresh1_status")
{
    using namespace intel_x64::msrs::ia32_package_therm_status;

    g_msrs[addr] = pkg_therm_thresh1_status::mask;
    CHECK(pkg_therm_thresh1_status::is_enabled());
    g_msrs[addr] = 0x0;
    CHECK(pkg_therm_thresh1_status::is_disabled());

    g_msrs[addr] = pkg_therm_thresh1_status::mask;
    CHECK(pkg_therm_thresh1_status::is_enabled(pkg_therm_thresh1_status::mask));
    g_msrs[addr] = 0x0;
    CHECK(pkg_therm_thresh1_status::is_disabled(0x0));
}

TEST_CASE("ia32_package_therm_status_pkg_therm_thresh1_log")
{
    using namespace intel_x64::msrs::ia32_package_therm_status;

    pkg_therm_thresh1_log::enable();
    CHECK(pkg_therm_thresh1_log::is_enabled());
    pkg_therm_thresh1_log::disable();
    CHECK(pkg_therm_thresh1_log::is_disabled());

    pkg_therm_thresh1_log::enable(pkg_therm_thresh1_log::mask);
    CHECK(pkg_therm_thresh1_log::is_enabled(pkg_therm_thresh1_log::mask));
    pkg_therm_thresh1_log::disable(0x0);
    CHECK(pkg_therm_thresh1_log::is_disabled(0x0));
}

TEST_CASE("ia32_package_therm_status_pkg_therm_thresh2_status")
{
    using namespace intel_x64::msrs::ia32_package_therm_status;

    g_msrs[addr] = pkg_therm_thresh2_status::mask;
    CHECK(pkg_therm_thresh2_status::is_enabled());
    g_msrs[addr] = 0x0;
    CHECK(pkg_therm_thresh2_status::is_disabled());

    g_msrs[addr] = pkg_therm_thresh2_status::mask;
    CHECK(pkg_therm_thresh2_status::is_enabled(pkg_therm_thresh2_status::mask));
    g_msrs[addr] = 0x0;
    CHECK(pkg_therm_thresh2_status::is_disabled(0x0));
}

TEST_CASE("ia32_package_therm_status_pkg_therm_thresh2_log")
{
    using namespace intel_x64::msrs::ia32_package_therm_status;

    pkg_therm_thresh2_log::enable();
    CHECK(pkg_therm_thresh2_log::is_enabled());
    pkg_therm_thresh2_log::disable();
    CHECK(pkg_therm_thresh2_log::is_disabled());

    pkg_therm_thresh2_log::enable(pkg_therm_thresh2_log::mask);
    CHECK(pkg_therm_thresh2_log::is_enabled(pkg_therm_thresh2_log::mask));
    pkg_therm_thresh2_log::disable(0x0);
    CHECK(pkg_therm_thresh2_log::is_disabled(0x0));
}

TEST_CASE("ia32_package_therm_status_pkg_power_limit_status")
{
    using namespace intel_x64::msrs::ia32_package_therm_status;

    g_msrs[addr] = pkg_power_limit_status::mask;
    CHECK(pkg_power_limit_status::is_enabled());
    g_msrs[addr] = 0x0;
    CHECK(pkg_power_limit_status::is_disabled());

    g_msrs[addr] = pkg_power_limit_status::mask;
    CHECK(pkg_power_limit_status::is_enabled(pkg_power_limit_status::mask));
    g_msrs[addr] = 0x0;
    CHECK(pkg_power_limit_status::is_disabled(0x0));
}

TEST_CASE("ia32_package_therm_status_pkg_power_limit_log")
{
    using namespace intel_x64::msrs::ia32_package_therm_status;

    pkg_power_limit_log::enable();
    CHECK(pkg_power_limit_log::is_enabled());
    pkg_power_limit_log::disable();
    CHECK(pkg_power_limit_log::is_disabled());

    pkg_power_limit_log::enable(pkg_power_limit_log::mask);
    CHECK(pkg_power_limit_log::is_enabled(pkg_power_limit_log::mask));
    pkg_power_limit_log::disable(0x0);
    CHECK(pkg_power_limit_log::is_disabled(0x0));
}

TEST_CASE("ia32_package_therm_status_pkg_digital_readout")
{
    using namespace intel_x64::msrs::ia32_package_therm_status;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(pkg_digital_readout::get() == (pkg_digital_readout::mask >> pkg_digital_readout::from));
}

TEST_CASE("ia32_package_therm_interrupt")
{
    using namespace intel_x64::msrs::ia32_package_therm_interrupt;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_package_therm_interrupt_pkg_high_temp")
{
    using namespace intel_x64::msrs::ia32_package_therm_interrupt;

    pkg_high_temp::enable();
    CHECK(pkg_high_temp::is_enabled());
    pkg_high_temp::disable();
    CHECK(pkg_high_temp::is_disabled());

    pkg_high_temp::enable(pkg_high_temp::mask);
    CHECK(pkg_high_temp::is_enabled(pkg_high_temp::mask));
    pkg_high_temp::disable(0x0);
    CHECK(pkg_high_temp::is_disabled(0x0));
}

TEST_CASE("ia32_package_therm_interrupt_pkg_low_temp")
{
    using namespace intel_x64::msrs::ia32_package_therm_interrupt;

    pkg_low_temp::enable();
    CHECK(pkg_low_temp::is_enabled());
    pkg_low_temp::disable();
    CHECK(pkg_low_temp::is_disabled());

    pkg_low_temp::enable(pkg_low_temp::mask);
    CHECK(pkg_low_temp::is_enabled(pkg_low_temp::mask));
    pkg_low_temp::disable(0x0);
    CHECK(pkg_low_temp::is_disabled(0x0));
}

TEST_CASE("ia32_package_therm_interrupt_pkg_prochot")
{
    using namespace intel_x64::msrs::ia32_package_therm_interrupt;

    pkg_prochot::enable();
    CHECK(pkg_prochot::is_enabled());
    pkg_prochot::disable();
    CHECK(pkg_prochot::is_disabled());

    pkg_prochot::enable(pkg_prochot::mask);
    CHECK(pkg_prochot::is_enabled(pkg_prochot::mask));
    pkg_prochot::disable(0x0);
    CHECK(pkg_prochot::is_disabled(0x0));
}

TEST_CASE("ia32_package_therm_interrupt_pkg_overheat")
{
    using namespace intel_x64::msrs::ia32_package_therm_interrupt;

    pkg_overheat::enable();
    CHECK(pkg_overheat::is_enabled());
    pkg_overheat::disable();
    CHECK(pkg_overheat::is_disabled());

    pkg_overheat::enable(pkg_overheat::mask);
    CHECK(pkg_overheat::is_enabled(pkg_overheat::mask));
    pkg_overheat::disable(0x0);
    CHECK(pkg_overheat::is_disabled(0x0));
}

TEST_CASE("ia32_package_therm_interrupt_pkg_threshold_1_value")
{
    using namespace intel_x64::msrs::ia32_package_therm_interrupt;

    pkg_threshold_1_value::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(pkg_threshold_1_value::get() == (pkg_threshold_1_value::mask >> pkg_threshold_1_value::from));

    pkg_threshold_1_value::set(pkg_threshold_1_value::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(pkg_threshold_1_value::get(pkg_threshold_1_value::mask) == (pkg_threshold_1_value::mask >> pkg_threshold_1_value::from));
}

TEST_CASE("ia32_package_therm_interrupt_pkg_threshold_1_enable")
{
    using namespace intel_x64::msrs::ia32_package_therm_interrupt;

    pkg_threshold_1_enable::enable();
    CHECK(pkg_threshold_1_enable::is_enabled());
    pkg_threshold_1_enable::disable();
    CHECK(pkg_threshold_1_enable::is_disabled());

    pkg_threshold_1_enable::enable(pkg_threshold_1_enable::mask);
    CHECK(pkg_threshold_1_enable::is_enabled(pkg_threshold_1_enable::mask));
    pkg_threshold_1_enable::disable(0x0);
    CHECK(pkg_threshold_1_enable::is_disabled(0x0));
}

TEST_CASE("ia32_package_therm_interrupt_pkg_threshold_2_value")
{
    using namespace intel_x64::msrs::ia32_package_therm_interrupt;

    pkg_threshold_2_value::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(pkg_threshold_2_value::get() == (pkg_threshold_2_value::mask >> pkg_threshold_2_value::from));

    pkg_threshold_2_value::set(pkg_threshold_2_value::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(pkg_threshold_2_value::get(pkg_threshold_2_value::mask) == (pkg_threshold_2_value::mask >> pkg_threshold_2_value::from));
}

TEST_CASE("ia32_package_therm_interrupt_pkg_threshold_2_enable")
{
    using namespace intel_x64::msrs::ia32_package_therm_interrupt;

    pkg_threshold_2_enable::enable();
    CHECK(pkg_threshold_2_enable::is_enabled());
    pkg_threshold_2_enable::disable();
    CHECK(pkg_threshold_2_enable::is_disabled());

    pkg_threshold_2_enable::enable(pkg_threshold_2_enable::mask);
    CHECK(pkg_threshold_2_enable::is_enabled(pkg_threshold_2_enable::mask));
    pkg_threshold_2_enable::disable(0x0);
    CHECK(pkg_threshold_2_enable::is_disabled(0x0));
}

TEST_CASE("ia32_package_therm_interrupt_pkg_power_limit")
{
    using namespace intel_x64::msrs::ia32_package_therm_interrupt;

    pkg_power_limit::enable();
    CHECK(pkg_power_limit::is_enabled());
    pkg_power_limit::disable();
    CHECK(pkg_power_limit::is_disabled());

    pkg_power_limit::enable(pkg_power_limit::mask);
    CHECK(pkg_power_limit::is_enabled(pkg_power_limit::mask));
    pkg_power_limit::disable(0x0);
    CHECK(pkg_power_limit::is_disabled(0x0));
}

TEST_CASE("ia32_debugctl")
{
    using namespace intel_x64::msrs::ia32_debugctl;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_debugctl_lbr")
{
    using namespace intel_x64::msrs::ia32_debugctl;

    lbr::enable();
    CHECK(lbr::is_enabled());
    lbr::disable();
    CHECK(lbr::is_disabled());

    lbr::enable(lbr::mask);
    CHECK(lbr::is_enabled(lbr::mask));
    lbr::disable(0x0);
    CHECK(lbr::is_disabled(0x0));
}

TEST_CASE("ia32_debugctl_btf")
{
    using namespace intel_x64::msrs::ia32_debugctl;

    btf::enable();
    CHECK(btf::is_enabled());
    btf::disable();
    CHECK(btf::is_disabled());

    btf::enable(btf::mask);
    CHECK(btf::is_enabled(btf::mask));
    btf::disable(0x0);
    CHECK(btf::is_disabled(0x0));
}

TEST_CASE("ia32_debugctl_tr")
{
    using namespace intel_x64::msrs::ia32_debugctl;

    tr::enable();
    CHECK(tr::is_enabled());
    tr::disable();
    CHECK(tr::is_disabled());

    tr::enable(tr::mask);
    CHECK(tr::is_enabled(tr::mask));
    tr::disable(0x0);
    CHECK(tr::is_disabled(0x0));
}

TEST_CASE("ia32_debugctl_bts")
{
    using namespace intel_x64::msrs::ia32_debugctl;

    bts::enable();
    CHECK(bts::is_enabled());
    bts::disable();
    CHECK(bts::is_disabled());

    bts::enable(bts::mask);
    CHECK(bts::is_enabled(bts::mask));
    bts::disable(0x0);
    CHECK(bts::is_disabled(0x0));
}

TEST_CASE("ia32_debugctl_btint")
{
    using namespace intel_x64::msrs::ia32_debugctl;

    btint::enable();
    CHECK(btint::is_enabled());
    btint::disable();
    CHECK(btint::is_disabled());

    btint::enable(btint::mask);
    CHECK(btint::is_enabled(btint::mask));
    btint::disable(0x0);
    CHECK(btint::is_disabled(0x0));
}

TEST_CASE("ia32_debugctl_bt_off_os")
{
    using namespace intel_x64::msrs::ia32_debugctl;

    bt_off_os::enable();
    CHECK(bt_off_os::is_enabled());
    bt_off_os::disable();
    CHECK(bt_off_os::is_disabled());

    bt_off_os::enable(bt_off_os::mask);
    CHECK(bt_off_os::is_enabled(bt_off_os::mask));
    bt_off_os::disable(0x0);
    CHECK(bt_off_os::is_disabled(0x0));
}

TEST_CASE("ia32_debugctl_bt_off_user")
{
    using namespace intel_x64::msrs::ia32_debugctl;

    bt_off_user::enable();
    CHECK(bt_off_user::is_enabled());
    bt_off_user::disable();
    CHECK(bt_off_user::is_disabled());

    bt_off_user::enable(bt_off_user::mask);
    CHECK(bt_off_user::is_enabled(bt_off_user::mask));
    bt_off_user::disable(0x0);
    CHECK(bt_off_user::is_disabled(0x0));
}

TEST_CASE("ia32_debugctl_freeze_lbrs_on_pmi")
{
    using namespace intel_x64::msrs::ia32_debugctl;

    freeze_lbrs_on_pmi::enable();
    CHECK(freeze_lbrs_on_pmi::is_enabled());
    freeze_lbrs_on_pmi::disable();
    CHECK(freeze_lbrs_on_pmi::is_disabled());

    freeze_lbrs_on_pmi::enable(freeze_lbrs_on_pmi::mask);
    CHECK(freeze_lbrs_on_pmi::is_enabled(freeze_lbrs_on_pmi::mask));
    freeze_lbrs_on_pmi::disable(0x0);
    CHECK(freeze_lbrs_on_pmi::is_disabled(0x0));
}

TEST_CASE("ia32_debugctl_freeze_perfmon_on_pmi")
{
    using namespace intel_x64::msrs::ia32_debugctl;

    freeze_perfmon_on_pmi::enable();
    CHECK(freeze_perfmon_on_pmi::is_enabled());
    freeze_perfmon_on_pmi::disable();
    CHECK(freeze_perfmon_on_pmi::is_disabled());

    freeze_perfmon_on_pmi::enable(freeze_perfmon_on_pmi::mask);
    CHECK(freeze_perfmon_on_pmi::is_enabled(freeze_perfmon_on_pmi::mask));
    freeze_perfmon_on_pmi::disable(0x0);
    CHECK(freeze_perfmon_on_pmi::is_disabled(0x0));
}

TEST_CASE("ia32_debugctl_enable_uncore_pmi")
{
    using namespace intel_x64::msrs::ia32_debugctl;

    enable_uncore_pmi::enable();
    CHECK(enable_uncore_pmi::is_enabled());
    enable_uncore_pmi::disable();
    CHECK(enable_uncore_pmi::is_disabled());

    enable_uncore_pmi::enable(enable_uncore_pmi::mask);
    CHECK(enable_uncore_pmi::is_enabled(enable_uncore_pmi::mask));
    enable_uncore_pmi::disable(0x0);
    CHECK(enable_uncore_pmi::is_disabled(0x0));
}

TEST_CASE("ia32_debugctl_freeze_while_smm")
{
    using namespace intel_x64::msrs::ia32_debugctl;

    freeze_while_smm::enable();
    CHECK(freeze_while_smm::is_enabled());
    freeze_while_smm::disable();
    CHECK(freeze_while_smm::is_disabled());

    freeze_while_smm::enable(freeze_while_smm::mask);
    CHECK(freeze_while_smm::is_enabled(freeze_while_smm::mask));
    freeze_while_smm::disable(0x0);
    CHECK(freeze_while_smm::is_disabled(0x0));
}

TEST_CASE("ia32_debugctl_rtm_debug")
{
    using namespace intel_x64::msrs::ia32_debugctl;

    rtm_debug::enable();
    CHECK(rtm_debug::is_enabled());
    rtm_debug::disable();
    CHECK(rtm_debug::is_disabled());

    rtm_debug::enable(rtm_debug::mask);
    CHECK(rtm_debug::is_enabled(rtm_debug::mask));
    rtm_debug::disable(0x0);
    CHECK(rtm_debug::is_disabled(0x0));
}

TEST_CASE("ia32_smrr_physbase")
{
    using namespace intel_x64::msrs::ia32_smrr_physbase;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_smrr_physbase_type")
{
    using namespace intel_x64::msrs::ia32_smrr_physbase;

    type::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(type::get() == (type::mask >> type::from));

    type::set(type::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(type::get(type::mask) == (type::mask >> type::from));
}

TEST_CASE("ia32_smrr_physbase_physbase")
{
    using namespace intel_x64::msrs::ia32_smrr_physbase;

    physbase::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(physbase::get() == (physbase::mask >> physbase::from));

    physbase::set(physbase::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(physbase::get(physbase::mask) == (physbase::mask >> physbase::from));
}

TEST_CASE("ia32_smrr_physmask")
{
    using namespace intel_x64::msrs::ia32_smrr_physmask;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_smrr_physmask_valid")
{
    using namespace intel_x64::msrs::ia32_smrr_physmask;

    valid::enable();
    CHECK(valid::is_enabled());
    valid::disable();
    CHECK(valid::is_disabled());

    valid::enable(valid::mask);
    CHECK(valid::is_enabled(valid::mask));
    valid::disable(0x0);
    CHECK(valid::is_disabled(0x0));
}

TEST_CASE("ia32_smrr_physmask_physmask")
{
    using namespace intel_x64::msrs::ia32_smrr_physmask;

    physmask::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(physmask::get() == (physmask::mask >> physmask::from));

    physmask::set(physmask::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(physmask::get(physmask::mask) == (physmask::mask >> physmask::from));
}

TEST_CASE("ia32_platform_dca_cap")
{
    using namespace intel_x64::msrs::ia32_platform_dca_cap;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_cpu_dca_cap")
{
    using namespace intel_x64::msrs::ia32_cpu_dca_cap;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_dca_0_cap")
{
    using namespace intel_x64::msrs::ia32_dca_0_cap;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_dca_0_cap_dca_active")
{
    using namespace intel_x64::msrs::ia32_dca_0_cap;

    dca_active::enable();
    CHECK(dca_active::is_enabled());
    dca_active::disable();
    CHECK(dca_active::is_disabled());

    dca_active::enable(dca_active::mask);
    CHECK(dca_active::is_enabled(dca_active::mask));
    dca_active::disable(0x0);
    CHECK(dca_active::is_disabled(0x0));
}

TEST_CASE("ia32_dca_0_cap_transaction")
{
    using namespace intel_x64::msrs::ia32_dca_0_cap;

    transaction::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(transaction::get() == (transaction::mask >> transaction::from));

    transaction::set(transaction::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(transaction::get(transaction::mask) == (transaction::mask >> transaction::from));
}

TEST_CASE("ia32_dca_0_cap_dca_type")
{
    using namespace intel_x64::msrs::ia32_dca_0_cap;

    dca_type::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(dca_type::get() == (dca_type::mask >> dca_type::from));

    dca_type::set(dca_type::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(dca_type::get(dca_type::mask) == (dca_type::mask >> dca_type::from));
}

TEST_CASE("ia32_dca_0_cap_dca_queue_size")
{
    using namespace intel_x64::msrs::ia32_dca_0_cap;

    dca_queue_size::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(dca_queue_size::get() == (dca_queue_size::mask >> dca_queue_size::from));

    dca_queue_size::set(dca_queue_size::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(dca_queue_size::get(dca_queue_size::mask) == (dca_queue_size::mask >> dca_queue_size::from));
}

TEST_CASE("ia32_dca_0_cap_dca_delay")
{
    using namespace intel_x64::msrs::ia32_dca_0_cap;

    dca_delay::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(dca_delay::get() == (dca_delay::mask >> dca_delay::from));

    dca_delay::set(dca_delay::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(dca_delay::get(dca_delay::mask) == (dca_delay::mask >> dca_delay::from));
}

TEST_CASE("ia32_dca_0_cap_sw_block")
{
    using namespace intel_x64::msrs::ia32_dca_0_cap;

    sw_block::enable();
    CHECK(sw_block::is_enabled());
    sw_block::disable();
    CHECK(sw_block::is_disabled());

    sw_block::enable(sw_block::mask);
    CHECK(sw_block::is_enabled(sw_block::mask));
    sw_block::disable(0x0);
    CHECK(sw_block::is_disabled(0x0));
}

TEST_CASE("ia32_dca_0_cap_hw_block")
{
    using namespace intel_x64::msrs::ia32_dca_0_cap;

    hw_block::enable();
    CHECK(hw_block::is_enabled());
    hw_block::disable();
    CHECK(hw_block::is_disabled());

    hw_block::enable(hw_block::mask);
    CHECK(hw_block::is_enabled(hw_block::mask));
    hw_block::disable(0x0);
    CHECK(hw_block::is_disabled(0x0));
}

TEST_CASE("ia32_mtrr_physbase0")
{
    using namespace intel_x64::msrs::ia32_mtrr_physbase0;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mtrr_physmask0")
{
    using namespace intel_x64::msrs::ia32_mtrr_physmask0;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mtrr_physbase1")
{
    using namespace intel_x64::msrs::ia32_mtrr_physbase1;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mtrr_physmask1")
{
    using namespace intel_x64::msrs::ia32_mtrr_physmask1;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mtrr_physbase2")
{
    using namespace intel_x64::msrs::ia32_mtrr_physbase2;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mtrr_physmask2")
{
    using namespace intel_x64::msrs::ia32_mtrr_physmask2;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mtrr_physbase3")
{
    using namespace intel_x64::msrs::ia32_mtrr_physbase3;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mtrr_physmask3")
{
    using namespace intel_x64::msrs::ia32_mtrr_physmask3;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mtrr_physbase4")
{
    using namespace intel_x64::msrs::ia32_mtrr_physbase4;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mtrr_physmask4")
{
    using namespace intel_x64::msrs::ia32_mtrr_physmask4;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mtrr_physbase5")
{
    using namespace intel_x64::msrs::ia32_mtrr_physbase5;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mtrr_physmask5")
{
    using namespace intel_x64::msrs::ia32_mtrr_physmask5;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mtrr_physbase6")
{
    using namespace intel_x64::msrs::ia32_mtrr_physbase6;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mtrr_physmask6")
{
    using namespace intel_x64::msrs::ia32_mtrr_physmask6;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mtrr_physbase7")
{
    using namespace intel_x64::msrs::ia32_mtrr_physbase7;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mtrr_physmask7")
{
    using namespace intel_x64::msrs::ia32_mtrr_physmask7;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mtrr_physbase8")
{
    using namespace intel_x64::msrs::ia32_mtrr_physbase8;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mtrr_physmask8")
{
    using namespace intel_x64::msrs::ia32_mtrr_physmask8;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mtrr_physbase9")
{
    using namespace intel_x64::msrs::ia32_mtrr_physbase9;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mtrr_physmask9")
{
    using namespace intel_x64::msrs::ia32_mtrr_physmask9;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mtrr_fix64k_00000")
{
    using namespace intel_x64::msrs::ia32_mtrr_fix64k_00000;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mtrr_fix16k_80000")
{
    using namespace intel_x64::msrs::ia32_mtrr_fix16k_80000;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mtrr_fix16k_A0000")
{
    using namespace intel_x64::msrs::ia32_mtrr_fix16k_A0000;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mtrr_fix4k_C0000")
{
    using namespace intel_x64::msrs::ia32_mtrr_fix4k_C0000;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mtrr_fix4k_C8000")
{
    using namespace intel_x64::msrs::ia32_mtrr_fix4k_C8000;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mtrr_fix4k_D0000")
{
    using namespace intel_x64::msrs::ia32_mtrr_fix4k_D0000;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mtrr_fix4k_D8000")
{
    using namespace intel_x64::msrs::ia32_mtrr_fix4k_D8000;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mtrr_fix4k_E0000")
{
    using namespace intel_x64::msrs::ia32_mtrr_fix4k_E0000;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mtrr_fix4k_E8000")
{
    using namespace intel_x64::msrs::ia32_mtrr_fix4k_E8000;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mtrr_fix4k_F0000")
{
    using namespace intel_x64::msrs::ia32_mtrr_fix4k_F0000;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mtrr_fix4k_F8000")
{
    using namespace intel_x64::msrs::ia32_mtrr_fix4k_F8000;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc0_ctl2")
{
    using namespace intel_x64::msrs::ia32_mc0_ctl2;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc0_ctl2_error_threshold")
{
    using namespace intel_x64::msrs::ia32_mc0_ctl2;

    error_threshold::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(error_threshold::get() == (error_threshold::mask >> error_threshold::from));

    error_threshold::set(error_threshold::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(error_threshold::get(error_threshold::mask) == (error_threshold::mask >> error_threshold::from));
}

TEST_CASE("ia32_mc0_ctl2_cmci_en")
{
    using namespace intel_x64::msrs::ia32_mc0_ctl2;

    cmci_en::enable();
    CHECK(cmci_en::is_enabled());
    cmci_en::disable();
    CHECK(cmci_en::is_disabled());

    cmci_en::enable(cmci_en::mask);
    CHECK(cmci_en::is_enabled(cmci_en::mask));
    cmci_en::disable(0x0);
    CHECK(cmci_en::is_disabled(0x0));
}

TEST_CASE("ia32_mc1_ctl2")
{
    using namespace intel_x64::msrs::ia32_mc1_ctl2;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc1_ctl2_error_threshold")
{
    using namespace intel_x64::msrs::ia32_mc1_ctl2;

    error_threshold::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(error_threshold::get() == (error_threshold::mask >> error_threshold::from));

    error_threshold::set(error_threshold::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(error_threshold::get(error_threshold::mask) == (error_threshold::mask >> error_threshold::from));
}

TEST_CASE("ia32_mc1_ctl2_cmci_en")
{
    using namespace intel_x64::msrs::ia32_mc1_ctl2;

    cmci_en::enable();
    CHECK(cmci_en::is_enabled());
    cmci_en::disable();
    CHECK(cmci_en::is_disabled());

    cmci_en::enable(cmci_en::mask);
    CHECK(cmci_en::is_enabled(cmci_en::mask));
    cmci_en::disable(0x0);
    CHECK(cmci_en::is_disabled(0x0));
}

TEST_CASE("ia32_mc2_ctl2")
{
    using namespace intel_x64::msrs::ia32_mc2_ctl2;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc2_ctl2_error_threshold")
{
    using namespace intel_x64::msrs::ia32_mc2_ctl2;

    error_threshold::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(error_threshold::get() == (error_threshold::mask >> error_threshold::from));

    error_threshold::set(error_threshold::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(error_threshold::get(error_threshold::mask) == (error_threshold::mask >> error_threshold::from));
}

TEST_CASE("ia32_mc2_ctl2_cmci_en")
{
    using namespace intel_x64::msrs::ia32_mc2_ctl2;

    cmci_en::enable();
    CHECK(cmci_en::is_enabled());
    cmci_en::disable();
    CHECK(cmci_en::is_disabled());

    cmci_en::enable(cmci_en::mask);
    CHECK(cmci_en::is_enabled(cmci_en::mask));
    cmci_en::disable(0x0);
    CHECK(cmci_en::is_disabled(0x0));
}

TEST_CASE("ia32_mc3_ctl2")
{
    using namespace intel_x64::msrs::ia32_mc3_ctl2;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc3_ctl2_error_threshold")
{
    using namespace intel_x64::msrs::ia32_mc3_ctl2;

    error_threshold::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(error_threshold::get() == (error_threshold::mask >> error_threshold::from));

    error_threshold::set(error_threshold::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(error_threshold::get(error_threshold::mask) == (error_threshold::mask >> error_threshold::from));
}

TEST_CASE("ia32_mc3_ctl2_cmci_en")
{
    using namespace intel_x64::msrs::ia32_mc3_ctl2;

    cmci_en::enable();
    CHECK(cmci_en::is_enabled());
    cmci_en::disable();
    CHECK(cmci_en::is_disabled());

    cmci_en::enable(cmci_en::mask);
    CHECK(cmci_en::is_enabled(cmci_en::mask));
    cmci_en::disable(0x0);
    CHECK(cmci_en::is_disabled(0x0));
}

TEST_CASE("ia32_mc4_ctl2")
{
    using namespace intel_x64::msrs::ia32_mc4_ctl2;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc4_ctl2_error_threshold")
{
    using namespace intel_x64::msrs::ia32_mc4_ctl2;

    error_threshold::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(error_threshold::get() == (error_threshold::mask >> error_threshold::from));

    error_threshold::set(error_threshold::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(error_threshold::get(error_threshold::mask) == (error_threshold::mask >> error_threshold::from));
}

TEST_CASE("ia32_mc4_ctl2_cmci_en")
{
    using namespace intel_x64::msrs::ia32_mc4_ctl2;

    cmci_en::enable();
    CHECK(cmci_en::is_enabled());
    cmci_en::disable();
    CHECK(cmci_en::is_disabled());

    cmci_en::enable(cmci_en::mask);
    CHECK(cmci_en::is_enabled(cmci_en::mask));
    cmci_en::disable(0x0);
    CHECK(cmci_en::is_disabled(0x0));
}

TEST_CASE("ia32_mc5_ctl2")
{
    using namespace intel_x64::msrs::ia32_mc5_ctl2;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc5_ctl2_error_threshold")
{
    using namespace intel_x64::msrs::ia32_mc5_ctl2;

    error_threshold::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(error_threshold::get() == (error_threshold::mask >> error_threshold::from));

    error_threshold::set(error_threshold::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(error_threshold::get(error_threshold::mask) == (error_threshold::mask >> error_threshold::from));
}

TEST_CASE("ia32_mc5_ctl2_cmci_en")
{
    using namespace intel_x64::msrs::ia32_mc5_ctl2;

    cmci_en::enable();
    CHECK(cmci_en::is_enabled());
    cmci_en::disable();
    CHECK(cmci_en::is_disabled());

    cmci_en::enable(cmci_en::mask);
    CHECK(cmci_en::is_enabled(cmci_en::mask));
    cmci_en::disable(0x0);
    CHECK(cmci_en::is_disabled(0x0));
}

TEST_CASE("ia32_mc6_ctl2")
{
    using namespace intel_x64::msrs::ia32_mc6_ctl2;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc6_ctl2_error_threshold")
{
    using namespace intel_x64::msrs::ia32_mc6_ctl2;

    error_threshold::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(error_threshold::get() == (error_threshold::mask >> error_threshold::from));

    error_threshold::set(error_threshold::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(error_threshold::get(error_threshold::mask) == (error_threshold::mask >> error_threshold::from));
}

TEST_CASE("ia32_mc6_ctl2_cmci_en")
{
    using namespace intel_x64::msrs::ia32_mc6_ctl2;

    cmci_en::enable();
    CHECK(cmci_en::is_enabled());
    cmci_en::disable();
    CHECK(cmci_en::is_disabled());

    cmci_en::enable(cmci_en::mask);
    CHECK(cmci_en::is_enabled(cmci_en::mask));
    cmci_en::disable(0x0);
    CHECK(cmci_en::is_disabled(0x0));
}

TEST_CASE("ia32_mc7_ctl2")
{
    using namespace intel_x64::msrs::ia32_mc7_ctl2;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc7_ctl2_error_threshold")
{
    using namespace intel_x64::msrs::ia32_mc7_ctl2;

    error_threshold::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(error_threshold::get() == (error_threshold::mask >> error_threshold::from));

    error_threshold::set(error_threshold::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(error_threshold::get(error_threshold::mask) == (error_threshold::mask >> error_threshold::from));
}

TEST_CASE("ia32_mc7_ctl2_cmci_en")
{
    using namespace intel_x64::msrs::ia32_mc7_ctl2;

    cmci_en::enable();
    CHECK(cmci_en::is_enabled());
    cmci_en::disable();
    CHECK(cmci_en::is_disabled());

    cmci_en::enable(cmci_en::mask);
    CHECK(cmci_en::is_enabled(cmci_en::mask));
    cmci_en::disable(0x0);
    CHECK(cmci_en::is_disabled(0x0));
}

TEST_CASE("ia32_mc8_ctl2")
{
    using namespace intel_x64::msrs::ia32_mc8_ctl2;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc8_ctl2_error_threshold")
{
    using namespace intel_x64::msrs::ia32_mc8_ctl2;

    error_threshold::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(error_threshold::get() == (error_threshold::mask >> error_threshold::from));

    error_threshold::set(error_threshold::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(error_threshold::get(error_threshold::mask) == (error_threshold::mask >> error_threshold::from));
}

TEST_CASE("ia32_mc8_ctl2_cmci_en")
{
    using namespace intel_x64::msrs::ia32_mc8_ctl2;

    cmci_en::enable();
    CHECK(cmci_en::is_enabled());
    cmci_en::disable();
    CHECK(cmci_en::is_disabled());

    cmci_en::enable(cmci_en::mask);
    CHECK(cmci_en::is_enabled(cmci_en::mask));
    cmci_en::disable(0x0);
    CHECK(cmci_en::is_disabled(0x0));
}

TEST_CASE("ia32_mc9_ctl2")
{
    using namespace intel_x64::msrs::ia32_mc9_ctl2;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc9_ctl2_error_threshold")
{
    using namespace intel_x64::msrs::ia32_mc9_ctl2;

    error_threshold::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(error_threshold::get() == (error_threshold::mask >> error_threshold::from));

    error_threshold::set(error_threshold::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(error_threshold::get(error_threshold::mask) == (error_threshold::mask >> error_threshold::from));
}

TEST_CASE("ia32_mc9_ctl2_cmci_en")
{
    using namespace intel_x64::msrs::ia32_mc9_ctl2;

    cmci_en::enable();
    CHECK(cmci_en::is_enabled());
    cmci_en::disable();
    CHECK(cmci_en::is_disabled());

    cmci_en::enable(cmci_en::mask);
    CHECK(cmci_en::is_enabled(cmci_en::mask));
    cmci_en::disable(0x0);
    CHECK(cmci_en::is_disabled(0x0));
}

TEST_CASE("ia32_mc10_ctl2")
{
    using namespace intel_x64::msrs::ia32_mc10_ctl2;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc10_ctl2_error_threshold")
{
    using namespace intel_x64::msrs::ia32_mc10_ctl2;

    error_threshold::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(error_threshold::get() == (error_threshold::mask >> error_threshold::from));

    error_threshold::set(error_threshold::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(error_threshold::get(error_threshold::mask) == (error_threshold::mask >> error_threshold::from));
}

TEST_CASE("ia32_mc10_ctl2_cmci_en")
{
    using namespace intel_x64::msrs::ia32_mc10_ctl2;

    cmci_en::enable();
    CHECK(cmci_en::is_enabled());
    cmci_en::disable();
    CHECK(cmci_en::is_disabled());

    cmci_en::enable(cmci_en::mask);
    CHECK(cmci_en::is_enabled(cmci_en::mask));
    cmci_en::disable(0x0);
    CHECK(cmci_en::is_disabled(0x0));
}

TEST_CASE("ia32_mc11_ctl2")
{
    using namespace intel_x64::msrs::ia32_mc11_ctl2;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc11_ctl2_error_threshold")
{
    using namespace intel_x64::msrs::ia32_mc11_ctl2;

    error_threshold::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(error_threshold::get() == (error_threshold::mask >> error_threshold::from));

    error_threshold::set(error_threshold::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(error_threshold::get(error_threshold::mask) == (error_threshold::mask >> error_threshold::from));
}

TEST_CASE("ia32_mc11_ctl2_cmci_en")
{
    using namespace intel_x64::msrs::ia32_mc11_ctl2;

    cmci_en::enable();
    CHECK(cmci_en::is_enabled());
    cmci_en::disable();
    CHECK(cmci_en::is_disabled());

    cmci_en::enable(cmci_en::mask);
    CHECK(cmci_en::is_enabled(cmci_en::mask));
    cmci_en::disable(0x0);
    CHECK(cmci_en::is_disabled(0x0));
}

TEST_CASE("ia32_mc12_ctl2")
{
    using namespace intel_x64::msrs::ia32_mc12_ctl2;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc12_ctl2_error_threshold")
{
    using namespace intel_x64::msrs::ia32_mc12_ctl2;

    error_threshold::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(error_threshold::get() == (error_threshold::mask >> error_threshold::from));

    error_threshold::set(error_threshold::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(error_threshold::get(error_threshold::mask) == (error_threshold::mask >> error_threshold::from));
}

TEST_CASE("ia32_mc12_ctl2_cmci_en")
{
    using namespace intel_x64::msrs::ia32_mc12_ctl2;

    cmci_en::enable();
    CHECK(cmci_en::is_enabled());
    cmci_en::disable();
    CHECK(cmci_en::is_disabled());

    cmci_en::enable(cmci_en::mask);
    CHECK(cmci_en::is_enabled(cmci_en::mask));
    cmci_en::disable(0x0);
    CHECK(cmci_en::is_disabled(0x0));
}

TEST_CASE("ia32_mc13_ctl2")
{
    using namespace intel_x64::msrs::ia32_mc13_ctl2;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc13_ctl2_error_threshold")
{
    using namespace intel_x64::msrs::ia32_mc13_ctl2;

    error_threshold::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(error_threshold::get() == (error_threshold::mask >> error_threshold::from));

    error_threshold::set(error_threshold::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(error_threshold::get(error_threshold::mask) == (error_threshold::mask >> error_threshold::from));
}

TEST_CASE("ia32_mc13_ctl2_cmci_en")
{
    using namespace intel_x64::msrs::ia32_mc13_ctl2;

    cmci_en::enable();
    CHECK(cmci_en::is_enabled());
    cmci_en::disable();
    CHECK(cmci_en::is_disabled());

    cmci_en::enable(cmci_en::mask);
    CHECK(cmci_en::is_enabled(cmci_en::mask));
    cmci_en::disable(0x0);
    CHECK(cmci_en::is_disabled(0x0));
}

TEST_CASE("ia32_mc14_ctl2")
{
    using namespace intel_x64::msrs::ia32_mc14_ctl2;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc14_ctl2_error_threshold")
{
    using namespace intel_x64::msrs::ia32_mc14_ctl2;

    error_threshold::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(error_threshold::get() == (error_threshold::mask >> error_threshold::from));

    error_threshold::set(error_threshold::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(error_threshold::get(error_threshold::mask) == (error_threshold::mask >> error_threshold::from));
}

TEST_CASE("ia32_mc14_ctl2_cmci_en")
{
    using namespace intel_x64::msrs::ia32_mc14_ctl2;

    cmci_en::enable();
    CHECK(cmci_en::is_enabled());
    cmci_en::disable();
    CHECK(cmci_en::is_disabled());

    cmci_en::enable(cmci_en::mask);
    CHECK(cmci_en::is_enabled(cmci_en::mask));
    cmci_en::disable(0x0);
    CHECK(cmci_en::is_disabled(0x0));
}

TEST_CASE("ia32_mc15_ctl2")
{
    using namespace intel_x64::msrs::ia32_mc15_ctl2;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc15_ctl2_error_threshold")
{
    using namespace intel_x64::msrs::ia32_mc15_ctl2;

    error_threshold::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(error_threshold::get() == (error_threshold::mask >> error_threshold::from));

    error_threshold::set(error_threshold::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(error_threshold::get(error_threshold::mask) == (error_threshold::mask >> error_threshold::from));
}

TEST_CASE("ia32_mc15_ctl2_cmci_en")
{
    using namespace intel_x64::msrs::ia32_mc15_ctl2;

    cmci_en::enable();
    CHECK(cmci_en::is_enabled());
    cmci_en::disable();
    CHECK(cmci_en::is_disabled());

    cmci_en::enable(cmci_en::mask);
    CHECK(cmci_en::is_enabled(cmci_en::mask));
    cmci_en::disable(0x0);
    CHECK(cmci_en::is_disabled(0x0));
}

TEST_CASE("ia32_mc16_ctl2")
{
    using namespace intel_x64::msrs::ia32_mc16_ctl2;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc16_ctl2_error_threshold")
{
    using namespace intel_x64::msrs::ia32_mc16_ctl2;

    error_threshold::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(error_threshold::get() == (error_threshold::mask >> error_threshold::from));

    error_threshold::set(error_threshold::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(error_threshold::get(error_threshold::mask) == (error_threshold::mask >> error_threshold::from));
}

TEST_CASE("ia32_mc16_ctl2_cmci_en")
{
    using namespace intel_x64::msrs::ia32_mc16_ctl2;

    cmci_en::enable();
    CHECK(cmci_en::is_enabled());
    cmci_en::disable();
    CHECK(cmci_en::is_disabled());

    cmci_en::enable(cmci_en::mask);
    CHECK(cmci_en::is_enabled(cmci_en::mask));
    cmci_en::disable(0x0);
    CHECK(cmci_en::is_disabled(0x0));
}

TEST_CASE("ia32_mc17_ctl2")
{
    using namespace intel_x64::msrs::ia32_mc17_ctl2;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc17_ctl2_error_threshold")
{
    using namespace intel_x64::msrs::ia32_mc17_ctl2;

    error_threshold::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(error_threshold::get() == (error_threshold::mask >> error_threshold::from));

    error_threshold::set(error_threshold::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(error_threshold::get(error_threshold::mask) == (error_threshold::mask >> error_threshold::from));
}

TEST_CASE("ia32_mc17_ctl2_cmci_en")
{
    using namespace intel_x64::msrs::ia32_mc17_ctl2;

    cmci_en::enable();
    CHECK(cmci_en::is_enabled());
    cmci_en::disable();
    CHECK(cmci_en::is_disabled());

    cmci_en::enable(cmci_en::mask);
    CHECK(cmci_en::is_enabled(cmci_en::mask));
    cmci_en::disable(0x0);
    CHECK(cmci_en::is_disabled(0x0));
}

TEST_CASE("ia32_mc18_ctl2")
{
    using namespace intel_x64::msrs::ia32_mc18_ctl2;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc18_ctl2_error_threshold")
{
    using namespace intel_x64::msrs::ia32_mc18_ctl2;

    error_threshold::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(error_threshold::get() == (error_threshold::mask >> error_threshold::from));

    error_threshold::set(error_threshold::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(error_threshold::get(error_threshold::mask) == (error_threshold::mask >> error_threshold::from));
}

TEST_CASE("ia32_mc18_ctl2_cmci_en")
{
    using namespace intel_x64::msrs::ia32_mc18_ctl2;

    cmci_en::enable();
    CHECK(cmci_en::is_enabled());
    cmci_en::disable();
    CHECK(cmci_en::is_disabled());

    cmci_en::enable(cmci_en::mask);
    CHECK(cmci_en::is_enabled(cmci_en::mask));
    cmci_en::disable(0x0);
    CHECK(cmci_en::is_disabled(0x0));
}

TEST_CASE("ia32_mc19_ctl2")
{
    using namespace intel_x64::msrs::ia32_mc19_ctl2;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc19_ctl2_error_threshold")
{
    using namespace intel_x64::msrs::ia32_mc19_ctl2;

    error_threshold::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(error_threshold::get() == (error_threshold::mask >> error_threshold::from));

    error_threshold::set(error_threshold::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(error_threshold::get(error_threshold::mask) == (error_threshold::mask >> error_threshold::from));
}

TEST_CASE("ia32_mc19_ctl2_cmci_en")
{
    using namespace intel_x64::msrs::ia32_mc19_ctl2;

    cmci_en::enable();
    CHECK(cmci_en::is_enabled());
    cmci_en::disable();
    CHECK(cmci_en::is_disabled());

    cmci_en::enable(cmci_en::mask);
    CHECK(cmci_en::is_enabled(cmci_en::mask));
    cmci_en::disable(0x0);
    CHECK(cmci_en::is_disabled(0x0));
}

TEST_CASE("ia32_mc20_ctl2")
{
    using namespace intel_x64::msrs::ia32_mc20_ctl2;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc20_ctl2_error_threshold")
{
    using namespace intel_x64::msrs::ia32_mc20_ctl2;

    error_threshold::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(error_threshold::get() == (error_threshold::mask >> error_threshold::from));

    error_threshold::set(error_threshold::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(error_threshold::get(error_threshold::mask) == (error_threshold::mask >> error_threshold::from));
}

TEST_CASE("ia32_mc20_ctl2_cmci_en")
{
    using namespace intel_x64::msrs::ia32_mc20_ctl2;

    cmci_en::enable();
    CHECK(cmci_en::is_enabled());
    cmci_en::disable();
    CHECK(cmci_en::is_disabled());

    cmci_en::enable(cmci_en::mask);
    CHECK(cmci_en::is_enabled(cmci_en::mask));
    cmci_en::disable(0x0);
    CHECK(cmci_en::is_disabled(0x0));
}

TEST_CASE("ia32_mc21_ctl2")
{
    using namespace intel_x64::msrs::ia32_mc21_ctl2;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc21_ctl2_error_threshold")
{
    using namespace intel_x64::msrs::ia32_mc21_ctl2;

    error_threshold::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(error_threshold::get() == (error_threshold::mask >> error_threshold::from));

    error_threshold::set(error_threshold::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(error_threshold::get(error_threshold::mask) == (error_threshold::mask >> error_threshold::from));
}

TEST_CASE("ia32_mc21_ctl2_cmci_en")
{
    using namespace intel_x64::msrs::ia32_mc21_ctl2;

    cmci_en::enable();
    CHECK(cmci_en::is_enabled());
    cmci_en::disable();
    CHECK(cmci_en::is_disabled());

    cmci_en::enable(cmci_en::mask);
    CHECK(cmci_en::is_enabled(cmci_en::mask));
    cmci_en::disable(0x0);
    CHECK(cmci_en::is_disabled(0x0));
}

TEST_CASE("ia32_mc22_ctl2")
{
    using namespace intel_x64::msrs::ia32_mc22_ctl2;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc22_ctl2_error_threshold")
{
    using namespace intel_x64::msrs::ia32_mc22_ctl2;

    error_threshold::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(error_threshold::get() == (error_threshold::mask >> error_threshold::from));

    error_threshold::set(error_threshold::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(error_threshold::get(error_threshold::mask) == (error_threshold::mask >> error_threshold::from));
}

TEST_CASE("ia32_mc22_ctl2_cmci_en")
{
    using namespace intel_x64::msrs::ia32_mc22_ctl2;

    cmci_en::enable();
    CHECK(cmci_en::is_enabled());
    cmci_en::disable();
    CHECK(cmci_en::is_disabled());

    cmci_en::enable(cmci_en::mask);
    CHECK(cmci_en::is_enabled(cmci_en::mask));
    cmci_en::disable(0x0);
    CHECK(cmci_en::is_disabled(0x0));
}

TEST_CASE("ia32_mc23_ctl2")
{
    using namespace intel_x64::msrs::ia32_mc23_ctl2;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc23_ctl2_error_threshold")
{
    using namespace intel_x64::msrs::ia32_mc23_ctl2;

    error_threshold::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(error_threshold::get() == (error_threshold::mask >> error_threshold::from));

    error_threshold::set(error_threshold::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(error_threshold::get(error_threshold::mask) == (error_threshold::mask >> error_threshold::from));
}

TEST_CASE("ia32_mc23_ctl2_cmci_en")
{
    using namespace intel_x64::msrs::ia32_mc23_ctl2;

    cmci_en::enable();
    CHECK(cmci_en::is_enabled());
    cmci_en::disable();
    CHECK(cmci_en::is_disabled());

    cmci_en::enable(cmci_en::mask);
    CHECK(cmci_en::is_enabled(cmci_en::mask));
    cmci_en::disable(0x0);
    CHECK(cmci_en::is_disabled(0x0));
}

TEST_CASE("ia32_mc24_ctl2")
{
    using namespace intel_x64::msrs::ia32_mc24_ctl2;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc24_ctl2_error_threshold")
{
    using namespace intel_x64::msrs::ia32_mc24_ctl2;

    error_threshold::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(error_threshold::get() == (error_threshold::mask >> error_threshold::from));

    error_threshold::set(error_threshold::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(error_threshold::get(error_threshold::mask) == (error_threshold::mask >> error_threshold::from));
}

TEST_CASE("ia32_mc24_ctl2_cmci_en")
{
    using namespace intel_x64::msrs::ia32_mc24_ctl2;

    cmci_en::enable();
    CHECK(cmci_en::is_enabled());
    cmci_en::disable();
    CHECK(cmci_en::is_disabled());

    cmci_en::enable(cmci_en::mask);
    CHECK(cmci_en::is_enabled(cmci_en::mask));
    cmci_en::disable(0x0);
    CHECK(cmci_en::is_disabled(0x0));
}

TEST_CASE("ia32_mc25_ctl2")
{
    using namespace intel_x64::msrs::ia32_mc25_ctl2;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc25_ctl2_error_threshold")
{
    using namespace intel_x64::msrs::ia32_mc25_ctl2;

    error_threshold::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(error_threshold::get() == (error_threshold::mask >> error_threshold::from));

    error_threshold::set(error_threshold::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(error_threshold::get(error_threshold::mask) == (error_threshold::mask >> error_threshold::from));
}

TEST_CASE("ia32_mc25_ctl2_cmci_en")
{
    using namespace intel_x64::msrs::ia32_mc25_ctl2;

    cmci_en::enable();
    CHECK(cmci_en::is_enabled());
    cmci_en::disable();
    CHECK(cmci_en::is_disabled());

    cmci_en::enable(cmci_en::mask);
    CHECK(cmci_en::is_enabled(cmci_en::mask));
    cmci_en::disable(0x0);
    CHECK(cmci_en::is_disabled(0x0));
}

TEST_CASE("ia32_mc26_ctl2")
{
    using namespace intel_x64::msrs::ia32_mc26_ctl2;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc26_ctl2_error_threshold")
{
    using namespace intel_x64::msrs::ia32_mc26_ctl2;

    error_threshold::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(error_threshold::get() == (error_threshold::mask >> error_threshold::from));

    error_threshold::set(error_threshold::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(error_threshold::get(error_threshold::mask) == (error_threshold::mask >> error_threshold::from));
}

TEST_CASE("ia32_mc26_ctl2_cmci_en")
{
    using namespace intel_x64::msrs::ia32_mc26_ctl2;

    cmci_en::enable();
    CHECK(cmci_en::is_enabled());
    cmci_en::disable();
    CHECK(cmci_en::is_disabled());

    cmci_en::enable(cmci_en::mask);
    CHECK(cmci_en::is_enabled(cmci_en::mask));
    cmci_en::disable(0x0);
    CHECK(cmci_en::is_disabled(0x0));
}

TEST_CASE("ia32_mc27_ctl2")
{
    using namespace intel_x64::msrs::ia32_mc27_ctl2;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc27_ctl2_error_threshold")
{
    using namespace intel_x64::msrs::ia32_mc27_ctl2;

    error_threshold::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(error_threshold::get() == (error_threshold::mask >> error_threshold::from));

    error_threshold::set(error_threshold::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(error_threshold::get(error_threshold::mask) == (error_threshold::mask >> error_threshold::from));
}

TEST_CASE("ia32_mc27_ctl2_cmci_en")
{
    using namespace intel_x64::msrs::ia32_mc27_ctl2;

    cmci_en::enable();
    CHECK(cmci_en::is_enabled());
    cmci_en::disable();
    CHECK(cmci_en::is_disabled());

    cmci_en::enable(cmci_en::mask);
    CHECK(cmci_en::is_enabled(cmci_en::mask));
    cmci_en::disable(0x0);
    CHECK(cmci_en::is_disabled(0x0));
}

TEST_CASE("ia32_mc28_ctl2")
{
    using namespace intel_x64::msrs::ia32_mc28_ctl2;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc28_ctl2_error_threshold")
{
    using namespace intel_x64::msrs::ia32_mc28_ctl2;

    error_threshold::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(error_threshold::get() == (error_threshold::mask >> error_threshold::from));

    error_threshold::set(error_threshold::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(error_threshold::get(error_threshold::mask) == (error_threshold::mask >> error_threshold::from));
}

TEST_CASE("ia32_mc28_ctl2_cmci_en")
{
    using namespace intel_x64::msrs::ia32_mc28_ctl2;

    cmci_en::enable();
    CHECK(cmci_en::is_enabled());
    cmci_en::disable();
    CHECK(cmci_en::is_disabled());

    cmci_en::enable(cmci_en::mask);
    CHECK(cmci_en::is_enabled(cmci_en::mask));
    cmci_en::disable(0x0);
    CHECK(cmci_en::is_disabled(0x0));
}

TEST_CASE("ia32_mc29_ctl2")
{
    using namespace intel_x64::msrs::ia32_mc29_ctl2;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc29_ctl2_error_threshold")
{
    using namespace intel_x64::msrs::ia32_mc29_ctl2;

    error_threshold::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(error_threshold::get() == (error_threshold::mask >> error_threshold::from));

    error_threshold::set(error_threshold::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(error_threshold::get(error_threshold::mask) == (error_threshold::mask >> error_threshold::from));
}

TEST_CASE("ia32_mc29_ctl2_cmci_en")
{
    using namespace intel_x64::msrs::ia32_mc29_ctl2;

    cmci_en::enable();
    CHECK(cmci_en::is_enabled());
    cmci_en::disable();
    CHECK(cmci_en::is_disabled());

    cmci_en::enable(cmci_en::mask);
    CHECK(cmci_en::is_enabled(cmci_en::mask));
    cmci_en::disable(0x0);
    CHECK(cmci_en::is_disabled(0x0));
}

TEST_CASE("ia32_mc30_ctl2")
{
    using namespace intel_x64::msrs::ia32_mc30_ctl2;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc30_ctl2_error_threshold")
{
    using namespace intel_x64::msrs::ia32_mc30_ctl2;

    error_threshold::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(error_threshold::get() == (error_threshold::mask >> error_threshold::from));

    error_threshold::set(error_threshold::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(error_threshold::get(error_threshold::mask) == (error_threshold::mask >> error_threshold::from));
}

TEST_CASE("ia32_mc30_ctl2_cmci_en")
{
    using namespace intel_x64::msrs::ia32_mc30_ctl2;

    cmci_en::enable();
    CHECK(cmci_en::is_enabled());
    cmci_en::disable();
    CHECK(cmci_en::is_disabled());

    cmci_en::enable(cmci_en::mask);
    CHECK(cmci_en::is_enabled(cmci_en::mask));
    cmci_en::disable(0x0);
    CHECK(cmci_en::is_disabled(0x0));
}

TEST_CASE("ia32_mc31_ctl2")
{
    using namespace intel_x64::msrs::ia32_mc31_ctl2;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc31_ctl2_error_threshold")
{
    using namespace intel_x64::msrs::ia32_mc31_ctl2;

    error_threshold::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(error_threshold::get() == (error_threshold::mask >> error_threshold::from));

    error_threshold::set(error_threshold::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(error_threshold::get(error_threshold::mask) == (error_threshold::mask >> error_threshold::from));
}

TEST_CASE("ia32_mc31_ctl2_cmci_en")
{
    using namespace intel_x64::msrs::ia32_mc31_ctl2;

    cmci_en::enable();
    CHECK(cmci_en::is_enabled());
    cmci_en::disable();
    CHECK(cmci_en::is_disabled());

    cmci_en::enable(cmci_en::mask);
    CHECK(cmci_en::is_enabled(cmci_en::mask));
    cmci_en::disable(0x0);
    CHECK(cmci_en::is_disabled(0x0));
}

TEST_CASE("ia32_mtrr_def_type")
{
    using namespace intel_x64::msrs::ia32_mtrr_def_type;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mtrr_def_type_def_mem_type")
{
    using namespace intel_x64::msrs::ia32_mtrr_def_type;

    def_mem_type::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(def_mem_type::get() == (def_mem_type::mask >> def_mem_type::from));

    def_mem_type::set(def_mem_type::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(def_mem_type::get(def_mem_type::mask) == (def_mem_type::mask >> def_mem_type::from));
}

TEST_CASE("ia32_mtrr_def_type_fixed_range_mtrr")
{
    using namespace intel_x64::msrs::ia32_mtrr_def_type;

    fixed_range_mtrr::enable();
    CHECK(fixed_range_mtrr::is_enabled());
    fixed_range_mtrr::disable();
    CHECK(fixed_range_mtrr::is_disabled());

    fixed_range_mtrr::enable(fixed_range_mtrr::mask);
    CHECK(fixed_range_mtrr::is_enabled(fixed_range_mtrr::mask));
    fixed_range_mtrr::disable(0x0);
    CHECK(fixed_range_mtrr::is_disabled(0x0));
}

TEST_CASE("ia32_mtrr_def_type_mtrr")
{
    using namespace intel_x64::msrs::ia32_mtrr_def_type;

    mtrr::enable();
    CHECK(mtrr::is_enabled());
    mtrr::disable();
    CHECK(mtrr::is_disabled());

    mtrr::enable(mtrr::mask);
    CHECK(mtrr::is_enabled(mtrr::mask));
    mtrr::disable(0x0);
    CHECK(mtrr::is_disabled(0x0));
}

TEST_CASE("ia32_fixed_ctr0")
{
    using namespace intel_x64::msrs::ia32_fixed_ctr0;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_fixed_ctr1")
{
    using namespace intel_x64::msrs::ia32_fixed_ctr1;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_fixed_ctr2")
{
    using namespace intel_x64::msrs::ia32_fixed_ctr2;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_perf_capabilities")
{
    using namespace intel_x64::msrs::ia32_perf_capabilities;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_perf_capabilities_lbo_format")
{
    using namespace intel_x64::msrs::ia32_perf_capabilities;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(lbo_format::get() == (lbo_format::mask >> lbo_format::from));

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(lbo_format::get(lbo_format::mask) == (lbo_format::mask >> lbo_format::from));
}

TEST_CASE("ia32_perf_capabilities_pebs_trap")
{
    using namespace intel_x64::msrs::ia32_perf_capabilities;

    g_msrs[addr] = pebs_trap::mask;
    CHECK(pebs_trap::is_enabled());
    g_msrs[addr] = 0x0;
    CHECK(pebs_trap::is_disabled());

    g_msrs[addr] = pebs_trap::mask;
    CHECK(pebs_trap::is_enabled(pebs_trap::mask));
    g_msrs[addr] = 0x0;
    CHECK(pebs_trap::is_disabled(0x0));
}

TEST_CASE("ia32_perf_capabilities_pebs_savearchregs")
{
    using namespace intel_x64::msrs::ia32_perf_capabilities;

    g_msrs[addr] = pebs_savearchregs::mask;
    CHECK(pebs_savearchregs::is_enabled());
    g_msrs[addr] = 0x0;
    CHECK(pebs_savearchregs::is_disabled());

    g_msrs[addr] = pebs_savearchregs::mask;
    CHECK(pebs_savearchregs::is_enabled(pebs_savearchregs::mask));
    g_msrs[addr] = 0x0;
    CHECK(pebs_savearchregs::is_disabled(0x0));
}

TEST_CASE("ia32_perf_capabilities_pebs_record_format")
{
    using namespace intel_x64::msrs::ia32_perf_capabilities;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(pebs_record_format::get() == (pebs_record_format::mask >> pebs_record_format::from));

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(pebs_record_format::get(pebs_record_format::mask) == (pebs_record_format::mask >> pebs_record_format::from));
}

TEST_CASE("ia32_perf_capabilities_freeze")
{
    using namespace intel_x64::msrs::ia32_perf_capabilities;

    g_msrs[addr] = freeze::mask;
    CHECK(freeze::is_enabled());
    g_msrs[addr] = 0x0;
    CHECK(freeze::is_disabled());

    g_msrs[addr] = freeze::mask;
    CHECK(freeze::is_enabled(freeze::mask));
    g_msrs[addr] = 0x0;
    CHECK(freeze::is_disabled(0x0));
}

TEST_CASE("ia32_perf_capabilities_counter_width")
{
    using namespace intel_x64::msrs::ia32_perf_capabilities;

    g_msrs[addr] = counter_width::mask;
    CHECK(counter_width::is_enabled());
    g_msrs[addr] = 0x0;
    CHECK(counter_width::is_disabled());

    g_msrs[addr] = counter_width::mask;
    CHECK(counter_width::is_enabled(counter_width::mask));
    g_msrs[addr] = 0x0;
    CHECK(counter_width::is_disabled(0x0));
}

TEST_CASE("ia32_fixed_ctr_ctrl")
{
    using namespace intel_x64::msrs::ia32_fixed_ctr_ctrl;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_fixed_ctr_ctrl_en0_os")
{
    using namespace intel_x64::msrs::ia32_fixed_ctr_ctrl;

    en0_os::enable();
    CHECK(en0_os::is_enabled());
    en0_os::disable();
    CHECK(en0_os::is_disabled());

    en0_os::enable(en0_os::mask);
    CHECK(en0_os::is_enabled(en0_os::mask));
    en0_os::disable(0x0);
    CHECK(en0_os::is_disabled(0x0));
}

TEST_CASE("ia32_fixed_ctr_ctrl_en0_usr")
{
    using namespace intel_x64::msrs::ia32_fixed_ctr_ctrl;

    en0_usr::enable();
    CHECK(en0_usr::is_enabled());
    en0_usr::disable();
    CHECK(en0_usr::is_disabled());

    en0_usr::enable(en0_usr::mask);
    CHECK(en0_usr::is_enabled(en0_usr::mask));
    en0_usr::disable(0x0);
    CHECK(en0_usr::is_disabled(0x0));
}

TEST_CASE("ia32_fixed_ctr_ctrl_en0_anythread")
{
    using namespace intel_x64::msrs::ia32_fixed_ctr_ctrl;

    en0_anythread::enable();
    CHECK(en0_anythread::is_enabled());
    en0_anythread::disable();
    CHECK(en0_anythread::is_disabled());

    en0_anythread::enable(en0_anythread::mask);
    CHECK(en0_anythread::is_enabled(en0_anythread::mask));
    en0_anythread::disable(0x0);
    CHECK(en0_anythread::is_disabled(0x0));
}

TEST_CASE("ia32_fixed_ctr_ctrl_en0_pmi")
{
    using namespace intel_x64::msrs::ia32_fixed_ctr_ctrl;

    en0_pmi::enable();
    CHECK(en0_pmi::is_enabled());
    en0_pmi::disable();
    CHECK(en0_pmi::is_disabled());

    en0_pmi::enable(en0_pmi::mask);
    CHECK(en0_pmi::is_enabled(en0_pmi::mask));
    en0_pmi::disable(0x0);
    CHECK(en0_pmi::is_disabled(0x0));
}

TEST_CASE("ia32_fixed_ctr_ctrl_en1_os")
{
    using namespace intel_x64::msrs::ia32_fixed_ctr_ctrl;

    en1_os::enable();
    CHECK(en1_os::is_enabled());
    en1_os::disable();
    CHECK(en1_os::is_disabled());

    en1_os::enable(en1_os::mask);
    CHECK(en1_os::is_enabled(en1_os::mask));
    en1_os::disable(0x0);
    CHECK(en1_os::is_disabled(0x0));
}

TEST_CASE("ia32_fixed_ctr_ctrl_en1_usr")
{
    using namespace intel_x64::msrs::ia32_fixed_ctr_ctrl;

    en1_usr::enable();
    CHECK(en1_usr::is_enabled());
    en1_usr::disable();
    CHECK(en1_usr::is_disabled());

    en1_usr::enable(en1_usr::mask);
    CHECK(en1_usr::is_enabled(en1_usr::mask));
    en1_usr::disable(0x0);
    CHECK(en1_usr::is_disabled(0x0));
}

TEST_CASE("ia32_fixed_ctr_ctrl_en1_anythread")
{
    using namespace intel_x64::msrs::ia32_fixed_ctr_ctrl;

    en1_anythread::enable();
    CHECK(en1_anythread::is_enabled());
    en1_anythread::disable();
    CHECK(en1_anythread::is_disabled());

    en1_anythread::enable(en1_anythread::mask);
    CHECK(en1_anythread::is_enabled(en1_anythread::mask));
    en1_anythread::disable(0x0);
    CHECK(en1_anythread::is_disabled(0x0));
}

TEST_CASE("ia32_fixed_ctr_ctrl_en1_pmi")
{
    using namespace intel_x64::msrs::ia32_fixed_ctr_ctrl;

    en1_pmi::enable();
    CHECK(en1_pmi::is_enabled());
    en1_pmi::disable();
    CHECK(en1_pmi::is_disabled());

    en1_pmi::enable(en1_pmi::mask);
    CHECK(en1_pmi::is_enabled(en1_pmi::mask));
    en1_pmi::disable(0x0);
    CHECK(en1_pmi::is_disabled(0x0));
}

TEST_CASE("ia32_fixed_ctr_ctrl_en2_os")
{
    using namespace intel_x64::msrs::ia32_fixed_ctr_ctrl;

    en2_os::enable();
    CHECK(en2_os::is_enabled());
    en2_os::disable();
    CHECK(en2_os::is_disabled());

    en2_os::enable(en2_os::mask);
    CHECK(en2_os::is_enabled(en2_os::mask));
    en2_os::disable(0x0);
    CHECK(en2_os::is_disabled(0x0));
}

TEST_CASE("ia32_fixed_ctr_ctrl_en2_usr")
{
    using namespace intel_x64::msrs::ia32_fixed_ctr_ctrl;

    en2_usr::enable();
    CHECK(en2_usr::is_enabled());
    en2_usr::disable();
    CHECK(en2_usr::is_disabled());

    en2_usr::enable(en2_usr::mask);
    CHECK(en2_usr::is_enabled(en2_usr::mask));
    en2_usr::disable(0x0);
    CHECK(en2_usr::is_disabled(0x0));
}

TEST_CASE("ia32_fixed_ctr_ctrl_en2_anythread")
{
    using namespace intel_x64::msrs::ia32_fixed_ctr_ctrl;

    en2_anythread::enable();
    CHECK(en2_anythread::is_enabled());
    en2_anythread::disable();
    CHECK(en2_anythread::is_disabled());

    en2_anythread::enable(en2_anythread::mask);
    CHECK(en2_anythread::is_enabled(en2_anythread::mask));
    en2_anythread::disable(0x0);
    CHECK(en2_anythread::is_disabled(0x0));
}

TEST_CASE("ia32_fixed_ctr_ctrl_en2_pmi")
{
    using namespace intel_x64::msrs::ia32_fixed_ctr_ctrl;

    en2_pmi::enable();
    CHECK(en2_pmi::is_enabled());
    en2_pmi::disable();
    CHECK(en2_pmi::is_disabled());

    en2_pmi::enable(en2_pmi::mask);
    CHECK(en2_pmi::is_enabled(en2_pmi::mask));
    en2_pmi::disable(0x0);
    CHECK(en2_pmi::is_disabled(0x0));
}

TEST_CASE("ia32_perf_global_status")
{
    using namespace intel_x64::msrs::ia32_perf_global_status;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_perf_global_status_ovf_pmc0")
{
    using namespace intel_x64::msrs::ia32_perf_global_status;

    ovf_pmc0::enable();
    CHECK(ovf_pmc0::is_enabled());
    ovf_pmc0::disable();
    CHECK(ovf_pmc0::is_disabled());

    ovf_pmc0::enable(ovf_pmc0::mask);
    CHECK(ovf_pmc0::is_enabled(ovf_pmc0::mask));
    ovf_pmc0::disable(0x0);
    CHECK(ovf_pmc0::is_disabled(0x0));
}

TEST_CASE("ia32_perf_global_status_ovf_pmc1")
{
    using namespace intel_x64::msrs::ia32_perf_global_status;

    ovf_pmc1::enable();
    CHECK(ovf_pmc1::is_enabled());
    ovf_pmc1::disable();
    CHECK(ovf_pmc1::is_disabled());

    ovf_pmc1::enable(ovf_pmc1::mask);
    CHECK(ovf_pmc1::is_enabled(ovf_pmc1::mask));
    ovf_pmc1::disable(0x0);
    CHECK(ovf_pmc1::is_disabled(0x0));
}

TEST_CASE("ia32_perf_global_status_ovf_pmc2")
{
    using namespace intel_x64::msrs::ia32_perf_global_status;

    ovf_pmc2::enable();
    CHECK(ovf_pmc2::is_enabled());
    ovf_pmc2::disable();
    CHECK(ovf_pmc2::is_disabled());

    ovf_pmc2::enable(ovf_pmc2::mask);
    CHECK(ovf_pmc2::is_enabled(ovf_pmc2::mask));
    ovf_pmc2::disable(0x0);
    CHECK(ovf_pmc2::is_disabled(0x0));
}

TEST_CASE("ia32_perf_global_status_ovf_pmc3")
{
    using namespace intel_x64::msrs::ia32_perf_global_status;

    ovf_pmc3::enable();
    CHECK(ovf_pmc3::is_enabled());
    ovf_pmc3::disable();
    CHECK(ovf_pmc3::is_disabled());

    ovf_pmc3::enable(ovf_pmc3::mask);
    CHECK(ovf_pmc3::is_enabled(ovf_pmc3::mask));
    ovf_pmc3::disable(0x0);
    CHECK(ovf_pmc3::is_disabled(0x0));
}

TEST_CASE("ia32_perf_global_status_ovf_fixedctr0")
{
    using namespace intel_x64::msrs::ia32_perf_global_status;

    ovf_fixedctr0::enable();
    CHECK(ovf_fixedctr0::is_enabled());
    ovf_fixedctr0::disable();
    CHECK(ovf_fixedctr0::is_disabled());

    ovf_fixedctr0::enable(ovf_fixedctr0::mask);
    CHECK(ovf_fixedctr0::is_enabled(ovf_fixedctr0::mask));
    ovf_fixedctr0::disable(0x0);
    CHECK(ovf_fixedctr0::is_disabled(0x0));
}

TEST_CASE("ia32_perf_global_status_ovf_fixedctr1")
{
    using namespace intel_x64::msrs::ia32_perf_global_status;

    ovf_fixedctr1::enable();
    CHECK(ovf_fixedctr1::is_enabled());
    ovf_fixedctr1::disable();
    CHECK(ovf_fixedctr1::is_disabled());

    ovf_fixedctr1::enable(ovf_fixedctr1::mask);
    CHECK(ovf_fixedctr1::is_enabled(ovf_fixedctr1::mask));
    ovf_fixedctr1::disable(0x0);
    CHECK(ovf_fixedctr1::is_disabled(0x0));
}

TEST_CASE("ia32_perf_global_status_ovf_fixedctr2")
{
    using namespace intel_x64::msrs::ia32_perf_global_status;

    ovf_fixedctr2::enable();
    CHECK(ovf_fixedctr2::is_enabled());
    ovf_fixedctr2::disable();
    CHECK(ovf_fixedctr2::is_disabled());

    ovf_fixedctr2::enable(ovf_fixedctr2::mask);
    CHECK(ovf_fixedctr2::is_enabled(ovf_fixedctr2::mask));
    ovf_fixedctr2::disable(0x0);
    CHECK(ovf_fixedctr2::is_disabled(0x0));
}

TEST_CASE("ia32_perf_global_status_trace_topa_pmi")
{
    using namespace intel_x64::msrs::ia32_perf_global_status;

    trace_topa_pmi::enable();
    CHECK(trace_topa_pmi::is_enabled());
    trace_topa_pmi::disable();
    CHECK(trace_topa_pmi::is_disabled());

    trace_topa_pmi::enable(trace_topa_pmi::mask);
    CHECK(trace_topa_pmi::is_enabled(trace_topa_pmi::mask));
    trace_topa_pmi::disable(0x0);
    CHECK(trace_topa_pmi::is_disabled(0x0));
}

TEST_CASE("ia32_perf_global_status_lbr_frz")
{
    using namespace intel_x64::msrs::ia32_perf_global_status;

    lbr_frz::enable();
    CHECK(lbr_frz::is_enabled());
    lbr_frz::disable();
    CHECK(lbr_frz::is_disabled());

    lbr_frz::enable(lbr_frz::mask);
    CHECK(lbr_frz::is_enabled(lbr_frz::mask));
    lbr_frz::disable(0x0);
    CHECK(lbr_frz::is_disabled(0x0));
}

TEST_CASE("ia32_perf_global_status_ctr_frz")
{
    using namespace intel_x64::msrs::ia32_perf_global_status;

    ctr_frz::enable();
    CHECK(ctr_frz::is_enabled());
    ctr_frz::disable();
    CHECK(ctr_frz::is_disabled());

    ctr_frz::enable(ctr_frz::mask);
    CHECK(ctr_frz::is_enabled(ctr_frz::mask));
    ctr_frz::disable(0x0);
    CHECK(ctr_frz::is_disabled(0x0));
}

TEST_CASE("ia32_perf_global_status_asci")
{
    using namespace intel_x64::msrs::ia32_perf_global_status;

    asci::enable();
    CHECK(asci::is_enabled());
    asci::disable();
    CHECK(asci::is_disabled());

    asci::enable(asci::mask);
    CHECK(asci::is_enabled(asci::mask));
    asci::disable(0x0);
    CHECK(asci::is_disabled(0x0));
}

TEST_CASE("ia32_perf_global_status_ovf_uncore")
{
    using namespace intel_x64::msrs::ia32_perf_global_status;

    ovf_uncore::enable();
    CHECK(ovf_uncore::is_enabled());
    ovf_uncore::disable();
    CHECK(ovf_uncore::is_disabled());

    ovf_uncore::enable(ovf_uncore::mask);
    CHECK(ovf_uncore::is_enabled(ovf_uncore::mask));
    ovf_uncore::disable(0x0);
    CHECK(ovf_uncore::is_disabled(0x0));
}

TEST_CASE("ia32_perf_global_status_ovfbuf")
{
    using namespace intel_x64::msrs::ia32_perf_global_status;

    ovfbuf::enable();
    CHECK(ovfbuf::is_enabled());
    ovfbuf::disable();
    CHECK(ovfbuf::is_disabled());

    ovfbuf::enable(ovfbuf::mask);
    CHECK(ovfbuf::is_enabled(ovfbuf::mask));
    ovfbuf::disable(0x0);
    CHECK(ovfbuf::is_disabled(0x0));
}

TEST_CASE("ia32_perf_global_status_condchgd")
{
    using namespace intel_x64::msrs::ia32_perf_global_status;

    condchgd::enable();
    CHECK(condchgd::is_enabled());
    condchgd::disable();
    CHECK(condchgd::is_disabled());

    condchgd::enable(condchgd::mask);
    CHECK(condchgd::is_enabled(condchgd::mask));
    condchgd::disable(0x0);
    CHECK(condchgd::is_disabled(0x0));
}

TEST_CASE("ia32_perf_global_ctrl")
{
    using namespace intel_x64::msrs::ia32_perf_global_ctrl;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_perf_global_ctrl_pmc0")
{
    using namespace intel_x64::msrs::ia32_perf_global_ctrl;

    pmc0::enable();
    CHECK(pmc0::is_enabled());
    pmc0::disable();
    CHECK(pmc0::is_disabled());

    pmc0::enable(pmc0::mask);
    CHECK(pmc0::is_enabled(pmc0::mask));
    pmc0::disable(0x0);
    CHECK(pmc0::is_disabled(0x0));
}

TEST_CASE("ia32_perf_global_ctrl_pmc1")
{
    using namespace intel_x64::msrs::ia32_perf_global_ctrl;

    pmc1::enable();
    CHECK(pmc1::is_enabled());
    pmc1::disable();
    CHECK(pmc1::is_disabled());

    pmc1::enable(pmc1::mask);
    CHECK(pmc1::is_enabled(pmc1::mask));
    pmc1::disable(0x0);
    CHECK(pmc1::is_disabled(0x0));
}

TEST_CASE("ia32_perf_global_ctrl_pmc2")
{
    using namespace intel_x64::msrs::ia32_perf_global_ctrl;

    pmc2::enable();
    CHECK(pmc2::is_enabled());
    pmc2::disable();
    CHECK(pmc2::is_disabled());

    pmc2::enable(pmc2::mask);
    CHECK(pmc2::is_enabled(pmc2::mask));
    pmc2::disable(0x0);
    CHECK(pmc2::is_disabled(0x0));
}

TEST_CASE("ia32_perf_global_ctrl_pmc3")
{
    using namespace intel_x64::msrs::ia32_perf_global_ctrl;

    pmc3::enable();
    CHECK(pmc3::is_enabled());
    pmc3::disable();
    CHECK(pmc3::is_disabled());

    pmc3::enable(pmc3::mask);
    CHECK(pmc3::is_enabled(pmc3::mask));
    pmc3::disable(0x0);
    CHECK(pmc3::is_disabled(0x0));
}

TEST_CASE("ia32_perf_global_ctrl_pmc4")
{
    using namespace intel_x64::msrs::ia32_perf_global_ctrl;

    pmc4::enable();
    CHECK(pmc4::is_enabled());
    pmc4::disable();
    CHECK(pmc4::is_disabled());

    pmc4::enable(pmc4::mask);
    CHECK(pmc4::is_enabled(pmc4::mask));
    pmc4::disable(0x0);
    CHECK(pmc4::is_disabled(0x0));
}

TEST_CASE("ia32_perf_global_ctrl_pmc5")
{
    using namespace intel_x64::msrs::ia32_perf_global_ctrl;

    pmc5::enable();
    CHECK(pmc5::is_enabled());
    pmc5::disable();
    CHECK(pmc5::is_disabled());

    pmc5::enable(pmc5::mask);
    CHECK(pmc5::is_enabled(pmc5::mask));
    pmc5::disable(0x0);
    CHECK(pmc5::is_disabled(0x0));
}

TEST_CASE("ia32_perf_global_ctrl_pmc6")
{
    using namespace intel_x64::msrs::ia32_perf_global_ctrl;

    pmc6::enable();
    CHECK(pmc6::is_enabled());
    pmc6::disable();
    CHECK(pmc6::is_disabled());

    pmc6::enable(pmc6::mask);
    CHECK(pmc6::is_enabled(pmc6::mask));
    pmc6::disable(0x0);
    CHECK(pmc6::is_disabled(0x0));
}

TEST_CASE("ia32_perf_global_ctrl_pmc7")
{
    using namespace intel_x64::msrs::ia32_perf_global_ctrl;

    pmc7::enable();
    CHECK(pmc7::is_enabled());
    pmc7::disable();
    CHECK(pmc7::is_disabled());

    pmc7::enable(pmc7::mask);
    CHECK(pmc7::is_enabled(pmc7::mask));
    pmc7::disable(0x0);
    CHECK(pmc7::is_disabled(0x0));
}

TEST_CASE("ia32_perf_global_ctrl_fixed_ctr0")
{
    using namespace intel_x64::msrs::ia32_perf_global_ctrl;

    fixed_ctr0::enable();
    CHECK(fixed_ctr0::is_enabled());
    fixed_ctr0::disable();
    CHECK(fixed_ctr0::is_disabled());

    fixed_ctr0::enable(fixed_ctr0::mask);
    CHECK(fixed_ctr0::is_enabled(fixed_ctr0::mask));
    fixed_ctr0::disable(0x0);
    CHECK(fixed_ctr0::is_disabled(0x0));
}

TEST_CASE("ia32_perf_global_ctrl_fixed_ctr1")
{
    using namespace intel_x64::msrs::ia32_perf_global_ctrl;

    fixed_ctr1::enable();
    CHECK(fixed_ctr1::is_enabled());
    fixed_ctr1::disable();
    CHECK(fixed_ctr1::is_disabled());

    fixed_ctr1::enable(fixed_ctr1::mask);
    CHECK(fixed_ctr1::is_enabled(fixed_ctr1::mask));
    fixed_ctr1::disable(0x0);
    CHECK(fixed_ctr1::is_disabled(0x0));
}

TEST_CASE("ia32_perf_global_ctrl_fixed_ctr2")
{
    using namespace intel_x64::msrs::ia32_perf_global_ctrl;

    fixed_ctr2::enable();
    CHECK(fixed_ctr2::is_enabled());
    fixed_ctr2::disable();
    CHECK(fixed_ctr2::is_disabled());

    fixed_ctr2::enable(fixed_ctr2::mask);
    CHECK(fixed_ctr2::is_enabled(fixed_ctr2::mask));
    fixed_ctr2::disable(0x0);
    CHECK(fixed_ctr2::is_disabled(0x0));
}

TEST_CASE("ia32_perf_global_ovf_ctrl")
{
    using namespace intel_x64::msrs::ia32_perf_global_ovf_ctrl;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_perf_global_ovf_ctrl_clear_ovf_pmc0")
{
    using namespace intel_x64::msrs::ia32_perf_global_ovf_ctrl;

    clear_ovf_pmc0::enable();
    CHECK(clear_ovf_pmc0::is_enabled());
    clear_ovf_pmc0::disable();
    CHECK(clear_ovf_pmc0::is_disabled());

    clear_ovf_pmc0::enable(clear_ovf_pmc0::mask);
    CHECK(clear_ovf_pmc0::is_enabled(clear_ovf_pmc0::mask));
    clear_ovf_pmc0::disable(0x0);
    CHECK(clear_ovf_pmc0::is_disabled(0x0));
}

TEST_CASE("ia32_perf_global_ovf_ctrl_clear_ovf_pmc1")
{
    using namespace intel_x64::msrs::ia32_perf_global_ovf_ctrl;

    clear_ovf_pmc1::enable();
    CHECK(clear_ovf_pmc1::is_enabled());
    clear_ovf_pmc1::disable();
    CHECK(clear_ovf_pmc1::is_disabled());

    clear_ovf_pmc1::enable(clear_ovf_pmc1::mask);
    CHECK(clear_ovf_pmc1::is_enabled(clear_ovf_pmc1::mask));
    clear_ovf_pmc1::disable(0x0);
    CHECK(clear_ovf_pmc1::is_disabled(0x0));
}

TEST_CASE("ia32_perf_global_ovf_ctrl_clear_ovf_pmc2")
{
    using namespace intel_x64::msrs::ia32_perf_global_ovf_ctrl;

    clear_ovf_pmc2::enable();
    CHECK(clear_ovf_pmc2::is_enabled());
    clear_ovf_pmc2::disable();
    CHECK(clear_ovf_pmc2::is_disabled());

    clear_ovf_pmc2::enable(clear_ovf_pmc2::mask);
    CHECK(clear_ovf_pmc2::is_enabled(clear_ovf_pmc2::mask));
    clear_ovf_pmc2::disable(0x0);
    CHECK(clear_ovf_pmc2::is_disabled(0x0));
}

TEST_CASE("ia32_perf_global_ovf_ctrl_clear_ovf_fixed_ctr0")
{
    using namespace intel_x64::msrs::ia32_perf_global_ovf_ctrl;

    clear_ovf_fixed_ctr0::enable();
    CHECK(clear_ovf_fixed_ctr0::is_enabled());
    clear_ovf_fixed_ctr0::disable();
    CHECK(clear_ovf_fixed_ctr0::is_disabled());

    clear_ovf_fixed_ctr0::enable(clear_ovf_fixed_ctr0::mask);
    CHECK(clear_ovf_fixed_ctr0::is_enabled(clear_ovf_fixed_ctr0::mask));
    clear_ovf_fixed_ctr0::disable(0x0);
    CHECK(clear_ovf_fixed_ctr0::is_disabled(0x0));
}

TEST_CASE("ia32_perf_global_ovf_ctrl_clear_ovf_fixed_ctr1")
{
    using namespace intel_x64::msrs::ia32_perf_global_ovf_ctrl;

    clear_ovf_fixed_ctr1::enable();
    CHECK(clear_ovf_fixed_ctr1::is_enabled());
    clear_ovf_fixed_ctr1::disable();
    CHECK(clear_ovf_fixed_ctr1::is_disabled());

    clear_ovf_fixed_ctr1::enable(clear_ovf_fixed_ctr1::mask);
    CHECK(clear_ovf_fixed_ctr1::is_enabled(clear_ovf_fixed_ctr1::mask));
    clear_ovf_fixed_ctr1::disable(0x0);
    CHECK(clear_ovf_fixed_ctr1::is_disabled(0x0));
}

TEST_CASE("ia32_perf_global_ovf_ctrl_clear_ovf_fixed_ctr2")
{
    using namespace intel_x64::msrs::ia32_perf_global_ovf_ctrl;

    clear_ovf_fixed_ctr2::enable();
    CHECK(clear_ovf_fixed_ctr2::is_enabled());
    clear_ovf_fixed_ctr2::disable();
    CHECK(clear_ovf_fixed_ctr2::is_disabled());

    clear_ovf_fixed_ctr2::enable(clear_ovf_fixed_ctr2::mask);
    CHECK(clear_ovf_fixed_ctr2::is_enabled(clear_ovf_fixed_ctr2::mask));
    clear_ovf_fixed_ctr2::disable(0x0);
    CHECK(clear_ovf_fixed_ctr2::is_disabled(0x0));
}

TEST_CASE("ia32_perf_global_ovf_ctrl_clear_trace_topa_pmi")
{
    using namespace intel_x64::msrs::ia32_perf_global_ovf_ctrl;

    clear_trace_topa_pmi::enable();
    CHECK(clear_trace_topa_pmi::is_enabled());
    clear_trace_topa_pmi::disable();
    CHECK(clear_trace_topa_pmi::is_disabled());

    clear_trace_topa_pmi::enable(clear_trace_topa_pmi::mask);
    CHECK(clear_trace_topa_pmi::is_enabled(clear_trace_topa_pmi::mask));
    clear_trace_topa_pmi::disable(0x0);
    CHECK(clear_trace_topa_pmi::is_disabled(0x0));
}

TEST_CASE("ia32_perf_global_ovf_ctrl_lbr_frz")
{
    using namespace intel_x64::msrs::ia32_perf_global_ovf_ctrl;

    lbr_frz::enable();
    CHECK(lbr_frz::is_enabled());
    lbr_frz::disable();
    CHECK(lbr_frz::is_disabled());

    lbr_frz::enable(lbr_frz::mask);
    CHECK(lbr_frz::is_enabled(lbr_frz::mask));
    lbr_frz::disable(0x0);
    CHECK(lbr_frz::is_disabled(0x0));
}

TEST_CASE("ia32_perf_global_ovf_ctrl_ctr_frz")
{
    using namespace intel_x64::msrs::ia32_perf_global_ovf_ctrl;

    ctr_frz::enable();
    CHECK(ctr_frz::is_enabled());
    ctr_frz::disable();
    CHECK(ctr_frz::is_disabled());

    ctr_frz::enable(ctr_frz::mask);
    CHECK(ctr_frz::is_enabled(ctr_frz::mask));
    ctr_frz::disable(0x0);
    CHECK(ctr_frz::is_disabled(0x0));
}

TEST_CASE("ia32_perf_global_ovf_ctrl_clear_ovf_uncore")
{
    using namespace intel_x64::msrs::ia32_perf_global_ovf_ctrl;

    clear_ovf_uncore::enable();
    CHECK(clear_ovf_uncore::is_enabled());
    clear_ovf_uncore::disable();
    CHECK(clear_ovf_uncore::is_disabled());

    clear_ovf_uncore::enable(clear_ovf_uncore::mask);
    CHECK(clear_ovf_uncore::is_enabled(clear_ovf_uncore::mask));
    clear_ovf_uncore::disable(0x0);
    CHECK(clear_ovf_uncore::is_disabled(0x0));
}

TEST_CASE("ia32_perf_global_ovf_ctrl_clear_ovfbuf")
{
    using namespace intel_x64::msrs::ia32_perf_global_ovf_ctrl;

    clear_ovfbuf::enable();
    CHECK(clear_ovfbuf::is_enabled());
    clear_ovfbuf::disable();
    CHECK(clear_ovfbuf::is_disabled());

    clear_ovfbuf::enable(clear_ovfbuf::mask);
    CHECK(clear_ovfbuf::is_enabled(clear_ovfbuf::mask));
    clear_ovfbuf::disable(0x0);
    CHECK(clear_ovfbuf::is_disabled(0x0));
}

TEST_CASE("ia32_perf_global_ovf_ctrl_clear_condchgd")
{
    using namespace intel_x64::msrs::ia32_perf_global_ovf_ctrl;

    clear_condchgd::enable();
    CHECK(clear_condchgd::is_enabled());
    clear_condchgd::disable();
    CHECK(clear_condchgd::is_disabled());

    clear_condchgd::enable(clear_condchgd::mask);
    CHECK(clear_condchgd::is_enabled(clear_condchgd::mask));
    clear_condchgd::disable(0x0);
    CHECK(clear_condchgd::is_disabled(0x0));
}

TEST_CASE("ia32_perf_global_status_set")
{
    using namespace intel_x64::msrs::ia32_perf_global_status_set;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_perf_global_status_set_ovf_pmc0")
{
    using namespace intel_x64::msrs::ia32_perf_global_status_set;

    ovf_pmc0::enable();
    CHECK(ovf_pmc0::is_enabled());
    ovf_pmc0::disable();
    CHECK(ovf_pmc0::is_disabled());

    ovf_pmc0::enable(ovf_pmc0::mask);
    CHECK(ovf_pmc0::is_enabled(ovf_pmc0::mask));
    ovf_pmc0::disable(0x0);
    CHECK(ovf_pmc0::is_disabled(0x0));
}

TEST_CASE("ia32_perf_global_status_set_ovf_pmc1")
{
    using namespace intel_x64::msrs::ia32_perf_global_status_set;

    ovf_pmc1::enable();
    CHECK(ovf_pmc1::is_enabled());
    ovf_pmc1::disable();
    CHECK(ovf_pmc1::is_disabled());

    ovf_pmc1::enable(ovf_pmc1::mask);
    CHECK(ovf_pmc1::is_enabled(ovf_pmc1::mask));
    ovf_pmc1::disable(0x0);
    CHECK(ovf_pmc1::is_disabled(0x0));
}

TEST_CASE("ia32_perf_global_status_set_ovf_pmc2")
{
    using namespace intel_x64::msrs::ia32_perf_global_status_set;

    ovf_pmc2::enable();
    CHECK(ovf_pmc2::is_enabled());
    ovf_pmc2::disable();
    CHECK(ovf_pmc2::is_disabled());

    ovf_pmc2::enable(ovf_pmc2::mask);
    CHECK(ovf_pmc2::is_enabled(ovf_pmc2::mask));
    ovf_pmc2::disable(0x0);
    CHECK(ovf_pmc2::is_disabled(0x0));
}

TEST_CASE("ia32_perf_global_status_set_ovf_fixed_ctr0")
{
    using namespace intel_x64::msrs::ia32_perf_global_status_set;

    ovf_fixed_ctr0::enable();
    CHECK(ovf_fixed_ctr0::is_enabled());
    ovf_fixed_ctr0::disable();
    CHECK(ovf_fixed_ctr0::is_disabled());

    ovf_fixed_ctr0::enable(ovf_fixed_ctr0::mask);
    CHECK(ovf_fixed_ctr0::is_enabled(ovf_fixed_ctr0::mask));
    ovf_fixed_ctr0::disable(0x0);
    CHECK(ovf_fixed_ctr0::is_disabled(0x0));
}

TEST_CASE("ia32_perf_global_status_set_ovf_fixed_ctr1")
{
    using namespace intel_x64::msrs::ia32_perf_global_status_set;

    ovf_fixed_ctr1::enable();
    CHECK(ovf_fixed_ctr1::is_enabled());
    ovf_fixed_ctr1::disable();
    CHECK(ovf_fixed_ctr1::is_disabled());

    ovf_fixed_ctr1::enable(ovf_fixed_ctr1::mask);
    CHECK(ovf_fixed_ctr1::is_enabled(ovf_fixed_ctr1::mask));
    ovf_fixed_ctr1::disable(0x0);
    CHECK(ovf_fixed_ctr1::is_disabled(0x0));
}

TEST_CASE("ia32_perf_global_status_set_ovf_fixed_ctr2")
{
    using namespace intel_x64::msrs::ia32_perf_global_status_set;

    ovf_fixed_ctr2::enable();
    CHECK(ovf_fixed_ctr2::is_enabled());
    ovf_fixed_ctr2::disable();
    CHECK(ovf_fixed_ctr2::is_disabled());

    ovf_fixed_ctr2::enable(ovf_fixed_ctr2::mask);
    CHECK(ovf_fixed_ctr2::is_enabled(ovf_fixed_ctr2::mask));
    ovf_fixed_ctr2::disable(0x0);
    CHECK(ovf_fixed_ctr2::is_disabled(0x0));
}

TEST_CASE("ia32_perf_global_status_set_trace_topa_pmi")
{
    using namespace intel_x64::msrs::ia32_perf_global_status_set;

    trace_topa_pmi::enable();
    CHECK(trace_topa_pmi::is_enabled());
    trace_topa_pmi::disable();
    CHECK(trace_topa_pmi::is_disabled());

    trace_topa_pmi::enable(trace_topa_pmi::mask);
    CHECK(trace_topa_pmi::is_enabled(trace_topa_pmi::mask));
    trace_topa_pmi::disable(0x0);
    CHECK(trace_topa_pmi::is_disabled(0x0));
}

TEST_CASE("ia32_perf_global_status_set_lbr_frz")
{
    using namespace intel_x64::msrs::ia32_perf_global_status_set;

    lbr_frz::enable();
    CHECK(lbr_frz::is_enabled());
    lbr_frz::disable();
    CHECK(lbr_frz::is_disabled());

    lbr_frz::enable(lbr_frz::mask);
    CHECK(lbr_frz::is_enabled(lbr_frz::mask));
    lbr_frz::disable(0x0);
    CHECK(lbr_frz::is_disabled(0x0));
}

TEST_CASE("ia32_perf_global_status_set_ctr_frz")
{
    using namespace intel_x64::msrs::ia32_perf_global_status_set;

    ctr_frz::enable();
    CHECK(ctr_frz::is_enabled());
    ctr_frz::disable();
    CHECK(ctr_frz::is_disabled());

    ctr_frz::enable(ctr_frz::mask);
    CHECK(ctr_frz::is_enabled(ctr_frz::mask));
    ctr_frz::disable(0x0);
    CHECK(ctr_frz::is_disabled(0x0));
}

TEST_CASE("ia32_perf_global_status_set_ovf_uncore")
{
    using namespace intel_x64::msrs::ia32_perf_global_status_set;

    ovf_uncore::enable();
    CHECK(ovf_uncore::is_enabled());
    ovf_uncore::disable();
    CHECK(ovf_uncore::is_disabled());

    ovf_uncore::enable(ovf_uncore::mask);
    CHECK(ovf_uncore::is_enabled(ovf_uncore::mask));
    ovf_uncore::disable(0x0);
    CHECK(ovf_uncore::is_disabled(0x0));
}

TEST_CASE("ia32_perf_global_status_set_ovfbuf")
{
    using namespace intel_x64::msrs::ia32_perf_global_status_set;

    ovfbuf::enable();
    CHECK(ovfbuf::is_enabled());
    ovfbuf::disable();
    CHECK(ovfbuf::is_disabled());

    ovfbuf::enable(ovfbuf::mask);
    CHECK(ovfbuf::is_enabled(ovfbuf::mask));
    ovfbuf::disable(0x0);
    CHECK(ovfbuf::is_disabled(0x0));
}

TEST_CASE("ia32_perf_global_inuse")
{
    using namespace intel_x64::msrs::ia32_perf_global_inuse;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_perf_global_inuse_perfevtsel0")
{
    using namespace intel_x64::msrs::ia32_perf_global_inuse;

    g_msrs[addr] = perfevtsel0::mask;
    CHECK(perfevtsel0::is_enabled());
    g_msrs[addr] = 0x0;
    CHECK(perfevtsel0::is_disabled());

    g_msrs[addr] = perfevtsel0::mask;
    CHECK(perfevtsel0::is_enabled(perfevtsel0::mask));
    g_msrs[addr] = 0x0;
    CHECK(perfevtsel0::is_disabled(0x0));
}

TEST_CASE("ia32_perf_global_inuse_perfevtsel1")
{
    using namespace intel_x64::msrs::ia32_perf_global_inuse;

    g_msrs[addr] = perfevtsel1::mask;
    CHECK(perfevtsel1::is_enabled());
    g_msrs[addr] = 0x0;
    CHECK(perfevtsel1::is_disabled());

    g_msrs[addr] = perfevtsel1::mask;
    CHECK(perfevtsel1::is_enabled(perfevtsel1::mask));
    g_msrs[addr] = 0x0;
    CHECK(perfevtsel1::is_disabled(0x0));
}

TEST_CASE("ia32_perf_global_inuse_perfevtsel2")
{
    using namespace intel_x64::msrs::ia32_perf_global_inuse;

    g_msrs[addr] = perfevtsel2::mask;
    CHECK(perfevtsel2::is_enabled());
    g_msrs[addr] = 0x0;
    CHECK(perfevtsel2::is_disabled());

    g_msrs[addr] = perfevtsel2::mask;
    CHECK(perfevtsel2::is_enabled(perfevtsel2::mask));
    g_msrs[addr] = 0x0;
    CHECK(perfevtsel2::is_disabled(0x0));
}

TEST_CASE("ia32_perf_global_inuse_fixed_ctr0")
{
    using namespace intel_x64::msrs::ia32_perf_global_inuse;

    g_msrs[addr] = fixed_ctr0::mask;
    CHECK(fixed_ctr0::is_enabled());
    g_msrs[addr] = 0x0;
    CHECK(fixed_ctr0::is_disabled());

    g_msrs[addr] = fixed_ctr0::mask;
    CHECK(fixed_ctr0::is_enabled(fixed_ctr0::mask));
    g_msrs[addr] = 0x0;
    CHECK(fixed_ctr0::is_disabled(0x0));
}

TEST_CASE("ia32_perf_global_inuse_fixed_ctr1")
{
    using namespace intel_x64::msrs::ia32_perf_global_inuse;

    g_msrs[addr] = fixed_ctr1::mask;
    CHECK(fixed_ctr1::is_enabled());
    g_msrs[addr] = 0x0;
    CHECK(fixed_ctr1::is_disabled());

    g_msrs[addr] = fixed_ctr1::mask;
    CHECK(fixed_ctr1::is_enabled(fixed_ctr1::mask));
    g_msrs[addr] = 0x0;
    CHECK(fixed_ctr1::is_disabled(0x0));
}

TEST_CASE("ia32_perf_global_inuse_fixed_ctr2")
{
    using namespace intel_x64::msrs::ia32_perf_global_inuse;

    g_msrs[addr] = fixed_ctr2::mask;
    CHECK(fixed_ctr2::is_enabled());
    g_msrs[addr] = 0x0;
    CHECK(fixed_ctr2::is_disabled());

    g_msrs[addr] = fixed_ctr2::mask;
    CHECK(fixed_ctr2::is_enabled(fixed_ctr2::mask));
    g_msrs[addr] = 0x0;
    CHECK(fixed_ctr2::is_disabled(0x0));
}

TEST_CASE("ia32_perf_global_inuse_pmi")
{
    using namespace intel_x64::msrs::ia32_perf_global_inuse;

    g_msrs[addr] = pmi::mask;
    CHECK(pmi::is_enabled());
    g_msrs[addr] = 0x0;
    CHECK(pmi::is_disabled());

    g_msrs[addr] = pmi::mask;
    CHECK(pmi::is_enabled(pmi::mask));
    g_msrs[addr] = 0x0;
    CHECK(pmi::is_disabled(0x0));
}

TEST_CASE("ia32_pebs_enable")
{
    using namespace intel_x64::msrs::ia32_pebs_enable;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_pebs_pebs")
{
    using namespace intel_x64::msrs::ia32_pebs_enable;

    pebs::enable();
    CHECK(pebs::is_enabled());
    pebs::disable();
    CHECK(pebs::is_disabled());

    pebs::enable(pebs::mask);
    CHECK(pebs::is_enabled(pebs::mask));
    pebs::disable(0x0);
    CHECK(pebs::is_disabled(0x0));
}

TEST_CASE("ia32_mc6_ctl")
{
    using namespace intel_x64::msrs::ia32_mc6_ctl;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc6_status")
{
    using namespace intel_x64::msrs::ia32_mc6_status;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc6_addr")
{
    using namespace intel_x64::msrs::ia32_mc6_addr;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc6_misc")
{
    using namespace intel_x64::msrs::ia32_mc6_misc;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc7_ctl")
{
    using namespace intel_x64::msrs::ia32_mc7_ctl;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc7_status")
{
    using namespace intel_x64::msrs::ia32_mc7_status;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc7_addr")
{
    using namespace intel_x64::msrs::ia32_mc7_addr;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc7_misc")
{
    using namespace intel_x64::msrs::ia32_mc7_misc;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc8_ctl")
{
    using namespace intel_x64::msrs::ia32_mc8_ctl;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc8_status")
{
    using namespace intel_x64::msrs::ia32_mc8_status;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc8_addr")
{
    using namespace intel_x64::msrs::ia32_mc8_addr;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc8_misc")
{
    using namespace intel_x64::msrs::ia32_mc8_misc;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc9_ctl")
{
    using namespace intel_x64::msrs::ia32_mc9_ctl;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc9_status")
{
    using namespace intel_x64::msrs::ia32_mc9_status;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc9_addr")
{
    using namespace intel_x64::msrs::ia32_mc9_addr;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc9_misc")
{
    using namespace intel_x64::msrs::ia32_mc9_misc;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc10_ctl")
{
    using namespace intel_x64::msrs::ia32_mc10_ctl;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc10_status")
{
    using namespace intel_x64::msrs::ia32_mc10_status;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc10_addr")
{
    using namespace intel_x64::msrs::ia32_mc10_addr;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc10_misc")
{
    using namespace intel_x64::msrs::ia32_mc10_misc;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc11_ctl")
{
    using namespace intel_x64::msrs::ia32_mc11_ctl;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc11_status")
{
    using namespace intel_x64::msrs::ia32_mc11_status;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc11_addr")
{
    using namespace intel_x64::msrs::ia32_mc11_addr;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc11_misc")
{
    using namespace intel_x64::msrs::ia32_mc11_misc;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc12_ctl")
{
    using namespace intel_x64::msrs::ia32_mc12_ctl;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc12_status")
{
    using namespace intel_x64::msrs::ia32_mc12_status;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc12_addr")
{
    using namespace intel_x64::msrs::ia32_mc12_addr;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc12_misc")
{
    using namespace intel_x64::msrs::ia32_mc12_misc;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc13_ctl")
{
    using namespace intel_x64::msrs::ia32_mc13_ctl;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc13_status")
{
    using namespace intel_x64::msrs::ia32_mc13_status;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc13_addr")
{
    using namespace intel_x64::msrs::ia32_mc13_addr;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc13_misc")
{
    using namespace intel_x64::msrs::ia32_mc13_misc;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc14_ctl")
{
    using namespace intel_x64::msrs::ia32_mc14_ctl;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc14_status")
{
    using namespace intel_x64::msrs::ia32_mc14_status;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc14_addr")
{
    using namespace intel_x64::msrs::ia32_mc14_addr;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc14_misc")
{
    using namespace intel_x64::msrs::ia32_mc14_misc;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc15_ctl")
{
    using namespace intel_x64::msrs::ia32_mc15_ctl;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc15_status")
{
    using namespace intel_x64::msrs::ia32_mc15_status;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc15_addr")
{
    using namespace intel_x64::msrs::ia32_mc15_addr;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc15_misc")
{
    using namespace intel_x64::msrs::ia32_mc15_misc;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc16_ctl")
{
    using namespace intel_x64::msrs::ia32_mc16_ctl;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc16_status")
{
    using namespace intel_x64::msrs::ia32_mc16_status;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc16_addr")
{
    using namespace intel_x64::msrs::ia32_mc16_addr;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc16_misc")
{
    using namespace intel_x64::msrs::ia32_mc16_misc;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc17_ctl")
{
    using namespace intel_x64::msrs::ia32_mc17_ctl;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc17_status")
{
    using namespace intel_x64::msrs::ia32_mc17_status;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc17_addr")
{
    using namespace intel_x64::msrs::ia32_mc17_addr;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc17_misc")
{
    using namespace intel_x64::msrs::ia32_mc17_misc;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc18_ctl")
{
    using namespace intel_x64::msrs::ia32_mc18_ctl;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc18_status")
{
    using namespace intel_x64::msrs::ia32_mc18_status;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc18_addr")
{
    using namespace intel_x64::msrs::ia32_mc18_addr;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc18_misc")
{
    using namespace intel_x64::msrs::ia32_mc18_misc;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc19_ctl")
{
    using namespace intel_x64::msrs::ia32_mc19_ctl;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc19_status")
{
    using namespace intel_x64::msrs::ia32_mc19_status;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc19_addr")
{
    using namespace intel_x64::msrs::ia32_mc19_addr;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc19_misc")
{
    using namespace intel_x64::msrs::ia32_mc19_misc;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc20_ctl")
{
    using namespace intel_x64::msrs::ia32_mc20_ctl;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc20_status")
{
    using namespace intel_x64::msrs::ia32_mc20_status;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc20_addr")
{
    using namespace intel_x64::msrs::ia32_mc20_addr;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc20_misc")
{
    using namespace intel_x64::msrs::ia32_mc20_misc;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc21_ctl")
{
    using namespace intel_x64::msrs::ia32_mc21_ctl;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc21_status")
{
    using namespace intel_x64::msrs::ia32_mc21_status;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc21_addr")
{
    using namespace intel_x64::msrs::ia32_mc21_addr;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc21_misc")
{
    using namespace intel_x64::msrs::ia32_mc21_misc;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc22_ctl")
{
    using namespace intel_x64::msrs::ia32_mc22_ctl;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc22_status")
{
    using namespace intel_x64::msrs::ia32_mc22_status;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc22_addr")
{
    using namespace intel_x64::msrs::ia32_mc22_addr;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc22_misc")
{
    using namespace intel_x64::msrs::ia32_mc22_misc;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc23_ctl")
{
    using namespace intel_x64::msrs::ia32_mc23_ctl;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc23_status")
{
    using namespace intel_x64::msrs::ia32_mc23_status;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc23_addr")
{
    using namespace intel_x64::msrs::ia32_mc23_addr;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc23_misc")
{
    using namespace intel_x64::msrs::ia32_mc23_misc;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc24_ctl")
{
    using namespace intel_x64::msrs::ia32_mc24_ctl;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc24_status")
{
    using namespace intel_x64::msrs::ia32_mc24_status;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc24_addr")
{
    using namespace intel_x64::msrs::ia32_mc24_addr;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc24_misc")
{
    using namespace intel_x64::msrs::ia32_mc24_misc;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc25_ctl")
{
    using namespace intel_x64::msrs::ia32_mc25_ctl;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc25_status")
{
    using namespace intel_x64::msrs::ia32_mc25_status;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc25_addr")
{
    using namespace intel_x64::msrs::ia32_mc25_addr;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc25_misc")
{
    using namespace intel_x64::msrs::ia32_mc25_misc;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc26_ctl")
{
    using namespace intel_x64::msrs::ia32_mc26_ctl;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc26_status")
{
    using namespace intel_x64::msrs::ia32_mc26_status;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc26_addr")
{
    using namespace intel_x64::msrs::ia32_mc26_addr;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc26_misc")
{
    using namespace intel_x64::msrs::ia32_mc26_misc;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc27_ctl")
{
    using namespace intel_x64::msrs::ia32_mc27_ctl;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc27_status")
{
    using namespace intel_x64::msrs::ia32_mc27_status;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc27_addr")
{
    using namespace intel_x64::msrs::ia32_mc27_addr;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc27_misc")
{
    using namespace intel_x64::msrs::ia32_mc27_misc;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc28_ctl")
{
    using namespace intel_x64::msrs::ia32_mc28_ctl;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc28_status")
{
    using namespace intel_x64::msrs::ia32_mc28_status;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc28_addr")
{
    using namespace intel_x64::msrs::ia32_mc28_addr;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc28_misc")
{
    using namespace intel_x64::msrs::ia32_mc28_misc;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_vmx_basic")
{
    using namespace intel_x64::msrs::ia32_vmx_basic;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_vmx_basic_revision_id")
{
    using namespace intel_x64::msrs::ia32_vmx_basic;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(revision_id::get() == (revision_id::mask >> revision_id::from));
    CHECK(revision_id::get(revision_id::mask) == (revision_id::mask >> revision_id::from));
}

TEST_CASE("ia32_vmx_basic_vmxon_vmcs_region_size")
{
    using namespace intel_x64::msrs::ia32_vmx_basic;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(vmxon_vmcs_region_size::get() == (vmxon_vmcs_region_size::mask >> vmxon_vmcs_region_size::from));
    CHECK(vmxon_vmcs_region_size::get(vmxon_vmcs_region_size::mask) == (vmxon_vmcs_region_size::mask >> vmxon_vmcs_region_size::from));
}

TEST_CASE("ia32_vmx_basic_physical_address_width")
{
    using namespace intel_x64::msrs::ia32_vmx_basic;

    g_msrs[addr] = physical_address_width::mask;
    CHECK(physical_address_width::is_enabled());
    g_msrs[addr] = 0x0;
    CHECK(physical_address_width::is_disabled());

    g_msrs[addr] = physical_address_width::mask;
    CHECK(physical_address_width::is_enabled(physical_address_width::mask));
    g_msrs[addr] = 0x0;
    CHECK(physical_address_width::is_disabled(0x0));
}

TEST_CASE("ia32_vmx_basic_dual_monitor_mode_support")
{
    using namespace intel_x64::msrs::ia32_vmx_basic;

    g_msrs[addr] = dual_monitor_mode_support::mask;
    CHECK(dual_monitor_mode_support::is_enabled());
    g_msrs[addr] = 0x0;
    CHECK(dual_monitor_mode_support::is_disabled());

    g_msrs[addr] = dual_monitor_mode_support::mask;
    CHECK(dual_monitor_mode_support::is_enabled(dual_monitor_mode_support::mask));
    g_msrs[addr] = 0x0;
    CHECK(dual_monitor_mode_support::is_disabled(0x0));
}

TEST_CASE("ia32_vmx_basic_memory_type")
{
    using namespace intel_x64::msrs;

    g_msrs[ia32_vmx_basic::addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(ia32_vmx_basic::memory_type::get() == (ia32_vmx_basic::memory_type::mask >> ia32_vmx_basic::memory_type::from));
    CHECK(ia32_vmx_basic::memory_type::get(ia32_vmx_basic::memory_type::mask) == (ia32_vmx_basic::memory_type::mask >> ia32_vmx_basic::memory_type::from));
}

TEST_CASE("ia32_vmx_basic_ins_outs_exit_information")
{
    using namespace intel_x64::msrs::ia32_vmx_basic;

    g_msrs[addr] = ins_outs_exit_information::mask;
    CHECK(ins_outs_exit_information::is_enabled());
    g_msrs[addr] = 0x0;
    CHECK(ins_outs_exit_information::is_disabled());

    g_msrs[addr] = ins_outs_exit_information::mask;
    CHECK(ins_outs_exit_information::is_enabled(ins_outs_exit_information::mask));
    g_msrs[addr] = 0x0;
    CHECK(ins_outs_exit_information::is_disabled(0x0));
}

TEST_CASE("ia32_vmx_basic_true_based_controls")
{
    using namespace intel_x64::msrs::ia32_vmx_basic;

    g_msrs[addr] = true_based_controls::mask;
    CHECK(true_based_controls::is_enabled());
    g_msrs[addr] = 0x0;
    CHECK(true_based_controls::is_disabled());

    g_msrs[addr] = true_based_controls::mask;
    CHECK(true_based_controls::is_enabled(true_based_controls::mask));
    g_msrs[addr] = 0x0;
    CHECK(true_based_controls::is_disabled(0x0));
}

TEST_CASE("ia32_vmx_pinbased_ctls")
{
    using namespace intel_x64::msrs::ia32_vmx_pinbased_ctls;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_vmx_pinbased_ctls_allowed_0_settings")
{
    using namespace intel_x64::msrs::ia32_vmx_pinbased_ctls;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(allowed_0_settings::get() == (allowed_0_settings::mask >> allowed_0_settings::from));
    CHECK(allowed_0_settings::get(allowed_0_settings::mask) == (allowed_0_settings::mask >> allowed_0_settings::from));
}

TEST_CASE("ia32_vmx_pinbased_ctls_allowed_1_settings")
{
    using namespace intel_x64::msrs::ia32_vmx_pinbased_ctls;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(allowed_1_settings::get() == (allowed_1_settings::mask >> allowed_1_settings::from));
    CHECK(allowed_1_settings::get(allowed_1_settings::mask) == (allowed_1_settings::mask >> allowed_1_settings::from));
}

TEST_CASE("ia32_vmx_procbased_ctls")
{
    using namespace intel_x64::msrs::ia32_vmx_procbased_ctls;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_vmx_procbased_ctls_allowed_0_settings")
{
    using namespace intel_x64::msrs::ia32_vmx_procbased_ctls;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(allowed_0_settings::get() == (allowed_0_settings::mask >> allowed_0_settings::from));
    CHECK(allowed_0_settings::get(allowed_0_settings::mask) == (allowed_0_settings::mask >> allowed_0_settings::from));
}

TEST_CASE("ia32_vmx_procbased_ctls_allowed_1_settings")
{
    using namespace intel_x64::msrs::ia32_vmx_procbased_ctls;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(allowed_1_settings::get() == (allowed_1_settings::mask >> allowed_1_settings::from));
    CHECK(allowed_1_settings::get(allowed_1_settings::mask) == (allowed_1_settings::mask >> allowed_1_settings::from));
}

TEST_CASE("ia32_vmx_exit_ctls")
{
    using namespace intel_x64::msrs::ia32_vmx_exit_ctls;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_vmx_exit_ctls_allowed_0_settings")
{
    using namespace intel_x64::msrs::ia32_vmx_exit_ctls;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(allowed_0_settings::get() == (allowed_0_settings::mask >> allowed_0_settings::from));
    CHECK(allowed_0_settings::get(allowed_0_settings::mask) == (allowed_0_settings::mask >> allowed_0_settings::from));
}

TEST_CASE("ia32_vmx_exit_ctls_allowed_1_settings")
{
    using namespace intel_x64::msrs::ia32_vmx_exit_ctls;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(allowed_1_settings::get() == (allowed_1_settings::mask >> allowed_1_settings::from));
    CHECK(allowed_1_settings::get(allowed_1_settings::mask) == (allowed_1_settings::mask >> allowed_1_settings::from));
}

TEST_CASE("ia32_vmx_entry_ctls")
{
    using namespace intel_x64::msrs::ia32_vmx_entry_ctls;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_vmx_entry_ctls_allowed_0_settings")
{
    using namespace intel_x64::msrs::ia32_vmx_entry_ctls;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(allowed_0_settings::get() == (allowed_0_settings::mask >> allowed_0_settings::from));
    CHECK(allowed_0_settings::get(allowed_0_settings::mask) == (allowed_0_settings::mask >> allowed_0_settings::from));
}

TEST_CASE("ia32_vmx_entry_ctls_allowed_1_settings")
{
    using namespace intel_x64::msrs::ia32_vmx_entry_ctls;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(allowed_1_settings::get() == (allowed_1_settings::mask >> allowed_1_settings::from));
    CHECK(allowed_1_settings::get(allowed_1_settings::mask) == (allowed_1_settings::mask >> allowed_1_settings::from));
}

TEST_CASE("ia32_vmx_misc")
{
    using namespace intel_x64::msrs::ia32_vmx_misc;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_vmx_misc_preemption_timer_decrement")
{
    using namespace intel_x64::msrs::ia32_vmx_misc;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(preemption_timer_decrement::get() == (preemption_timer_decrement::mask >> preemption_timer_decrement::from));
    CHECK(preemption_timer_decrement::get(preemption_timer_decrement::mask) == (preemption_timer_decrement::mask >> preemption_timer_decrement::from));
}

TEST_CASE("ia32_vmx_misc_store_efer_lma_on_vm_exit")
{
    using namespace intel_x64::msrs::ia32_vmx_misc;

    g_msrs[addr] = store_efer_lma_on_vm_exit::mask;
    CHECK(store_efer_lma_on_vm_exit::is_enabled());
    g_msrs[addr] = 0x0;
    CHECK(store_efer_lma_on_vm_exit::is_disabled());

    g_msrs[addr] = store_efer_lma_on_vm_exit::mask;
    CHECK(store_efer_lma_on_vm_exit::is_enabled(store_efer_lma_on_vm_exit::mask));
    g_msrs[addr] = 0x0;
    CHECK(store_efer_lma_on_vm_exit::is_disabled(0x0));
}

TEST_CASE("ia32_vmx_misc_activity_state_hlt_support")
{
    using namespace intel_x64::msrs::ia32_vmx_misc;

    g_msrs[addr] = activity_state_hlt_support::mask;
    CHECK(activity_state_hlt_support::is_enabled());
    g_msrs[addr] = 0x0;
    CHECK(activity_state_hlt_support::is_disabled());

    g_msrs[addr] = activity_state_hlt_support::mask;
    CHECK(activity_state_hlt_support::is_enabled(activity_state_hlt_support::mask));
    g_msrs[addr] = 0x0;
    CHECK(activity_state_hlt_support::is_disabled(0x0));
}

TEST_CASE("ia32_vmx_misc_activity_state_shutdown_support")
{
    using namespace intel_x64::msrs::ia32_vmx_misc;

    g_msrs[addr] = activity_state_shutdown_support::mask;
    CHECK(activity_state_shutdown_support::is_enabled());
    g_msrs[addr] = 0x0;
    CHECK(activity_state_shutdown_support::is_disabled());

    g_msrs[addr] = activity_state_shutdown_support::mask;
    CHECK(activity_state_shutdown_support::is_enabled(activity_state_shutdown_support::mask));
    g_msrs[addr] = 0x0;
    CHECK(activity_state_shutdown_support::is_disabled(0x0));
}

TEST_CASE("ia32_vmx_misc_activity_state_wait_for_sipi_support")
{
    using namespace intel_x64::msrs::ia32_vmx_misc;

    g_msrs[addr] = activity_state_wait_for_sipi_support::mask;
    CHECK(activity_state_wait_for_sipi_support::is_enabled());
    g_msrs[addr] = 0x0;
    CHECK(activity_state_wait_for_sipi_support::is_disabled());

    g_msrs[addr] = activity_state_wait_for_sipi_support::mask;
    CHECK(activity_state_wait_for_sipi_support::is_enabled(activity_state_wait_for_sipi_support::mask));
    g_msrs[addr] = 0x0;
    CHECK(activity_state_wait_for_sipi_support::is_disabled(0x0));
}

TEST_CASE("ia32_vmx_misc_processor_trace_support")
{
    using namespace intel_x64::msrs::ia32_vmx_misc;

    g_msrs[addr] = processor_trace_support::mask;
    CHECK(processor_trace_support::is_enabled());
    g_msrs[addr] = 0x0;
    CHECK(processor_trace_support::is_disabled());

    g_msrs[addr] = processor_trace_support::mask;
    CHECK(processor_trace_support::is_enabled(processor_trace_support::mask));
    g_msrs[addr] = 0x0;
    CHECK(processor_trace_support::is_disabled(0x0));
}

TEST_CASE("ia32_vmx_misc_rdmsr_in_smm_support")
{
    using namespace intel_x64::msrs::ia32_vmx_misc;

    g_msrs[addr] = rdmsr_in_smm_support::mask;
    CHECK(rdmsr_in_smm_support::is_enabled());
    g_msrs[addr] = 0x0;
    CHECK(rdmsr_in_smm_support::is_disabled());

    g_msrs[addr] = rdmsr_in_smm_support::mask;
    CHECK(rdmsr_in_smm_support::is_enabled(rdmsr_in_smm_support::mask));
    g_msrs[addr] = 0x0;
    CHECK(rdmsr_in_smm_support::is_disabled(0x0));
}

TEST_CASE("ia32_vmx_misc_cr3_targets")
{
    using namespace intel_x64::msrs::ia32_vmx_misc;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(cr3_targets::get() == (cr3_targets::mask >> cr3_targets::from));
    CHECK(cr3_targets::get(cr3_targets::mask) == (cr3_targets::mask >> cr3_targets::from));
}

TEST_CASE("ia32_vmx_misc_max_num_msr_load_store_on_exit")
{
    using namespace intel_x64::msrs::ia32_vmx_misc;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(max_num_msr_load_store_on_exit::get() == (max_num_msr_load_store_on_exit::mask >> max_num_msr_load_store_on_exit::from));
    CHECK(max_num_msr_load_store_on_exit::get(max_num_msr_load_store_on_exit::mask) == (max_num_msr_load_store_on_exit::mask >> max_num_msr_load_store_on_exit::from));
}

TEST_CASE("ia32_vmx_misc_vmxoff_blocked_smi_support")
{
    using namespace intel_x64::msrs::ia32_vmx_misc;

    g_msrs[addr] = vmxoff_blocked_smi_support::mask;
    CHECK(vmxoff_blocked_smi_support::is_enabled());
    g_msrs[addr] = 0x0;
    CHECK(vmxoff_blocked_smi_support::is_disabled());

    g_msrs[addr] = vmxoff_blocked_smi_support::mask;
    CHECK(vmxoff_blocked_smi_support::is_enabled(vmxoff_blocked_smi_support::mask));
    g_msrs[addr] = 0x0;
    CHECK(vmxoff_blocked_smi_support::is_disabled(0x0));
}

TEST_CASE("ia32_vmx_misc_vmwrite_all_fields_support")
{
    using namespace intel_x64::msrs::ia32_vmx_misc;

    g_msrs[addr] = vmwrite_all_fields_support::mask;
    CHECK(vmwrite_all_fields_support::is_enabled());
    g_msrs[addr] = 0x0;
    CHECK(vmwrite_all_fields_support::is_disabled());

    g_msrs[addr] = vmwrite_all_fields_support::mask;
    CHECK(vmwrite_all_fields_support::is_enabled(vmwrite_all_fields_support::mask));
    g_msrs[addr] = 0x0;
    CHECK(vmwrite_all_fields_support::is_disabled(0x0));
}

TEST_CASE("ia32_vmx_misc_injection_with_instruction_length_of_zero")
{
    using namespace intel_x64::msrs::ia32_vmx_misc;

    g_msrs[addr] = injection_with_instruction_length_of_zero::mask;
    CHECK(injection_with_instruction_length_of_zero::is_enabled());
    g_msrs[addr] = 0x0;
    CHECK(injection_with_instruction_length_of_zero::is_disabled());

    g_msrs[addr] = injection_with_instruction_length_of_zero::mask;
    CHECK(injection_with_instruction_length_of_zero::is_enabled(injection_with_instruction_length_of_zero::mask));
    g_msrs[addr] = 0x0;
    CHECK(injection_with_instruction_length_of_zero::is_disabled(0x0));
}

TEST_CASE("ia32_vmx_cr0_fixed0")
{
    using namespace intel_x64::msrs::ia32_vmx_cr0_fixed0;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_vmx_cr0_fixed1")
{
    using namespace intel_x64::msrs::ia32_vmx_cr0_fixed1;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_vmx_cr4_fixed0")
{
    using namespace intel_x64::msrs::ia32_vmx_cr4_fixed0;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_vmx_cr4_fixed1")
{
    using namespace intel_x64::msrs::ia32_vmx_cr4_fixed1;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_vmx_vmcs_enum")
{
    using namespace intel_x64::msrs::ia32_vmx_vmcs_enum;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_vmx_vmcs_enum_highest_index")
{
    using namespace intel_x64::msrs::ia32_vmx_vmcs_enum;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(highest_index::get() == (highest_index::mask >> highest_index::from));
    CHECK(highest_index::get(highest_index::mask) == (highest_index::mask >> highest_index::from));
}

TEST_CASE("ia32_vmx_procbased_ctls2")
{
    using namespace intel_x64::msrs::ia32_vmx_procbased_ctls2;

    g_msrs[addr] = 0x00000000FFFFFFFFULL;
    CHECK(get() == 0x00000000FFFFFFFFULL);

    dump(0);

    g_msrs[addr] = 0x0UL;
    CHECK(get() == 0x0UL);

    dump(0);

    g_msrs[addr] = 0x00000000FFFFFFFFULL;
    CHECK(allowed0() == 0xFFFFFFFFUL);
    CHECK(allowed1() == 0x00000000UL);

    dump(0);

    g_msrs[addr] = 0xFFFFFFFF00000000ULL;
    CHECK(allowed0() == 0x00000000UL);
    CHECK(allowed1() == 0xFFFFFFFFUL);

    dump(0);
}

TEST_CASE("ia32_vmx_procbased_ctls2_virtualize_apic_accesses")
{
    using namespace intel_x64::msrs::ia32_vmx_procbased_ctls2;
    auto mask = virtualize_apic_accesses::mask;

    g_msrs[addr] = mask;
    CHECK(virtualize_apic_accesses::is_enabled());
    g_msrs[addr] = ~mask;
    CHECK(virtualize_apic_accesses::is_disabled());

    g_msrs[addr] = mask;
    CHECK(virtualize_apic_accesses::is_enabled(virtualize_apic_accesses::mask));
    g_msrs[addr] = ~mask;
    CHECK(virtualize_apic_accesses::is_disabled(~virtualize_apic_accesses::mask));

    g_msrs[addr] = mask | (mask << 32);
    CHECK_FALSE(virtualize_apic_accesses::is_allowed0());
    CHECK(virtualize_apic_accesses::is_allowed1());

    g_msrs[addr] = ~(mask | (mask << 32));
    CHECK(virtualize_apic_accesses::is_allowed0());
    CHECK_FALSE(virtualize_apic_accesses::is_allowed1());
}

TEST_CASE("ia32_vmx_procbased_ctls2_enable_ept")
{
    using namespace intel_x64::msrs::ia32_vmx_procbased_ctls2;
    auto mask = intel_x64::msrs::ia32_vmx_procbased_ctls2::enable_ept::mask;

    g_msrs[addr] = mask;
    CHECK(enable_ept::is_enabled());
    g_msrs[addr] = ~mask;
    CHECK(enable_ept::is_disabled());

    g_msrs[addr] = mask;
    CHECK(enable_ept::is_enabled(enable_ept::mask));
    g_msrs[addr] = ~mask;
    CHECK(enable_ept::is_disabled(~enable_ept::mask));

    g_msrs[addr] = mask | (mask << 32);
    CHECK_FALSE(enable_ept::is_allowed0());
    CHECK(enable_ept::is_allowed1());

    g_msrs[addr] = ~(mask | (mask << 32));
    CHECK(enable_ept::is_allowed0());
    CHECK_FALSE(enable_ept::is_allowed1());
}

TEST_CASE("ia32_vmx_procbased_ctls2_descriptor_table_exiting")
{
    using namespace intel_x64::msrs::ia32_vmx_procbased_ctls2;
    auto mask = intel_x64::msrs::ia32_vmx_procbased_ctls2::descriptor_table_exiting::mask;

    g_msrs[addr] = mask;
    CHECK(descriptor_table_exiting::is_enabled());
    g_msrs[addr] = ~mask;
    CHECK(descriptor_table_exiting::is_disabled());

    g_msrs[addr] = mask;
    CHECK(descriptor_table_exiting::is_enabled(descriptor_table_exiting::mask));
    g_msrs[addr] = ~mask;
    CHECK(descriptor_table_exiting::is_disabled(~descriptor_table_exiting::mask));

    g_msrs[addr] = mask | (mask << 32);
    CHECK_FALSE(descriptor_table_exiting::is_allowed0());
    CHECK(descriptor_table_exiting::is_allowed1());

    g_msrs[addr] = ~(mask | (mask << 32));
    CHECK(descriptor_table_exiting::is_allowed0());
    CHECK_FALSE(descriptor_table_exiting::is_allowed1());
}

TEST_CASE("ia32_vmx_procbased_ctls2_enable_rdtscp")
{
    using namespace intel_x64::msrs::ia32_vmx_procbased_ctls2;
    auto mask = intel_x64::msrs::ia32_vmx_procbased_ctls2::enable_rdtscp::mask;

    g_msrs[addr] = mask;
    CHECK(enable_rdtscp::is_enabled());
    g_msrs[addr] = ~mask;
    CHECK(enable_rdtscp::is_disabled());

    g_msrs[addr] = mask;
    CHECK(enable_rdtscp::is_enabled(enable_rdtscp::mask));
    g_msrs[addr] = ~mask;
    CHECK(enable_rdtscp::is_disabled(~enable_rdtscp::mask));

    g_msrs[addr] = mask | (mask << 32);
    CHECK_FALSE(enable_rdtscp::is_allowed0());
    CHECK(enable_rdtscp::is_allowed1());

    g_msrs[addr] = ~(mask | (mask << 32));
    CHECK(enable_rdtscp::is_allowed0());
    CHECK_FALSE(enable_rdtscp::is_allowed1());
}

TEST_CASE("ia32_vmx_procbased_ctls2_virtualize_x2apic_mode")
{
    using namespace intel_x64::msrs::ia32_vmx_procbased_ctls2;
    auto mask = intel_x64::msrs::ia32_vmx_procbased_ctls2::virtualize_x2apic_mode::mask;

    g_msrs[addr] = mask;
    CHECK(virtualize_x2apic_mode::is_enabled());
    g_msrs[addr] = ~mask;
    CHECK(virtualize_x2apic_mode::is_disabled());

    g_msrs[addr] = mask;
    CHECK(virtualize_x2apic_mode::is_enabled(virtualize_x2apic_mode::mask));
    g_msrs[addr] = ~mask;
    CHECK(virtualize_x2apic_mode::is_disabled(~virtualize_x2apic_mode::mask));

    g_msrs[addr] = mask | (mask << 32);
    CHECK_FALSE(virtualize_x2apic_mode::is_allowed0());
    CHECK(virtualize_x2apic_mode::is_allowed1());

    g_msrs[addr] = ~(mask | (mask << 32));
    CHECK(virtualize_x2apic_mode::is_allowed0());
    CHECK_FALSE(virtualize_x2apic_mode::is_allowed1());
}

TEST_CASE("ia32_vmx_procbased_ctls2_enable_vpid")
{
    using namespace intel_x64::msrs::ia32_vmx_procbased_ctls2;
    auto mask = intel_x64::msrs::ia32_vmx_procbased_ctls2::enable_vpid::mask;

    g_msrs[addr] = mask;
    CHECK(enable_vpid::is_enabled());
    g_msrs[addr] = ~mask;
    CHECK(enable_vpid::is_disabled());

    g_msrs[addr] = mask;
    CHECK(enable_vpid::is_enabled(enable_vpid::mask));
    g_msrs[addr] = ~mask;
    CHECK(enable_vpid::is_disabled(~enable_vpid::mask));

    g_msrs[addr] = mask | (mask << 32);
    CHECK_FALSE(enable_vpid::is_allowed0());
    CHECK(enable_vpid::is_allowed1());

    g_msrs[addr] = ~(mask | (mask << 32));
    CHECK(enable_vpid::is_allowed0());
    CHECK_FALSE(enable_vpid::is_allowed1());
}

TEST_CASE("ia32_vmx_procbased_ctls2_wbinvd_exiting")
{
    using namespace intel_x64::msrs::ia32_vmx_procbased_ctls2;
    auto mask = intel_x64::msrs::ia32_vmx_procbased_ctls2::wbinvd_exiting::mask;

    g_msrs[addr] = mask;
    CHECK(wbinvd_exiting::is_enabled());
    g_msrs[addr] = ~mask;
    CHECK(wbinvd_exiting::is_disabled());

    g_msrs[addr] = mask;
    CHECK(wbinvd_exiting::is_enabled(wbinvd_exiting::mask));
    g_msrs[addr] = ~mask;
    CHECK(wbinvd_exiting::is_disabled(~wbinvd_exiting::mask));

    g_msrs[addr] = mask | (mask << 32);
    CHECK_FALSE(wbinvd_exiting::is_allowed0());
    CHECK(wbinvd_exiting::is_allowed1());

    g_msrs[addr] = ~(mask | (mask << 32));
    CHECK(wbinvd_exiting::is_allowed0());
    CHECK_FALSE(wbinvd_exiting::is_allowed1());
}

TEST_CASE("ia32_vmx_procbased_ctls2_unrestricted_guest")
{
    using namespace intel_x64::msrs::ia32_vmx_procbased_ctls2;
    auto mask = intel_x64::msrs::ia32_vmx_procbased_ctls2::unrestricted_guest::mask;

    g_msrs[addr] = mask;
    CHECK(unrestricted_guest::is_enabled());
    g_msrs[addr] = ~mask;
    CHECK(unrestricted_guest::is_disabled());

    g_msrs[addr] = mask;
    CHECK(unrestricted_guest::is_enabled(unrestricted_guest::mask));
    g_msrs[addr] = ~mask;
    CHECK(unrestricted_guest::is_disabled(~unrestricted_guest::mask));

    g_msrs[addr] = mask | (mask << 32);
    CHECK_FALSE(unrestricted_guest::is_allowed0());
    CHECK(unrestricted_guest::is_allowed1());

    g_msrs[addr] = ~(mask | (mask << 32));
    CHECK(unrestricted_guest::is_allowed0());
    CHECK_FALSE(unrestricted_guest::is_allowed1());
}

TEST_CASE("ia32_vmx_procbased_ctls2_apic_register_virtualization")
{
    using namespace intel_x64::msrs::ia32_vmx_procbased_ctls2;
    auto mask = intel_x64::msrs::ia32_vmx_procbased_ctls2::apic_register_virtualization::mask;

    g_msrs[addr] = mask;
    CHECK(apic_register_virtualization::is_enabled());
    g_msrs[addr] = ~mask;
    CHECK(apic_register_virtualization::is_disabled());

    g_msrs[addr] = mask;
    CHECK(apic_register_virtualization::is_enabled(apic_register_virtualization::mask));
    g_msrs[addr] = ~mask;
    CHECK(apic_register_virtualization::is_disabled(~apic_register_virtualization::mask));

    g_msrs[addr] = mask | (mask << 32);
    CHECK_FALSE(apic_register_virtualization::is_allowed0());
    CHECK(apic_register_virtualization::is_allowed1());

    g_msrs[addr] = ~(mask | (mask << 32));
    CHECK(apic_register_virtualization::is_allowed0());
    CHECK_FALSE(apic_register_virtualization::is_allowed1());
}

TEST_CASE("ia32_vmx_procbased_ctls2_virtual_interrupt_delivery")
{
    using namespace intel_x64::msrs::ia32_vmx_procbased_ctls2;
    auto mask = intel_x64::msrs::ia32_vmx_procbased_ctls2::virtual_interrupt_delivery::mask;

    g_msrs[addr] = mask;
    CHECK(virtual_interrupt_delivery::is_enabled());
    g_msrs[addr] = ~mask;
    CHECK(virtual_interrupt_delivery::is_disabled());

    g_msrs[addr] = mask;
    CHECK(virtual_interrupt_delivery::is_enabled(virtual_interrupt_delivery::mask));
    g_msrs[addr] = ~mask;
    CHECK(virtual_interrupt_delivery::is_disabled(~virtual_interrupt_delivery::mask));

    g_msrs[addr] = mask | (mask << 32);
    CHECK_FALSE(virtual_interrupt_delivery::is_allowed0());
    CHECK(virtual_interrupt_delivery::is_allowed1());

    g_msrs[addr] = ~(mask | (mask << 32));
    CHECK(virtual_interrupt_delivery::is_allowed0());
    CHECK_FALSE(virtual_interrupt_delivery::is_allowed1());
}

TEST_CASE("ia32_vmx_procbased_ctls2_pause_loop_exiting")
{
    using namespace intel_x64::msrs::ia32_vmx_procbased_ctls2;
    auto mask = intel_x64::msrs::ia32_vmx_procbased_ctls2::pause_loop_exiting::mask;

    g_msrs[addr] = mask;
    CHECK(pause_loop_exiting::is_enabled());
    g_msrs[addr] = ~mask;
    CHECK(pause_loop_exiting::is_disabled());

    g_msrs[addr] = mask;
    CHECK(pause_loop_exiting::is_enabled(pause_loop_exiting::mask));
    g_msrs[addr] = ~mask;
    CHECK(pause_loop_exiting::is_disabled(~pause_loop_exiting::mask));

    g_msrs[addr] = mask | (mask << 32);
    CHECK_FALSE(pause_loop_exiting::is_allowed0());
    CHECK(pause_loop_exiting::is_allowed1());

    g_msrs[addr] = ~(mask | (mask << 32));
    CHECK(pause_loop_exiting::is_allowed0());
    CHECK_FALSE(pause_loop_exiting::is_allowed1());
}

TEST_CASE("ia32_vmx_procbased_ctls2_rdrand_exiting")
{
    using namespace intel_x64::msrs::ia32_vmx_procbased_ctls2;
    auto mask = intel_x64::msrs::ia32_vmx_procbased_ctls2::rdrand_exiting::mask;

    g_msrs[addr] = mask;
    CHECK(rdrand_exiting::is_enabled());
    g_msrs[addr] = ~mask;
    CHECK(rdrand_exiting::is_disabled());

    g_msrs[addr] = mask;
    CHECK(rdrand_exiting::is_enabled(rdrand_exiting::mask));
    g_msrs[addr] = ~mask;
    CHECK(rdrand_exiting::is_disabled(~rdrand_exiting::mask));

    g_msrs[addr] = mask | (mask << 32);
    CHECK_FALSE(rdrand_exiting::is_allowed0());
    CHECK(rdrand_exiting::is_allowed1());

    g_msrs[addr] = ~(mask | (mask << 32));
    CHECK(rdrand_exiting::is_allowed0());
    CHECK_FALSE(rdrand_exiting::is_allowed1());
}

TEST_CASE("ia32_vmx_procbased_ctls2_enable_invpcid")
{
    using namespace intel_x64::msrs::ia32_vmx_procbased_ctls2;
    auto mask = intel_x64::msrs::ia32_vmx_procbased_ctls2::enable_invpcid::mask;

    g_msrs[addr] = mask;
    CHECK(enable_invpcid::is_enabled());
    g_msrs[addr] = ~mask;
    CHECK(enable_invpcid::is_disabled());

    g_msrs[addr] = mask;
    CHECK(enable_invpcid::is_enabled(enable_invpcid::mask));
    g_msrs[addr] = ~mask;
    CHECK(enable_invpcid::is_disabled(~enable_invpcid::mask));

    g_msrs[addr] = mask | (mask << 32);
    CHECK_FALSE(enable_invpcid::is_allowed0());
    CHECK(enable_invpcid::is_allowed1());

    g_msrs[addr] = ~(mask | (mask << 32));
    CHECK(enable_invpcid::is_allowed0());
    CHECK_FALSE(enable_invpcid::is_allowed1());
}

TEST_CASE("ia32_vmx_procbased_ctls2_enable_vm_functions")
{
    using namespace intel_x64::msrs::ia32_vmx_procbased_ctls2;
    auto mask = intel_x64::msrs::ia32_vmx_procbased_ctls2::enable_vm_functions::mask;

    g_msrs[addr] = mask;
    CHECK(enable_vm_functions::is_enabled());
    g_msrs[addr] = ~mask;
    CHECK(enable_vm_functions::is_disabled());

    g_msrs[addr] = mask;
    CHECK(enable_vm_functions::is_enabled(enable_vm_functions::mask));
    g_msrs[addr] = ~mask;
    CHECK(enable_vm_functions::is_disabled(~enable_vm_functions::mask));

    g_msrs[addr] = mask | (mask << 32);
    CHECK_FALSE(enable_vm_functions::is_allowed0());
    CHECK(enable_vm_functions::is_allowed1());

    g_msrs[addr] = ~(mask | (mask << 32));
    CHECK(enable_vm_functions::is_allowed0());
    CHECK_FALSE(enable_vm_functions::is_allowed1());
}

TEST_CASE("ia32_vmx_procbased_ctls2_vmcs_shadowing")
{
    using namespace intel_x64::msrs::ia32_vmx_procbased_ctls2;
    auto mask = intel_x64::msrs::ia32_vmx_procbased_ctls2::vmcs_shadowing::mask;

    g_msrs[addr] = mask;
    CHECK(vmcs_shadowing::is_enabled());
    g_msrs[addr] = ~mask;
    CHECK(vmcs_shadowing::is_disabled());

    g_msrs[addr] = mask;
    CHECK(vmcs_shadowing::is_enabled(vmcs_shadowing::mask));
    g_msrs[addr] = ~mask;
    CHECK(vmcs_shadowing::is_disabled(~vmcs_shadowing::mask));

    g_msrs[addr] = mask | (mask << 32);
    CHECK_FALSE(vmcs_shadowing::is_allowed0());
    CHECK(vmcs_shadowing::is_allowed1());

    g_msrs[addr] = ~(mask | (mask << 32));
    CHECK(vmcs_shadowing::is_allowed0());
    CHECK_FALSE(vmcs_shadowing::is_allowed1());
}

TEST_CASE("ia32_vmx_procbased_ctls2_enable_encls_exiting")
{
    using namespace intel_x64::msrs::ia32_vmx_procbased_ctls2;
    auto mask = intel_x64::msrs::ia32_vmx_procbased_ctls2::enable_encls_exiting::mask;

    g_msrs[addr] = mask;
    CHECK(enable_encls_exiting::is_enabled());
    g_msrs[addr] = ~mask;
    CHECK(enable_encls_exiting::is_disabled());

    g_msrs[addr] = mask;
    CHECK(enable_encls_exiting::is_enabled(enable_encls_exiting::mask));
    g_msrs[addr] = ~mask;
    CHECK(enable_encls_exiting::is_disabled(~enable_encls_exiting::mask));

    g_msrs[addr] = mask | (mask << 32);
    CHECK_FALSE(enable_encls_exiting::is_allowed0());
    CHECK(enable_encls_exiting::is_allowed1());

    g_msrs[addr] = ~(mask | (mask << 32));
    CHECK(enable_encls_exiting::is_allowed0());
    CHECK_FALSE(enable_encls_exiting::is_allowed1());
}

TEST_CASE("ia32_vmx_procbased_ctls2_rdseed_exiting")
{
    using namespace intel_x64::msrs::ia32_vmx_procbased_ctls2;
    auto mask = intel_x64::msrs::ia32_vmx_procbased_ctls2::rdseed_exiting::mask;

    g_msrs[addr] = mask;
    CHECK(rdseed_exiting::is_enabled());
    g_msrs[addr] = ~mask;
    CHECK(rdseed_exiting::is_disabled());

    g_msrs[addr] = mask;
    CHECK(rdseed_exiting::is_enabled(rdseed_exiting::mask));
    g_msrs[addr] = ~mask;
    CHECK(rdseed_exiting::is_disabled(~rdseed_exiting::mask));

    g_msrs[addr] = mask | (mask << 32);
    CHECK_FALSE(rdseed_exiting::is_allowed0());
    CHECK(rdseed_exiting::is_allowed1());

    g_msrs[addr] = ~(mask | (mask << 32));
    CHECK(rdseed_exiting::is_allowed0());
    CHECK_FALSE(rdseed_exiting::is_allowed1());
}

TEST_CASE("ia32_vmx_procbased_ctls2_enable_pml")
{
    using namespace intel_x64::msrs::ia32_vmx_procbased_ctls2;
    auto mask = intel_x64::msrs::ia32_vmx_procbased_ctls2::enable_pml::mask;

    g_msrs[addr] = mask;
    CHECK(enable_pml::is_enabled());
    g_msrs[addr] = ~mask;
    CHECK(enable_pml::is_disabled());

    g_msrs[addr] = mask;
    CHECK(enable_pml::is_enabled(enable_pml::mask));
    g_msrs[addr] = ~mask;
    CHECK(enable_pml::is_disabled(~enable_pml::mask));

    g_msrs[addr] = mask | (mask << 32);
    CHECK_FALSE(enable_pml::is_allowed0());
    CHECK(enable_pml::is_allowed1());

    g_msrs[addr] = ~(mask | (mask << 32));
    CHECK(enable_pml::is_allowed0());
    CHECK_FALSE(enable_pml::is_allowed1());
}

TEST_CASE("ia32_vmx_procbased_ctls2_ept_violation_ve")
{
    using namespace intel_x64::msrs::ia32_vmx_procbased_ctls2;
    auto mask = intel_x64::msrs::ia32_vmx_procbased_ctls2::ept_violation_ve::mask;

    g_msrs[addr] = mask;
    CHECK(ept_violation_ve::is_enabled());
    g_msrs[addr] = ~mask;
    CHECK(ept_violation_ve::is_disabled());

    g_msrs[addr] = mask;
    CHECK(ept_violation_ve::is_enabled(ept_violation_ve::mask));
    g_msrs[addr] = ~mask;
    CHECK(ept_violation_ve::is_disabled(~ept_violation_ve::mask));

    g_msrs[addr] = mask | (mask << 32);
    CHECK_FALSE(ept_violation_ve::is_allowed0());
    CHECK(ept_violation_ve::is_allowed1());

    g_msrs[addr] = ~(mask | (mask << 32));
    CHECK(ept_violation_ve::is_allowed0());
    CHECK_FALSE(ept_violation_ve::is_allowed1());
}

TEST_CASE("ia32_vmx_procbased_ctls2_pt_conceal_nonroot_operation")
{
    using namespace intel_x64::msrs::ia32_vmx_procbased_ctls2;
    auto mask = intel_x64::msrs::ia32_vmx_procbased_ctls2::pt_conceal_nonroot_operation::mask;

    g_msrs[addr] = mask;
    CHECK(pt_conceal_nonroot_operation::is_enabled());
    g_msrs[addr] = ~mask;
    CHECK(pt_conceal_nonroot_operation::is_disabled());

    g_msrs[addr] = mask;
    CHECK(pt_conceal_nonroot_operation::is_enabled(pt_conceal_nonroot_operation::mask));
    g_msrs[addr] = ~mask;
    CHECK(pt_conceal_nonroot_operation::is_disabled(~pt_conceal_nonroot_operation::mask));

    g_msrs[addr] = mask | (mask << 32);
    CHECK_FALSE(pt_conceal_nonroot_operation::is_allowed0());
    CHECK(pt_conceal_nonroot_operation::is_allowed1());

    g_msrs[addr] = ~(mask | (mask << 32));
    CHECK(pt_conceal_nonroot_operation::is_allowed0());
    CHECK_FALSE(pt_conceal_nonroot_operation::is_allowed1());
}

TEST_CASE("ia32_vmx_procbased_ctls2_enable_xsaves_xrstors")
{
    using namespace intel_x64::msrs::ia32_vmx_procbased_ctls2;
    auto mask = intel_x64::msrs::ia32_vmx_procbased_ctls2::enable_xsaves_xrstors::mask;

    g_msrs[addr] = mask;
    CHECK(enable_xsaves_xrstors::is_enabled());
    g_msrs[addr] = ~mask;
    CHECK(enable_xsaves_xrstors::is_disabled());

    g_msrs[addr] = mask;
    CHECK(enable_xsaves_xrstors::is_enabled(enable_xsaves_xrstors::mask));
    g_msrs[addr] = ~mask;
    CHECK(enable_xsaves_xrstors::is_disabled(~enable_xsaves_xrstors::mask));

    g_msrs[addr] = mask | (mask << 32);
    CHECK_FALSE(enable_xsaves_xrstors::is_allowed0());
    CHECK(enable_xsaves_xrstors::is_allowed1());

    g_msrs[addr] = ~(mask | (mask << 32));
    CHECK(enable_xsaves_xrstors::is_allowed0());
    CHECK_FALSE(enable_xsaves_xrstors::is_allowed1());
}

TEST_CASE("ia32_vmx_procbased_ctls2_ept_mode_based_control")
{
    using namespace intel_x64::msrs::ia32_vmx_procbased_ctls2;
    auto mask = intel_x64::msrs::ia32_vmx_procbased_ctls2::ept_mode_based_control::mask;

    g_msrs[addr] = mask;
    CHECK(ept_mode_based_control::is_enabled());
    g_msrs[addr] = ~mask;
    CHECK(ept_mode_based_control::is_disabled());

    g_msrs[addr] = mask;
    CHECK(ept_mode_based_control::is_enabled(ept_mode_based_control::mask));
    g_msrs[addr] = ~mask;
    CHECK(ept_mode_based_control::is_disabled(~ept_mode_based_control::mask));

    g_msrs[addr] = mask | (mask << 32);
    CHECK_FALSE(ept_mode_based_control::is_allowed0());
    CHECK(ept_mode_based_control::is_allowed1());

    g_msrs[addr] = ~(mask | (mask << 32));
    CHECK(ept_mode_based_control::is_allowed0());
    CHECK_FALSE(ept_mode_based_control::is_allowed1());
}

TEST_CASE("ia32_vmx_procbased_ctls2_use_tsc_scaling")
{
    using namespace intel_x64::msrs::ia32_vmx_procbased_ctls2;
    auto mask = intel_x64::msrs::ia32_vmx_procbased_ctls2::use_tsc_scaling::mask;

    g_msrs[addr] = mask;
    CHECK(use_tsc_scaling::is_enabled());
    g_msrs[addr] = ~mask;
    CHECK(use_tsc_scaling::is_disabled());

    g_msrs[addr] = mask;
    CHECK(use_tsc_scaling::is_enabled(use_tsc_scaling::mask));
    g_msrs[addr] = ~mask;
    CHECK(use_tsc_scaling::is_disabled(~use_tsc_scaling::mask));

    g_msrs[addr] = mask | (mask << 32);
    CHECK_FALSE(use_tsc_scaling::is_allowed0());
    CHECK(use_tsc_scaling::is_allowed1());

    g_msrs[addr] = ~(mask | (mask << 32));
    CHECK(use_tsc_scaling::is_allowed0());
    CHECK_FALSE(use_tsc_scaling::is_allowed1());
}

TEST_CASE("ia32_vmx_ept_vpid_cap")
{
    using namespace intel_x64::msrs::ia32_vmx_ept_vpid_cap;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_vmx_ept_vpid_cap_execute_only_translation")
{
    using namespace intel_x64::msrs::ia32_vmx_ept_vpid_cap;

    g_msrs[addr] = execute_only_translation::mask;
    CHECK(execute_only_translation::is_enabled());
    g_msrs[addr] = 0x0;
    CHECK(execute_only_translation::is_disabled());

    g_msrs[addr] = execute_only_translation::mask;
    CHECK(execute_only_translation::is_enabled(execute_only_translation::mask));
    g_msrs[addr] = 0x0;
    CHECK(execute_only_translation::is_disabled(0x0));
}

TEST_CASE("ia32_vmx_ept_vpid_cap_page_walk_length_of_4")
{
    using namespace intel_x64::msrs::ia32_vmx_ept_vpid_cap;

    g_msrs[addr] = page_walk_length_of_4::mask;
    CHECK(page_walk_length_of_4::is_enabled());
    g_msrs[addr] = 0x0;
    CHECK(page_walk_length_of_4::is_disabled());

    g_msrs[addr] = page_walk_length_of_4::mask;
    CHECK(page_walk_length_of_4::is_enabled(page_walk_length_of_4::mask));
    g_msrs[addr] = 0x0;
    CHECK(page_walk_length_of_4::is_disabled(0x0));
}

TEST_CASE("ia32_vmx_ept_vpid_cap_memory_type_uncacheable_supported")
{
    using namespace intel_x64::msrs::ia32_vmx_ept_vpid_cap;

    g_msrs[addr] = memory_type_uncacheable_supported::mask;
    CHECK(memory_type_uncacheable_supported::is_enabled());
    g_msrs[addr] = 0x0;
    CHECK(memory_type_uncacheable_supported::is_disabled());

    g_msrs[addr] = memory_type_uncacheable_supported::mask;
    CHECK(memory_type_uncacheable_supported::is_enabled(memory_type_uncacheable_supported::mask));
    g_msrs[addr] = 0x0;
    CHECK(memory_type_uncacheable_supported::is_disabled(0x0));
}

TEST_CASE("ia32_vmx_ept_vpid_cap_memory_type_write_back_supported")
{
    using namespace intel_x64::msrs::ia32_vmx_ept_vpid_cap;

    g_msrs[addr] = memory_type_write_back_supported::mask;
    CHECK(memory_type_write_back_supported::is_enabled());
    g_msrs[addr] = 0x0;
    CHECK(memory_type_write_back_supported::is_disabled());

    g_msrs[addr] = memory_type_write_back_supported::mask;
    CHECK(memory_type_write_back_supported::is_enabled(memory_type_write_back_supported::mask));
    g_msrs[addr] = 0x0;
    CHECK(memory_type_write_back_supported::is_disabled(0x0));
}

TEST_CASE("ia32_vmx_ept_vpid_cap_pde_2mb_support")
{
    using namespace intel_x64::msrs::ia32_vmx_ept_vpid_cap;

    g_msrs[addr] = pde_2mb_support::mask;
    CHECK(pde_2mb_support::is_enabled());
    g_msrs[addr] = 0x0;
    CHECK(pde_2mb_support::is_disabled());

    g_msrs[addr] = pde_2mb_support::mask;
    CHECK(pde_2mb_support::is_enabled(pde_2mb_support::mask));
    g_msrs[addr] = 0x0;
    CHECK(pde_2mb_support::is_disabled(0x0));
}

TEST_CASE("ia32_vmx_ept_vpid_cap_pdpte_1gb_support")
{
    using namespace intel_x64::msrs::ia32_vmx_ept_vpid_cap;

    g_msrs[addr] = pdpte_1gb_support::mask;
    CHECK(pdpte_1gb_support::is_enabled());
    g_msrs[addr] = 0x0;
    CHECK(pdpte_1gb_support::is_disabled());

    g_msrs[addr] = pdpte_1gb_support::mask;
    CHECK(pdpte_1gb_support::is_enabled(pdpte_1gb_support::mask));
    g_msrs[addr] = 0x0;
    CHECK(pdpte_1gb_support::is_disabled(0x0));
}

TEST_CASE("ia32_vmx_ept_vpid_cap_invept_support")
{
    using namespace intel_x64::msrs::ia32_vmx_ept_vpid_cap;

    g_msrs[addr] = invept_support::mask;
    CHECK(invept_support::is_enabled());
    g_msrs[addr] = 0x0;
    CHECK(invept_support::is_disabled());

    g_msrs[addr] = invept_support::mask;
    CHECK(invept_support::is_enabled(invept_support::mask));
    g_msrs[addr] = 0x0;
    CHECK(invept_support::is_disabled(0x0));
}

TEST_CASE("ia32_vmx_ept_vpid_cap_accessed_dirty_support")
{
    using namespace intel_x64::msrs::ia32_vmx_ept_vpid_cap;

    g_msrs[addr] = accessed_dirty_support::mask;
    CHECK(accessed_dirty_support::is_enabled());
    g_msrs[addr] = 0x0;
    CHECK(accessed_dirty_support::is_disabled());

    g_msrs[addr] = accessed_dirty_support::mask;
    CHECK(accessed_dirty_support::is_enabled(accessed_dirty_support::mask));
    g_msrs[addr] = 0x0;
    CHECK(accessed_dirty_support::is_disabled(0x0));
}

TEST_CASE("ia32_vmx_ept_vpid_cap_invept_single_context_support")
{
    using namespace intel_x64::msrs::ia32_vmx_ept_vpid_cap;

    g_msrs[addr] = invept_single_context_support::mask;
    CHECK(invept_single_context_support::is_enabled());
    g_msrs[addr] = 0x0;
    CHECK(invept_single_context_support::is_disabled());

    g_msrs[addr] = invept_single_context_support::mask;
    CHECK(invept_single_context_support::is_enabled(invept_single_context_support::mask));
    g_msrs[addr] = 0x0;
    CHECK(invept_single_context_support::is_disabled(0x0));
}

TEST_CASE("ia32_vmx_ept_vpid_cap_invvpid_support")
{
    using namespace intel_x64::msrs::ia32_vmx_ept_vpid_cap;

    g_msrs[addr] = invvpid_support::mask;
    CHECK(invvpid_support::is_enabled());
    g_msrs[addr] = 0x0;
    CHECK(invvpid_support::is_disabled());

    g_msrs[addr] = invvpid_support::mask;
    CHECK(invvpid_support::is_enabled(invvpid_support::mask));
    g_msrs[addr] = 0x0;
    CHECK(invvpid_support::is_disabled(0x0));
}

TEST_CASE("ia32_vmx_ept_vpid_cap_invvpid_individual_address_support")
{
    using namespace intel_x64::msrs::ia32_vmx_ept_vpid_cap;

    g_msrs[addr] = invvpid_individual_address_support::mask;
    CHECK(invvpid_individual_address_support::is_enabled());
    g_msrs[addr] = 0x0;
    CHECK(invvpid_individual_address_support::is_disabled());

    g_msrs[addr] = invvpid_individual_address_support::mask;
    CHECK(invvpid_individual_address_support::is_enabled(invvpid_individual_address_support::mask));
    g_msrs[addr] = 0x0;
    CHECK(invvpid_individual_address_support::is_disabled(0x0));
}

TEST_CASE("ia32_vmx_ept_vpid_cap_invvpid_single_context_support")
{
    using namespace intel_x64::msrs::ia32_vmx_ept_vpid_cap;

    g_msrs[addr] = invvpid_single_context_support::mask;
    CHECK(invvpid_single_context_support::is_enabled());
    g_msrs[addr] = 0x0;
    CHECK(invvpid_single_context_support::is_disabled());

    g_msrs[addr] = invvpid_single_context_support::mask;
    CHECK(invvpid_single_context_support::is_enabled(invvpid_single_context_support::mask));
    g_msrs[addr] = 0x0;
    CHECK(invvpid_single_context_support::is_disabled(0x0));
}

TEST_CASE("ia32_vmx_ept_vpid_cap_invvpid_all_context_support")
{
    using namespace intel_x64::msrs::ia32_vmx_ept_vpid_cap;

    g_msrs[addr] = invvpid_all_context_support::mask;
    CHECK(invvpid_all_context_support::is_enabled());
    g_msrs[addr] = 0x0;
    CHECK(invvpid_all_context_support::is_disabled());

    g_msrs[addr] = invvpid_all_context_support::mask;
    CHECK(invvpid_all_context_support::is_enabled(invvpid_all_context_support::mask));
    g_msrs[addr] = 0x0;
    CHECK(invvpid_all_context_support::is_disabled(0x0));
}

TEST_CASE("ia32_vmx_ept_vpid_cap_invvpid_single_context_retaining_globals_support")
{
    using namespace intel_x64::msrs::ia32_vmx_ept_vpid_cap;

    g_msrs[addr] = invvpid_single_context_retaining_globals_support::mask;
    CHECK(invvpid_single_context_retaining_globals_support::is_enabled());
    g_msrs[addr] = 0x0;
    CHECK(invvpid_single_context_retaining_globals_support::is_disabled());

    g_msrs[addr] = invvpid_single_context_retaining_globals_support::mask;
    CHECK(invvpid_single_context_retaining_globals_support::is_enabled(invvpid_single_context_retaining_globals_support::mask));
    g_msrs[addr] = 0x0;
    CHECK(invvpid_single_context_retaining_globals_support::is_disabled(0x0));
}

TEST_CASE("ia32_vmx_true_pinbased_ctls")
{
    using namespace intel_x64::msrs::ia32_vmx_true_pinbased_ctls;

    g_msrs[addr] = 0x00000000FFFFFFFFULL;
    CHECK(get() == 0x00000000FFFFFFFFULL);

    dump(0);

    g_msrs[addr] = 0x0UL;
    CHECK(get() == 0x0UL);

    dump(0);

    g_msrs[addr] = 0x00000000FFFFFFFFULL;
    CHECK(allowed0() == 0xFFFFFFFFUL);
    CHECK(allowed1() == 0x00000000UL);

    dump(0);

    g_msrs[addr] = 0xFFFFFFFF00000000ULL;
    CHECK(allowed0() == 0x00000000UL);
    CHECK(allowed1() == 0xFFFFFFFFUL);

    dump(0);
}

TEST_CASE("ia32_vmx_true_pinbased_ctls_external_interrupt_exiting")
{
    using namespace intel_x64::msrs::ia32_vmx_true_pinbased_ctls;
    auto mask = external_interrupt_exiting::mask;

    g_msrs[addr] = mask;
    CHECK(external_interrupt_exiting::is_enabled());
    g_msrs[addr] = ~mask;
    CHECK(external_interrupt_exiting::is_disabled());

    g_msrs[addr] = mask;
    CHECK(external_interrupt_exiting::is_enabled(external_interrupt_exiting::mask));
    g_msrs[addr] = ~mask;
    CHECK(external_interrupt_exiting::is_disabled(~external_interrupt_exiting::mask));

    g_msrs[addr] = mask | (mask << 32);
    CHECK_FALSE(external_interrupt_exiting::is_allowed0());
    CHECK(external_interrupt_exiting::is_allowed1());

    g_msrs[addr] = ~(mask | (mask << 32));
    CHECK(external_interrupt_exiting::is_allowed0());
    CHECK_FALSE(external_interrupt_exiting::is_allowed1());
}

TEST_CASE("ia32_vmx_true_pinbased_ctls_nmi_exiting")
{
    using namespace intel_x64::msrs::ia32_vmx_true_pinbased_ctls;
    auto mask = nmi_exiting::mask;

    g_msrs[addr] = mask;
    CHECK(nmi_exiting::is_enabled());
    g_msrs[addr] = ~mask;
    CHECK(nmi_exiting::is_disabled());

    g_msrs[addr] = mask;
    CHECK(nmi_exiting::is_enabled(nmi_exiting::mask));
    g_msrs[addr] = ~mask;
    CHECK(nmi_exiting::is_disabled(~nmi_exiting::mask));

    g_msrs[addr] = mask | (mask << 32);
    CHECK_FALSE(nmi_exiting::is_allowed0());
    CHECK(nmi_exiting::is_allowed1());

    g_msrs[addr] = ~(mask | (mask << 32));
    CHECK(nmi_exiting::is_allowed0());
    CHECK_FALSE(nmi_exiting::is_allowed1());
}

TEST_CASE("ia32_vmx_true_pinbased_ctls_virtual_nmis")
{
    using namespace intel_x64::msrs::ia32_vmx_true_pinbased_ctls;
    auto mask = virtual_nmis::mask;

    g_msrs[addr] = mask;
    CHECK(virtual_nmis::is_enabled());
    g_msrs[addr] = ~mask;
    CHECK(virtual_nmis::is_disabled());

    g_msrs[addr] = mask;
    CHECK(virtual_nmis::is_enabled(virtual_nmis::mask));
    g_msrs[addr] = ~mask;
    CHECK(virtual_nmis::is_disabled(~virtual_nmis::mask));

    g_msrs[addr] = mask | (mask << 32);
    CHECK_FALSE(virtual_nmis::is_allowed0());
    CHECK(virtual_nmis::is_allowed1());

    g_msrs[addr] = ~(mask | (mask << 32));
    CHECK(virtual_nmis::is_allowed0());
    CHECK_FALSE(virtual_nmis::is_allowed1());
}

TEST_CASE("ia32_vmx_true_pinbased_ctls_activate_vmx_preemption_timer")
{
    using namespace intel_x64::msrs::ia32_vmx_true_pinbased_ctls;
    auto mask = activate_vmx_preemption_timer::mask;

    g_msrs[addr] = mask;
    CHECK(activate_vmx_preemption_timer::is_enabled());
    g_msrs[addr] = ~mask;
    CHECK(activate_vmx_preemption_timer::is_disabled());

    g_msrs[addr] = mask;
    CHECK(activate_vmx_preemption_timer::is_enabled(activate_vmx_preemption_timer::mask));
    g_msrs[addr] = ~mask;
    CHECK(activate_vmx_preemption_timer::is_disabled(~activate_vmx_preemption_timer::mask));

    g_msrs[addr] = mask | (mask << 32);
    CHECK_FALSE(activate_vmx_preemption_timer::is_allowed0());
    CHECK(activate_vmx_preemption_timer::is_allowed1());

    g_msrs[addr] = ~(mask | (mask << 32));
    CHECK(activate_vmx_preemption_timer::is_allowed0());
    CHECK_FALSE(activate_vmx_preemption_timer::is_allowed1());
}

TEST_CASE("ia32_vmx_true_pinbased_ctls_process_posted_interrupts")
{
    using namespace intel_x64::msrs::ia32_vmx_true_pinbased_ctls;
    auto mask = process_posted_interrupts::mask;

    g_msrs[addr] = mask;
    CHECK(process_posted_interrupts::is_enabled());
    g_msrs[addr] = ~mask;
    CHECK(process_posted_interrupts::is_disabled());

    g_msrs[addr] = mask;
    CHECK(process_posted_interrupts::is_enabled(process_posted_interrupts::mask));
    g_msrs[addr] = ~mask;
    CHECK(process_posted_interrupts::is_disabled(~process_posted_interrupts::mask));

    g_msrs[addr] = mask | (mask << 32);
    CHECK_FALSE(process_posted_interrupts::is_allowed0());
    CHECK(process_posted_interrupts::is_allowed1());

    g_msrs[addr] = ~(mask | (mask << 32));
    CHECK(process_posted_interrupts::is_allowed0());
    CHECK_FALSE(process_posted_interrupts::is_allowed1());
}

TEST_CASE("ia32_vmx_true_procbased_ctls")
{
    using namespace intel_x64::msrs::ia32_vmx_true_procbased_ctls;

    g_msrs[addr] = 0x00000000FFFFFFFFULL;
    CHECK(get() == 0x00000000FFFFFFFFULL);

    dump(0);

    g_msrs[addr] = 0x0UL;
    CHECK(get() == 0x0UL);

    dump(0);

    g_msrs[addr] = 0x00000000FFFFFFFFULL;
    CHECK(allowed0() == 0xFFFFFFFFUL);
    CHECK(allowed1() == 0x00000000UL);

    dump(0);

    g_msrs[addr] = 0xFFFFFFFF00000000ULL;
    CHECK(allowed0() == 0x00000000UL);
    CHECK(allowed1() == 0xFFFFFFFFUL);

    dump(0);
}

TEST_CASE("ia32_vmx_true_procbased_ctls_interrupt_window_exiting")
{
    using namespace intel_x64::msrs::ia32_vmx_true_procbased_ctls;
    auto mask = interrupt_window_exiting::mask;

    g_msrs[addr] = mask;
    CHECK(interrupt_window_exiting::is_enabled());
    g_msrs[addr] = ~mask;
    CHECK(interrupt_window_exiting::is_disabled());

    g_msrs[addr] = mask;
    CHECK(interrupt_window_exiting::is_enabled(interrupt_window_exiting::mask));
    g_msrs[addr] = ~mask;
    CHECK(interrupt_window_exiting::is_disabled(~interrupt_window_exiting::mask));

    g_msrs[addr] = mask | (mask << 32);
    CHECK_FALSE(interrupt_window_exiting::is_allowed0());
    CHECK(interrupt_window_exiting::is_allowed1());

    g_msrs[addr] = ~(mask | (mask << 32));
    CHECK(interrupt_window_exiting::is_allowed0());
    CHECK_FALSE(interrupt_window_exiting::is_allowed1());
}

TEST_CASE("ia32_vmx_true_procbased_ctls_use_tsc_offsetting")
{
    using namespace intel_x64::msrs::ia32_vmx_true_procbased_ctls;
    auto mask = use_tsc_offsetting::mask;

    g_msrs[addr] = mask;
    CHECK(use_tsc_offsetting::is_enabled());
    g_msrs[addr] = ~mask;
    CHECK(use_tsc_offsetting::is_disabled());

    g_msrs[addr] = mask;
    CHECK(use_tsc_offsetting::is_enabled(use_tsc_offsetting::mask));
    g_msrs[addr] = ~mask;
    CHECK(use_tsc_offsetting::is_disabled(~use_tsc_offsetting::mask));

    g_msrs[addr] = mask | (mask << 32);
    CHECK_FALSE(use_tsc_offsetting::is_allowed0());
    CHECK(use_tsc_offsetting::is_allowed1());

    g_msrs[addr] = ~(mask | (mask << 32));
    CHECK(use_tsc_offsetting::is_allowed0());
    CHECK_FALSE(use_tsc_offsetting::is_allowed1());
}

TEST_CASE("ia32_vmx_true_procbased_ctls_hlt_exiting")
{
    using namespace intel_x64::msrs::ia32_vmx_true_procbased_ctls;
    auto mask = hlt_exiting::mask;

    g_msrs[addr] = mask;
    CHECK(hlt_exiting::is_enabled());
    g_msrs[addr] = ~mask;
    CHECK(hlt_exiting::is_disabled());

    g_msrs[addr] = mask;
    CHECK(hlt_exiting::is_enabled(hlt_exiting::mask));
    g_msrs[addr] = ~mask;
    CHECK(hlt_exiting::is_disabled(~hlt_exiting::mask));

    g_msrs[addr] = mask | (mask << 32);
    CHECK_FALSE(hlt_exiting::is_allowed0());
    CHECK(hlt_exiting::is_allowed1());

    g_msrs[addr] = ~(mask | (mask << 32));
    CHECK(hlt_exiting::is_allowed0());
    CHECK_FALSE(hlt_exiting::is_allowed1());
}

TEST_CASE("ia32_vmx_true_procbased_ctls_invlpg_exiting")
{
    using namespace intel_x64::msrs::ia32_vmx_true_procbased_ctls;
    auto mask = invlpg_exiting::mask;

    g_msrs[addr] = mask;
    CHECK(invlpg_exiting::is_enabled());
    g_msrs[addr] = ~mask;
    CHECK(invlpg_exiting::is_disabled());

    g_msrs[addr] = mask;
    CHECK(invlpg_exiting::is_enabled(invlpg_exiting::mask));
    g_msrs[addr] = ~mask;
    CHECK(invlpg_exiting::is_disabled(~invlpg_exiting::mask));

    g_msrs[addr] = mask | (mask << 32);
    CHECK_FALSE(invlpg_exiting::is_allowed0());
    CHECK(invlpg_exiting::is_allowed1());

    g_msrs[addr] = ~(mask | (mask << 32));
    CHECK(invlpg_exiting::is_allowed0());
    CHECK_FALSE(invlpg_exiting::is_allowed1());
}

TEST_CASE("ia32_vmx_true_procbased_ctls_mwait_exiting")
{
    using namespace intel_x64::msrs::ia32_vmx_true_procbased_ctls;
    auto mask = mwait_exiting::mask;

    g_msrs[addr] = mask;
    CHECK(mwait_exiting::is_enabled());
    g_msrs[addr] = ~mask;
    CHECK(mwait_exiting::is_disabled());

    g_msrs[addr] = mask;
    CHECK(mwait_exiting::is_enabled(mwait_exiting::mask));
    g_msrs[addr] = ~mask;
    CHECK(mwait_exiting::is_disabled(~mwait_exiting::mask));

    g_msrs[addr] = mask | (mask << 32);
    CHECK_FALSE(mwait_exiting::is_allowed0());
    CHECK(mwait_exiting::is_allowed1());

    g_msrs[addr] = ~(mask | (mask << 32));
    CHECK(mwait_exiting::is_allowed0());
    CHECK_FALSE(mwait_exiting::is_allowed1());
}

TEST_CASE("ia32_vmx_true_procbased_ctls_rdpmc_exiting")
{
    using namespace intel_x64::msrs::ia32_vmx_true_procbased_ctls;
    auto mask = rdpmc_exiting::mask;

    g_msrs[addr] = mask;
    CHECK(rdpmc_exiting::is_enabled());
    g_msrs[addr] = ~mask;
    CHECK(rdpmc_exiting::is_disabled());

    g_msrs[addr] = mask;
    CHECK(rdpmc_exiting::is_enabled(rdpmc_exiting::mask));
    g_msrs[addr] = ~mask;
    CHECK(rdpmc_exiting::is_disabled(~rdpmc_exiting::mask));

    g_msrs[addr] = mask | (mask << 32);
    CHECK_FALSE(rdpmc_exiting::is_allowed0());
    CHECK(rdpmc_exiting::is_allowed1());

    g_msrs[addr] = ~(mask | (mask << 32));
    CHECK(rdpmc_exiting::is_allowed0());
    CHECK_FALSE(rdpmc_exiting::is_allowed1());
}

TEST_CASE("ia32_vmx_true_procbased_ctls_rdtsc_exiting")
{
    using namespace intel_x64::msrs::ia32_vmx_true_procbased_ctls;
    auto mask = rdtsc_exiting::mask;

    g_msrs[addr] = mask;
    CHECK(rdtsc_exiting::is_enabled());
    g_msrs[addr] = ~mask;
    CHECK(rdtsc_exiting::is_disabled());

    g_msrs[addr] = mask;
    CHECK(rdtsc_exiting::is_enabled(rdtsc_exiting::mask));
    g_msrs[addr] = ~mask;
    CHECK(rdtsc_exiting::is_disabled(~rdtsc_exiting::mask));

    g_msrs[addr] = mask | (mask << 32);
    CHECK_FALSE(rdtsc_exiting::is_allowed0());
    CHECK(rdtsc_exiting::is_allowed1());

    g_msrs[addr] = ~(mask | (mask << 32));
    CHECK(rdtsc_exiting::is_allowed0());
    CHECK_FALSE(rdtsc_exiting::is_allowed1());
}

TEST_CASE("ia32_vmx_true_procbased_ctls_cr3_load_exiting")
{
    using namespace intel_x64::msrs::ia32_vmx_true_procbased_ctls;
    auto mask = cr3_load_exiting::mask;

    g_msrs[addr] = mask;
    CHECK(cr3_load_exiting::is_enabled());
    g_msrs[addr] = ~mask;
    CHECK(cr3_load_exiting::is_disabled());

    g_msrs[addr] = mask;
    CHECK(cr3_load_exiting::is_enabled(cr3_load_exiting::mask));
    g_msrs[addr] = ~mask;
    CHECK(cr3_load_exiting::is_disabled(~cr3_load_exiting::mask));

    g_msrs[addr] = mask | (mask << 32);
    CHECK_FALSE(cr3_load_exiting::is_allowed0());
    CHECK(cr3_load_exiting::is_allowed1());

    g_msrs[addr] = ~(mask | (mask << 32));
    CHECK(cr3_load_exiting::is_allowed0());
    CHECK_FALSE(cr3_load_exiting::is_allowed1());
}

TEST_CASE("ia32_vmx_true_procbased_ctls_cr3_store_exiting")
{
    using namespace intel_x64::msrs::ia32_vmx_true_procbased_ctls;
    auto mask = cr3_store_exiting::mask;

    g_msrs[addr] = mask;
    CHECK(cr3_store_exiting::is_enabled());
    g_msrs[addr] = ~mask;
    CHECK(cr3_store_exiting::is_disabled());

    g_msrs[addr] = mask;
    CHECK(cr3_store_exiting::is_enabled(cr3_store_exiting::mask));
    g_msrs[addr] = ~mask;
    CHECK(cr3_store_exiting::is_disabled(~cr3_store_exiting::mask));

    g_msrs[addr] = mask | (mask << 32);
    CHECK_FALSE(cr3_store_exiting::is_allowed0());
    CHECK(cr3_store_exiting::is_allowed1());

    g_msrs[addr] = ~(mask | (mask << 32));
    CHECK(cr3_store_exiting::is_allowed0());
    CHECK_FALSE(cr3_store_exiting::is_allowed1());
}

TEST_CASE("ia32_vmx_true_procbased_ctls_cr8_load_exiting")
{
    using namespace intel_x64::msrs::ia32_vmx_true_procbased_ctls;
    auto mask = cr8_load_exiting::mask;

    g_msrs[addr] = mask;
    CHECK(cr8_load_exiting::is_enabled());
    g_msrs[addr] = ~mask;
    CHECK(cr8_load_exiting::is_disabled());

    g_msrs[addr] = mask;
    CHECK(cr8_load_exiting::is_enabled(cr8_load_exiting::mask));
    g_msrs[addr] = ~mask;
    CHECK(cr8_load_exiting::is_disabled(~cr8_load_exiting::mask));

    g_msrs[addr] = mask | (mask << 32);
    CHECK_FALSE(cr8_load_exiting::is_allowed0());
    CHECK(cr8_load_exiting::is_allowed1());

    g_msrs[addr] = ~(mask | (mask << 32));
    CHECK(cr8_load_exiting::is_allowed0());
    CHECK_FALSE(cr8_load_exiting::is_allowed1());
}

TEST_CASE("ia32_vmx_true_procbased_ctls_cr8_store_exiting")
{
    using namespace intel_x64::msrs::ia32_vmx_true_procbased_ctls;
    auto mask = cr8_store_exiting::mask;

    g_msrs[addr] = mask;
    CHECK(cr8_store_exiting::is_enabled());
    g_msrs[addr] = ~mask;
    CHECK(cr8_store_exiting::is_disabled());

    g_msrs[addr] = mask;
    CHECK(cr8_store_exiting::is_enabled(cr8_store_exiting::mask));
    g_msrs[addr] = ~mask;
    CHECK(cr8_store_exiting::is_disabled(~cr8_store_exiting::mask));

    g_msrs[addr] = mask | (mask << 32);
    CHECK_FALSE(cr8_store_exiting::is_allowed0());
    CHECK(cr8_store_exiting::is_allowed1());

    g_msrs[addr] = ~(mask | (mask << 32));
    CHECK(cr8_store_exiting::is_allowed0());
    CHECK_FALSE(cr8_store_exiting::is_allowed1());
}

TEST_CASE("ia32_vmx_true_procbased_ctls_use_tpr_shadow")
{
    using namespace intel_x64::msrs::ia32_vmx_true_procbased_ctls;
    auto mask = use_tpr_shadow::mask;

    g_msrs[addr] = mask;
    CHECK(use_tpr_shadow::is_enabled());
    g_msrs[addr] = ~mask;
    CHECK(use_tpr_shadow::is_disabled());

    g_msrs[addr] = mask;
    CHECK(use_tpr_shadow::is_enabled(use_tpr_shadow::mask));
    g_msrs[addr] = ~mask;
    CHECK(use_tpr_shadow::is_disabled(~use_tpr_shadow::mask));

    g_msrs[addr] = mask | (mask << 32);
    CHECK_FALSE(use_tpr_shadow::is_allowed0());
    CHECK(use_tpr_shadow::is_allowed1());

    g_msrs[addr] = ~(mask | (mask << 32));
    CHECK(use_tpr_shadow::is_allowed0());
    CHECK_FALSE(use_tpr_shadow::is_allowed1());
}

TEST_CASE("ia32_vmx_true_procbased_ctls_nmi_window_exiting")
{
    using namespace intel_x64::msrs::ia32_vmx_true_procbased_ctls;
    auto mask = nmi_window_exiting::mask;

    g_msrs[addr] = mask;
    CHECK(nmi_window_exiting::is_enabled());
    g_msrs[addr] = ~mask;
    CHECK(nmi_window_exiting::is_disabled());

    g_msrs[addr] = mask;
    CHECK(nmi_window_exiting::is_enabled(nmi_window_exiting::mask));
    g_msrs[addr] = ~mask;
    CHECK(nmi_window_exiting::is_disabled(~nmi_window_exiting::mask));

    g_msrs[addr] = mask | (mask << 32);
    CHECK_FALSE(nmi_window_exiting::is_allowed0());
    CHECK(nmi_window_exiting::is_allowed1());

    g_msrs[addr] = ~(mask | (mask << 32));
    CHECK(nmi_window_exiting::is_allowed0());
    CHECK_FALSE(nmi_window_exiting::is_allowed1());
}

TEST_CASE("ia32_vmx_true_procbased_ctls_mov_dr_exiting")
{
    using namespace intel_x64::msrs::ia32_vmx_true_procbased_ctls;
    auto mask = mov_dr_exiting::mask;

    g_msrs[addr] = mask;
    CHECK(mov_dr_exiting::is_enabled());
    g_msrs[addr] = ~mask;
    CHECK(mov_dr_exiting::is_disabled());

    g_msrs[addr] = mask;
    CHECK(mov_dr_exiting::is_enabled(mov_dr_exiting::mask));
    g_msrs[addr] = ~mask;
    CHECK(mov_dr_exiting::is_disabled(~mov_dr_exiting::mask));

    g_msrs[addr] = mask | (mask << 32);
    CHECK_FALSE(mov_dr_exiting::is_allowed0());
    CHECK(mov_dr_exiting::is_allowed1());

    g_msrs[addr] = ~(mask | (mask << 32));
    CHECK(mov_dr_exiting::is_allowed0());
    CHECK_FALSE(mov_dr_exiting::is_allowed1());
}

TEST_CASE("ia32_vmx_true_procbased_ctls_unconditional_io_exiting")
{
    using namespace intel_x64::msrs::ia32_vmx_true_procbased_ctls;
    auto mask = unconditional_io_exiting::mask;

    g_msrs[addr] = mask;
    CHECK(unconditional_io_exiting::is_enabled());
    g_msrs[addr] = ~mask;
    CHECK(unconditional_io_exiting::is_disabled());

    g_msrs[addr] = mask;
    CHECK(unconditional_io_exiting::is_enabled(unconditional_io_exiting::mask));
    g_msrs[addr] = ~mask;
    CHECK(unconditional_io_exiting::is_disabled(~unconditional_io_exiting::mask));

    g_msrs[addr] = mask | (mask << 32);
    CHECK_FALSE(unconditional_io_exiting::is_allowed0());
    CHECK(unconditional_io_exiting::is_allowed1());

    g_msrs[addr] = ~(mask | (mask << 32));
    CHECK(unconditional_io_exiting::is_allowed0());
    CHECK_FALSE(unconditional_io_exiting::is_allowed1());
}

TEST_CASE("ia32_vmx_true_procbased_ctls_use_io_bitmaps")
{
    using namespace intel_x64::msrs::ia32_vmx_true_procbased_ctls;
    auto mask = use_io_bitmaps::mask;

    g_msrs[addr] = mask;
    CHECK(use_io_bitmaps::is_enabled());
    g_msrs[addr] = ~mask;
    CHECK(use_io_bitmaps::is_disabled());

    g_msrs[addr] = mask;
    CHECK(use_io_bitmaps::is_enabled(use_io_bitmaps::mask));
    g_msrs[addr] = ~mask;
    CHECK(use_io_bitmaps::is_disabled(~use_io_bitmaps::mask));

    g_msrs[addr] = mask | (mask << 32);
    CHECK_FALSE(use_io_bitmaps::is_allowed0());
    CHECK(use_io_bitmaps::is_allowed1());

    g_msrs[addr] = ~(mask | (mask << 32));
    CHECK(use_io_bitmaps::is_allowed0());
    CHECK_FALSE(use_io_bitmaps::is_allowed1());
}

TEST_CASE("ia32_vmx_true_procbased_ctls_monitor_trap_flag")
{
    using namespace intel_x64::msrs::ia32_vmx_true_procbased_ctls;
    auto mask = monitor_trap_flag::mask;

    g_msrs[addr] = mask;
    CHECK(monitor_trap_flag::is_enabled());
    g_msrs[addr] = ~mask;
    CHECK(monitor_trap_flag::is_disabled());

    g_msrs[addr] = mask;
    CHECK(monitor_trap_flag::is_enabled(monitor_trap_flag::mask));
    g_msrs[addr] = ~mask;
    CHECK(monitor_trap_flag::is_disabled(~monitor_trap_flag::mask));

    g_msrs[addr] = mask | (mask << 32);
    CHECK_FALSE(monitor_trap_flag::is_allowed0());
    CHECK(monitor_trap_flag::is_allowed1());

    g_msrs[addr] = ~(mask | (mask << 32));
    CHECK(monitor_trap_flag::is_allowed0());
    CHECK_FALSE(monitor_trap_flag::is_allowed1());
}

TEST_CASE("ia32_vmx_true_procbased_ctls_use_msr_bitmap")
{
    using namespace intel_x64::msrs::ia32_vmx_true_procbased_ctls;
    auto mask = use_msr_bitmap::mask;

    g_msrs[addr] = mask;
    CHECK(use_msr_bitmap::is_enabled());
    g_msrs[addr] = ~mask;
    CHECK(use_msr_bitmap::is_disabled());

    g_msrs[addr] = mask;
    CHECK(use_msr_bitmap::is_enabled(use_msr_bitmap::mask));
    g_msrs[addr] = ~mask;
    CHECK(use_msr_bitmap::is_disabled(~use_msr_bitmap::mask));

    g_msrs[addr] = mask | (mask << 32);
    CHECK_FALSE(use_msr_bitmap::is_allowed0());
    CHECK(use_msr_bitmap::is_allowed1());

    g_msrs[addr] = ~(mask | (mask << 32));
    CHECK(use_msr_bitmap::is_allowed0());
    CHECK_FALSE(use_msr_bitmap::is_allowed1());
}

TEST_CASE("ia32_vmx_true_procbased_ctls_monitor_exiting")
{
    using namespace intel_x64::msrs::ia32_vmx_true_procbased_ctls;
    auto mask = monitor_exiting::mask;

    g_msrs[addr] = mask;
    CHECK(monitor_exiting::is_enabled());
    g_msrs[addr] = ~mask;
    CHECK(monitor_exiting::is_disabled());

    g_msrs[addr] = mask;
    CHECK(monitor_exiting::is_enabled(monitor_exiting::mask));
    g_msrs[addr] = ~mask;
    CHECK(monitor_exiting::is_disabled(~monitor_exiting::mask));

    g_msrs[addr] = mask | (mask << 32);
    CHECK_FALSE(monitor_exiting::is_allowed0());
    CHECK(monitor_exiting::is_allowed1());

    g_msrs[addr] = ~(mask | (mask << 32));
    CHECK(monitor_exiting::is_allowed0());
    CHECK_FALSE(monitor_exiting::is_allowed1());
}

TEST_CASE("ia32_vmx_true_procbased_ctls_pause_exiting")
{
    using namespace intel_x64::msrs::ia32_vmx_true_procbased_ctls;
    auto mask = pause_exiting::mask;

    g_msrs[addr] = mask;
    CHECK(pause_exiting::is_enabled());
    g_msrs[addr] = ~mask;
    CHECK(pause_exiting::is_disabled());

    g_msrs[addr] = mask;
    CHECK(pause_exiting::is_enabled(pause_exiting::mask));
    g_msrs[addr] = ~mask;
    CHECK(pause_exiting::is_disabled(~pause_exiting::mask));

    g_msrs[addr] = mask | (mask << 32);
    CHECK_FALSE(pause_exiting::is_allowed0());
    CHECK(pause_exiting::is_allowed1());

    g_msrs[addr] = ~(mask | (mask << 32));
    CHECK(pause_exiting::is_allowed0());
    CHECK_FALSE(pause_exiting::is_allowed1());
}

TEST_CASE("ia32_vmx_true_procbased_ctls_activate_secondary_controls")
{
    using namespace intel_x64::msrs::ia32_vmx_true_procbased_ctls;
    auto mask = activate_secondary_controls::mask;

    g_msrs[addr] = mask;
    CHECK(activate_secondary_controls::is_enabled());
    g_msrs[addr] = ~mask;
    CHECK(activate_secondary_controls::is_disabled());

    g_msrs[addr] = mask;
    CHECK(activate_secondary_controls::is_enabled(activate_secondary_controls::mask));
    g_msrs[addr] = ~mask;
    CHECK(activate_secondary_controls::is_disabled(~activate_secondary_controls::mask));

    g_msrs[addr] = mask | (mask << 32);
    CHECK_FALSE(activate_secondary_controls::is_allowed0());
    CHECK(activate_secondary_controls::is_allowed1());

    g_msrs[addr] = ~(mask | (mask << 32));
    CHECK(activate_secondary_controls::is_allowed0());
    CHECK_FALSE(activate_secondary_controls::is_allowed1());
}

TEST_CASE("ia32_vmx_true_exit_ctls")
{
    using namespace intel_x64::msrs::ia32_vmx_true_exit_ctls;

    g_msrs[addr] = 0x00000000FFFFFFFFULL;
    CHECK(get() == 0x00000000FFFFFFFFULL);

    dump(0);

    g_msrs[addr] = 0x0UL;
    CHECK(get() == 0x0UL);

    dump(0);

    g_msrs[addr] = 0x00000000FFFFFFFFULL;
    CHECK(allowed0() == 0xFFFFFFFFUL);
    CHECK(allowed1() == 0x00000000UL);

    dump(0);

    g_msrs[addr] = 0xFFFFFFFF00000000ULL;
    CHECK(allowed0() == 0x00000000UL);
    CHECK(allowed1() == 0xFFFFFFFFUL);

    dump(0);
}

TEST_CASE("ia32_vmx_true_exit_ctls_save_debug_controls")
{
    using namespace intel_x64::msrs::ia32_vmx_true_exit_ctls;
    auto mask = save_debug_controls::mask;

    g_msrs[addr] = mask;
    CHECK(save_debug_controls::is_enabled());
    g_msrs[addr] = ~mask;
    CHECK(save_debug_controls::is_disabled());

    g_msrs[addr] = mask;
    CHECK(save_debug_controls::is_enabled(save_debug_controls::mask));
    g_msrs[addr] = ~mask;
    CHECK(save_debug_controls::is_disabled(~save_debug_controls::mask));

    g_msrs[addr] = mask | (mask << 32);
    CHECK_FALSE(save_debug_controls::is_allowed0());
    CHECK(save_debug_controls::is_allowed1());

    g_msrs[addr] = ~(mask | (mask << 32));
    CHECK(save_debug_controls::is_allowed0());
    CHECK_FALSE(save_debug_controls::is_allowed1());
}

TEST_CASE("ia32_vmx_true_exit_ctls_host_address_space_size")
{
    using namespace intel_x64::msrs::ia32_vmx_true_exit_ctls;
    auto mask = host_address_space_size::mask;

    g_msrs[addr] = mask;
    CHECK(host_address_space_size::is_enabled());
    g_msrs[addr] = ~mask;
    CHECK(host_address_space_size::is_disabled());

    g_msrs[addr] = mask;
    CHECK(host_address_space_size::is_enabled(host_address_space_size::mask));
    g_msrs[addr] = ~mask;
    CHECK(host_address_space_size::is_disabled(~host_address_space_size::mask));

    g_msrs[addr] = mask | (mask << 32);
    CHECK_FALSE(host_address_space_size::is_allowed0());
    CHECK(host_address_space_size::is_allowed1());

    g_msrs[addr] = ~(mask | (mask << 32));
    CHECK(host_address_space_size::is_allowed0());
    CHECK_FALSE(host_address_space_size::is_allowed1());
}

TEST_CASE("ia32_vmx_true_exit_ctls_load_ia32_perf_global_ctrl")
{
    using namespace intel_x64::msrs::ia32_vmx_true_exit_ctls;
    auto mask = load_ia32_perf_global_ctrl::mask;

    g_msrs[addr] = mask;
    CHECK(load_ia32_perf_global_ctrl::is_enabled());
    g_msrs[addr] = ~mask;
    CHECK(load_ia32_perf_global_ctrl::is_disabled());

    g_msrs[addr] = mask;
    CHECK(load_ia32_perf_global_ctrl::is_enabled(load_ia32_perf_global_ctrl::mask));
    g_msrs[addr] = ~mask;
    CHECK(load_ia32_perf_global_ctrl::is_disabled(~load_ia32_perf_global_ctrl::mask));

    g_msrs[addr] = mask | (mask << 32);
    CHECK_FALSE(load_ia32_perf_global_ctrl::is_allowed0());
    CHECK(load_ia32_perf_global_ctrl::is_allowed1());

    g_msrs[addr] = ~(mask | (mask << 32));
    CHECK(load_ia32_perf_global_ctrl::is_allowed0());
    CHECK_FALSE(load_ia32_perf_global_ctrl::is_allowed1());
}

TEST_CASE("ia32_vmx_true_exit_ctls_acknowledge_interrupt_on_exit")
{
    using namespace intel_x64::msrs::ia32_vmx_true_exit_ctls;
    auto mask = acknowledge_interrupt_on_exit::mask;

    g_msrs[addr] = mask;
    CHECK(acknowledge_interrupt_on_exit::is_enabled());
    g_msrs[addr] = ~mask;
    CHECK(acknowledge_interrupt_on_exit::is_disabled());

    g_msrs[addr] = mask;
    CHECK(acknowledge_interrupt_on_exit::is_enabled(acknowledge_interrupt_on_exit::mask));
    g_msrs[addr] = ~mask;
    CHECK(acknowledge_interrupt_on_exit::is_disabled(~acknowledge_interrupt_on_exit::mask));

    g_msrs[addr] = mask | (mask << 32);
    CHECK_FALSE(acknowledge_interrupt_on_exit::is_allowed0());
    CHECK(acknowledge_interrupt_on_exit::is_allowed1());

    g_msrs[addr] = ~(mask | (mask << 32));
    CHECK(acknowledge_interrupt_on_exit::is_allowed0());
    CHECK_FALSE(acknowledge_interrupt_on_exit::is_allowed1());
}

TEST_CASE("ia32_vmx_true_exit_ctls_save_ia32_pat")
{
    using namespace intel_x64::msrs::ia32_vmx_true_exit_ctls;
    auto mask = save_ia32_pat::mask;

    g_msrs[addr] = mask;
    CHECK(save_ia32_pat::is_enabled());
    g_msrs[addr] = ~mask;
    CHECK(save_ia32_pat::is_disabled());

    g_msrs[addr] = mask;
    CHECK(save_ia32_pat::is_enabled(save_ia32_pat::mask));
    g_msrs[addr] = ~mask;
    CHECK(save_ia32_pat::is_disabled(~save_ia32_pat::mask));

    g_msrs[addr] = mask | (mask << 32);
    CHECK_FALSE(save_ia32_pat::is_allowed0());
    CHECK(save_ia32_pat::is_allowed1());

    g_msrs[addr] = ~(mask | (mask << 32));
    CHECK(save_ia32_pat::is_allowed0());
    CHECK_FALSE(save_ia32_pat::is_allowed1());
}

TEST_CASE("ia32_vmx_true_exit_ctls_load_ia32_pat")
{
    using namespace intel_x64::msrs::ia32_vmx_true_exit_ctls;
    auto mask = load_ia32_pat::mask;

    g_msrs[addr] = mask;
    CHECK(load_ia32_pat::is_enabled());
    g_msrs[addr] = ~mask;
    CHECK(load_ia32_pat::is_disabled());

    g_msrs[addr] = mask;
    CHECK(load_ia32_pat::is_enabled(load_ia32_pat::mask));
    g_msrs[addr] = ~mask;
    CHECK(load_ia32_pat::is_disabled(~load_ia32_pat::mask));

    g_msrs[addr] = mask | (mask << 32);
    CHECK_FALSE(load_ia32_pat::is_allowed0());
    CHECK(load_ia32_pat::is_allowed1());

    g_msrs[addr] = ~(mask | (mask << 32));
    CHECK(load_ia32_pat::is_allowed0());
    CHECK_FALSE(load_ia32_pat::is_allowed1());
}

TEST_CASE("ia32_vmx_true_exit_ctls_save_ia32_efer")
{
    using namespace intel_x64::msrs::ia32_vmx_true_exit_ctls;
    auto mask = save_ia32_efer::mask;

    g_msrs[addr] = mask;
    CHECK(save_ia32_efer::is_enabled());
    g_msrs[addr] = ~mask;
    CHECK(save_ia32_efer::is_disabled());

    g_msrs[addr] = mask;
    CHECK(save_ia32_efer::is_enabled(save_ia32_efer::mask));
    g_msrs[addr] = ~mask;
    CHECK(save_ia32_efer::is_disabled(~save_ia32_efer::mask));

    g_msrs[addr] = mask | (mask << 32);
    CHECK_FALSE(save_ia32_efer::is_allowed0());
    CHECK(save_ia32_efer::is_allowed1());

    g_msrs[addr] = ~(mask | (mask << 32));
    CHECK(save_ia32_efer::is_allowed0());
    CHECK_FALSE(save_ia32_efer::is_allowed1());
}

TEST_CASE("ia32_vmx_true_exit_ctls_load_ia32_efer")
{
    using namespace intel_x64::msrs::ia32_vmx_true_exit_ctls;
    auto mask = load_ia32_efer::mask;

    g_msrs[addr] = mask;
    CHECK(load_ia32_efer::is_enabled());
    g_msrs[addr] = ~mask;
    CHECK(load_ia32_efer::is_disabled());

    g_msrs[addr] = mask;
    CHECK(load_ia32_efer::is_enabled(load_ia32_efer::mask));
    g_msrs[addr] = ~mask;
    CHECK(load_ia32_efer::is_disabled(~load_ia32_efer::mask));

    g_msrs[addr] = mask | (mask << 32);
    CHECK_FALSE(load_ia32_efer::is_allowed0());
    CHECK(load_ia32_efer::is_allowed1());

    g_msrs[addr] = ~(mask | (mask << 32));
    CHECK(load_ia32_efer::is_allowed0());
    CHECK_FALSE(load_ia32_efer::is_allowed1());
}

TEST_CASE("ia32_vmx_true_exit_ctls_save_vmx_preemption_timer_value")
{
    using namespace intel_x64::msrs::ia32_vmx_true_exit_ctls;
    auto mask = save_vmx_preemption_timer_value::mask;

    g_msrs[addr] = mask;
    CHECK(save_vmx_preemption_timer_value::is_enabled());
    g_msrs[addr] = ~mask;
    CHECK(save_vmx_preemption_timer_value::is_disabled());

    g_msrs[addr] = mask;
    CHECK(save_vmx_preemption_timer_value::is_enabled(save_vmx_preemption_timer_value::mask));
    g_msrs[addr] = ~mask;
    CHECK(save_vmx_preemption_timer_value::is_disabled(~save_vmx_preemption_timer_value::mask));

    g_msrs[addr] = mask | (mask << 32);
    CHECK_FALSE(save_vmx_preemption_timer_value::is_allowed0());
    CHECK(save_vmx_preemption_timer_value::is_allowed1());

    g_msrs[addr] = ~(mask | (mask << 32));
    CHECK(save_vmx_preemption_timer_value::is_allowed0());
    CHECK_FALSE(save_vmx_preemption_timer_value::is_allowed1());
}

TEST_CASE("ia32_vmx_true_exit_ctls_clear_ia32_bndcfgs")
{
    using namespace intel_x64::msrs::ia32_vmx_true_exit_ctls;
    auto mask = clear_ia32_bndcfgs::mask;

    g_msrs[addr] = mask;
    CHECK(clear_ia32_bndcfgs::is_enabled());
    g_msrs[addr] = ~mask;
    CHECK(clear_ia32_bndcfgs::is_disabled());

    g_msrs[addr] = mask;
    CHECK(clear_ia32_bndcfgs::is_enabled(clear_ia32_bndcfgs::mask));
    g_msrs[addr] = ~mask;
    CHECK(clear_ia32_bndcfgs::is_disabled(~clear_ia32_bndcfgs::mask));

    g_msrs[addr] = mask | (mask << 32);
    CHECK_FALSE(clear_ia32_bndcfgs::is_allowed0());
    CHECK(clear_ia32_bndcfgs::is_allowed1());

    g_msrs[addr] = ~(mask | (mask << 32));
    CHECK(clear_ia32_bndcfgs::is_allowed0());
    CHECK_FALSE(clear_ia32_bndcfgs::is_allowed1());
}

TEST_CASE("ia32_vmx_true_entry_ctls")
{
    using namespace intel_x64::msrs::ia32_vmx_true_entry_ctls;

    g_msrs[addr] = 0x00000000FFFFFFFFULL;
    CHECK(get() == 0x00000000FFFFFFFFULL);

    dump(0);

    g_msrs[addr] = 0x0UL;
    CHECK(get() == 0x0UL);

    dump(0);

    g_msrs[addr] = 0x00000000FFFFFFFFULL;
    CHECK(allowed0() == 0xFFFFFFFFUL);
    CHECK(allowed1() == 0x00000000UL);

    dump(0);

    g_msrs[addr] = 0xFFFFFFFF00000000ULL;
    CHECK(allowed0() == 0x00000000UL);
    CHECK(allowed1() == 0xFFFFFFFFUL);

    dump(0);
}

TEST_CASE("ia32_vmx_true_entry_ctls_load_debug_controls")
{
    using namespace intel_x64::msrs::ia32_vmx_true_entry_ctls;
    auto mask = load_debug_controls::mask;

    g_msrs[addr] = mask;
    CHECK(load_debug_controls::is_enabled());
    g_msrs[addr] = ~mask;
    CHECK(load_debug_controls::is_disabled());

    g_msrs[addr] = mask;
    CHECK(load_debug_controls::is_enabled(load_debug_controls::mask));
    g_msrs[addr] = ~mask;
    CHECK(load_debug_controls::is_disabled(~load_debug_controls::mask));

    g_msrs[addr] = mask | (mask << 32);
    CHECK_FALSE(load_debug_controls::is_allowed0());
    CHECK(load_debug_controls::is_allowed1());

    g_msrs[addr] = ~(mask | (mask << 32));
    CHECK(load_debug_controls::is_allowed0());
    CHECK_FALSE(load_debug_controls::is_allowed1());
}

TEST_CASE("ia32_vmx_true_entry_ctls_ia_32e_mode_guest")
{
    using namespace intel_x64::msrs::ia32_vmx_true_entry_ctls;
    auto mask = ia_32e_mode_guest::mask;

    g_msrs[addr] = mask;
    CHECK(ia_32e_mode_guest::is_enabled());
    g_msrs[addr] = ~mask;
    CHECK(ia_32e_mode_guest::is_disabled());

    g_msrs[addr] = mask;
    CHECK(ia_32e_mode_guest::is_enabled(ia_32e_mode_guest::mask));
    g_msrs[addr] = ~mask;
    CHECK(ia_32e_mode_guest::is_disabled(~ia_32e_mode_guest::mask));

    g_msrs[addr] = mask | (mask << 32);
    CHECK_FALSE(ia_32e_mode_guest::is_allowed0());
    CHECK(ia_32e_mode_guest::is_allowed1());

    g_msrs[addr] = ~(mask | (mask << 32));
    CHECK(ia_32e_mode_guest::is_allowed0());
    CHECK_FALSE(ia_32e_mode_guest::is_allowed1());
}

TEST_CASE("ia32_vmx_true_entry_ctls_entry_to_smm")
{
    using namespace intel_x64::msrs::ia32_vmx_true_entry_ctls;
    auto mask = entry_to_smm::mask;

    g_msrs[addr] = mask;
    CHECK(entry_to_smm::is_enabled());
    g_msrs[addr] = ~mask;
    CHECK(entry_to_smm::is_disabled());

    g_msrs[addr] = mask;
    CHECK(entry_to_smm::is_enabled(entry_to_smm::mask));
    g_msrs[addr] = ~mask;
    CHECK(entry_to_smm::is_disabled(~entry_to_smm::mask));

    g_msrs[addr] = mask | (mask << 32);
    CHECK_FALSE(entry_to_smm::is_allowed0());
    CHECK(entry_to_smm::is_allowed1());

    g_msrs[addr] = ~(mask | (mask << 32));
    CHECK(entry_to_smm::is_allowed0());
    CHECK_FALSE(entry_to_smm::is_allowed1());
}

TEST_CASE("ia32_vmx_true_entry_ctls_deactivate_dual_monitor_treatment")
{
    using namespace intel_x64::msrs::ia32_vmx_true_entry_ctls;
    auto mask = deactivate_dual_monitor_treatment::mask;

    g_msrs[addr] = mask;
    CHECK(deactivate_dual_monitor_treatment::is_enabled());
    g_msrs[addr] = ~mask;
    CHECK(deactivate_dual_monitor_treatment::is_disabled());

    g_msrs[addr] = mask;
    CHECK(deactivate_dual_monitor_treatment::is_enabled(deactivate_dual_monitor_treatment::mask));
    g_msrs[addr] = ~mask;
    CHECK(deactivate_dual_monitor_treatment::is_disabled(~deactivate_dual_monitor_treatment::mask));

    g_msrs[addr] = mask | (mask << 32);
    CHECK_FALSE(deactivate_dual_monitor_treatment::is_allowed0());
    CHECK(deactivate_dual_monitor_treatment::is_allowed1());

    g_msrs[addr] = ~(mask | (mask << 32));
    CHECK(deactivate_dual_monitor_treatment::is_allowed0());
    CHECK_FALSE(deactivate_dual_monitor_treatment::is_allowed1());
}

TEST_CASE("ia32_vmx_true_entry_ctls_load_ia32_perf_global_ctrl")
{
    using namespace intel_x64::msrs::ia32_vmx_true_entry_ctls;
    auto mask = load_ia32_perf_global_ctrl::mask;

    g_msrs[addr] = mask;
    CHECK(load_ia32_perf_global_ctrl::is_enabled());
    g_msrs[addr] = ~mask;
    CHECK(load_ia32_perf_global_ctrl::is_disabled());

    g_msrs[addr] = mask;
    CHECK(load_ia32_perf_global_ctrl::is_enabled(load_ia32_perf_global_ctrl::mask));
    g_msrs[addr] = ~mask;
    CHECK(load_ia32_perf_global_ctrl::is_disabled(~load_ia32_perf_global_ctrl::mask));

    g_msrs[addr] = mask | (mask << 32);
    CHECK_FALSE(load_ia32_perf_global_ctrl::is_allowed0());
    CHECK(load_ia32_perf_global_ctrl::is_allowed1());

    g_msrs[addr] = ~(mask | (mask << 32));
    CHECK(load_ia32_perf_global_ctrl::is_allowed0());
    CHECK_FALSE(load_ia32_perf_global_ctrl::is_allowed1());
}

TEST_CASE("ia32_vmx_true_entry_ctls_load_ia32_pat")
{
    using namespace intel_x64::msrs::ia32_vmx_true_entry_ctls;
    auto mask = load_ia32_pat::mask;

    g_msrs[addr] = mask;
    CHECK(load_ia32_pat::is_enabled());
    g_msrs[addr] = ~mask;
    CHECK(load_ia32_pat::is_disabled());

    g_msrs[addr] = mask;
    CHECK(load_ia32_pat::is_enabled(load_ia32_pat::mask));
    g_msrs[addr] = ~mask;
    CHECK(load_ia32_pat::is_disabled(~load_ia32_pat::mask));

    g_msrs[addr] = mask | (mask << 32);
    CHECK_FALSE(load_ia32_pat::is_allowed0());
    CHECK(load_ia32_pat::is_allowed1());

    g_msrs[addr] = ~(mask | (mask << 32));
    CHECK(load_ia32_pat::is_allowed0());
    CHECK_FALSE(load_ia32_pat::is_allowed1());
}

TEST_CASE("ia32_vmx_true_entry_ctls_load_ia32_efer")
{
    using namespace intel_x64::msrs::ia32_vmx_true_entry_ctls;
    auto mask = load_ia32_efer::mask;

    g_msrs[addr] = mask;
    CHECK(load_ia32_efer::is_enabled());
    g_msrs[addr] = ~mask;
    CHECK(load_ia32_efer::is_disabled());

    g_msrs[addr] = mask;
    CHECK(load_ia32_efer::is_enabled(load_ia32_efer::mask));
    g_msrs[addr] = ~mask;
    CHECK(load_ia32_efer::is_disabled(~load_ia32_efer::mask));

    g_msrs[addr] = mask | (mask << 32);
    CHECK_FALSE(load_ia32_efer::is_allowed0());
    CHECK(load_ia32_efer::is_allowed1());

    g_msrs[addr] = ~(mask | (mask << 32));
    CHECK(load_ia32_efer::is_allowed0());
    CHECK_FALSE(load_ia32_efer::is_allowed1());
}

TEST_CASE("ia32_vmx_true_entry_ctls_load_ia32_bndcfgs")
{
    using namespace intel_x64::msrs::ia32_vmx_true_entry_ctls;
    auto mask = load_ia32_bndcfgs::mask;

    g_msrs[addr] = mask;
    CHECK(load_ia32_bndcfgs::is_enabled());
    g_msrs[addr] = ~mask;
    CHECK(load_ia32_bndcfgs::is_disabled());

    g_msrs[addr] = mask;
    CHECK(load_ia32_bndcfgs::is_enabled(load_ia32_bndcfgs::mask));
    g_msrs[addr] = ~mask;
    CHECK(load_ia32_bndcfgs::is_disabled(~load_ia32_bndcfgs::mask));

    g_msrs[addr] = mask | (mask << 32);
    CHECK_FALSE(load_ia32_bndcfgs::is_allowed0());
    CHECK(load_ia32_bndcfgs::is_allowed1());

    g_msrs[addr] = ~(mask | (mask << 32));
    CHECK(load_ia32_bndcfgs::is_allowed0());
    CHECK_FALSE(load_ia32_bndcfgs::is_allowed1());
}

TEST_CASE("ia32_vmx_vmfunc")
{
    using namespace intel_x64::msrs::ia32_vmx_vmfunc;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_vmx_vmfunc_eptp_switching")
{
    using namespace intel_x64::msrs::ia32_vmx_vmfunc;
    auto mask = eptp_switching::mask;

    g_msrs[addr] = mask;
    CHECK(eptp_switching::is_enabled());

    g_msrs[addr] = mask;
    CHECK(eptp_switching::is_enabled(mask));

    g_msrs[addr] = mask | (mask << 32);
    CHECK(eptp_switching::is_allowed1());

    g_msrs[addr] = ~(mask | (mask << 32));
    CHECK_FALSE(eptp_switching::is_allowed1());
}

TEST_CASE("ia32_a_pmc0")
{
    using namespace intel_x64::msrs::ia32_a_pmc0;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_a_pmc1")
{
    using namespace intel_x64::msrs::ia32_a_pmc1;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_a_pmc2")
{
    using namespace intel_x64::msrs::ia32_a_pmc2;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_a_pmc3")
{
    using namespace intel_x64::msrs::ia32_a_pmc3;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_a_pmc4")
{
    using namespace intel_x64::msrs::ia32_a_pmc4;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_a_pmc5")
{
    using namespace intel_x64::msrs::ia32_a_pmc5;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_a_pmc6")
{
    using namespace intel_x64::msrs::ia32_a_pmc6;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_a_pmc7")
{
    using namespace intel_x64::msrs::ia32_a_pmc7;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mcg_ext_ctl")
{
    using namespace intel_x64::msrs::ia32_mcg_ext_ctl;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mcg_ext_ctl_lmce_en")
{
    using namespace intel_x64::msrs::ia32_mcg_ext_ctl;

    lmce_en::enable();
    CHECK(lmce_en::is_enabled());
    lmce_en::disable();
    CHECK(lmce_en::is_disabled());

    lmce_en::enable(lmce_en::mask);
    CHECK(lmce_en::is_enabled(lmce_en::mask));
    lmce_en::disable(0x0);
    CHECK(lmce_en::is_disabled(0x0));
}

TEST_CASE("ia32_sgx_svn_sinit")
{
    using namespace intel_x64::msrs::ia32_sgx_svn_sinit;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_sgx_svn_sinit_lock")
{
    using namespace intel_x64::msrs::ia32_sgx_svn_sinit;

    g_msrs[addr] = lock::mask;
    CHECK(lock::is_enabled());
    g_msrs[addr] = 0x0;
    CHECK(lock::is_disabled());

    g_msrs[addr] = lock::mask;
    CHECK(lock::is_enabled(lock::mask));
    g_msrs[addr] = 0x0;
    CHECK(lock::is_disabled(0x0));
}

TEST_CASE("ia32_sgx_svn_sinit_sgx_svn_sinit")
{
    using namespace intel_x64::msrs::ia32_sgx_svn_sinit;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(sgx_svn_sinit::get() == (sgx_svn_sinit::mask >> sgx_svn_sinit::from));
    CHECK(sgx_svn_sinit::get(sgx_svn_sinit::mask) == (sgx_svn_sinit::mask >> sgx_svn_sinit::from));
}

TEST_CASE("ia32_rtit_output_base")
{
    using namespace intel_x64::msrs::ia32_rtit_output_base;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_rtit_output_base_base_phys_address")
{
    using namespace intel_x64::msrs::ia32_rtit_output_base;

    base_phys_address::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(base_phys_address::get() == (base_phys_address::mask >> base_phys_address::from));

    base_phys_address::set(base_phys_address::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(base_phys_address::get(base_phys_address::mask) == (base_phys_address::mask >> base_phys_address::from));
}

TEST_CASE("ia32_rtit_output_mask_ptrs")
{
    using namespace intel_x64::msrs::ia32_rtit_output_mask_ptrs;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_rtit_output_mask_ptrs_mask_table_offset")
{
    using namespace intel_x64::msrs::ia32_rtit_output_mask_ptrs;

    mask_table_offset::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(mask_table_offset::get() == (mask_table_offset::mask >> mask_table_offset::from));

    mask_table_offset::set(mask_table_offset::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(mask_table_offset::get(mask_table_offset::mask) == (mask_table_offset::mask >> mask_table_offset::from));
}

TEST_CASE("ia32_rtit_output_mask_ptrs_output_offset")
{
    using namespace intel_x64::msrs::ia32_rtit_output_mask_ptrs;

    output_offset::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(output_offset::get() == (output_offset::mask >> output_offset::from));

    output_offset::set(output_offset::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(output_offset::get(output_offset::mask) == (output_offset::mask >> output_offset::from));
}

TEST_CASE("ia32_rtit_ctl")
{
    using namespace intel_x64::msrs::ia32_rtit_ctl;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_rtit_ctl_traceen")
{
    using namespace intel_x64::msrs::ia32_rtit_ctl;

    traceen::enable();
    CHECK(traceen::is_enabled());
    traceen::disable();
    CHECK(traceen::is_disabled());

    traceen::enable(traceen::mask);
    CHECK(traceen::is_enabled(traceen::mask));
    traceen::disable(0x0);
    CHECK(traceen::is_disabled(0x0));
}

TEST_CASE("ia32_rtit_ctl_cycen")
{
    using namespace intel_x64::msrs::ia32_rtit_ctl;

    cycen::enable();
    CHECK(cycen::is_enabled());
    cycen::disable();
    CHECK(cycen::is_disabled());

    cycen::enable(cycen::mask);
    CHECK(cycen::is_enabled(cycen::mask));
    cycen::disable(0x0);
    CHECK(cycen::is_disabled(0x0));
}

TEST_CASE("ia32_rtit_ctl_os")
{
    using namespace intel_x64::msrs::ia32_rtit_ctl;

    os::enable();
    CHECK(os::is_enabled());
    os::disable();
    CHECK(os::is_disabled());

    os::enable(os::mask);
    CHECK(os::is_enabled(os::mask));
    os::disable(0x0);
    CHECK(os::is_disabled(0x0));
}

TEST_CASE("ia32_rtit_ctl_user")
{
    using namespace intel_x64::msrs::ia32_rtit_ctl;

    user::enable();
    CHECK(user::is_enabled());
    user::disable();
    CHECK(user::is_disabled());

    user::enable(user::mask);
    CHECK(user::is_enabled(user::mask));
    user::disable(0x0);
    CHECK(user::is_disabled(0x0));
}

TEST_CASE("ia32_rtit_ctl_fabricen")
{
    using namespace intel_x64::msrs::ia32_rtit_ctl;

    fabricen::enable();
    CHECK(fabricen::is_enabled());
    fabricen::disable();
    CHECK(fabricen::is_disabled());

    fabricen::enable(fabricen::mask);
    CHECK(fabricen::is_enabled(fabricen::mask));
    fabricen::disable(0x0);
    CHECK(fabricen::is_disabled(0x0));
}

TEST_CASE("ia32_rtit_ctl_cr3_filter")
{
    using namespace intel_x64::msrs::ia32_rtit_ctl;

    cr3_filter::enable();
    CHECK(cr3_filter::is_enabled());
    cr3_filter::disable();
    CHECK(cr3_filter::is_disabled());

    cr3_filter::enable(cr3_filter::mask);
    CHECK(cr3_filter::is_enabled(cr3_filter::mask));
    cr3_filter::disable(0x0);
    CHECK(cr3_filter::is_disabled(0x0));
}

TEST_CASE("ia32_rtit_ctl_topa")
{
    using namespace intel_x64::msrs::ia32_rtit_ctl;

    topa::enable();
    CHECK(topa::is_enabled());
    topa::disable();
    CHECK(topa::is_disabled());

    topa::enable(topa::mask);
    CHECK(topa::is_enabled(topa::mask));
    topa::disable(0x0);
    CHECK(topa::is_disabled(0x0));
}

TEST_CASE("ia32_rtit_ctl_mtcen")
{
    using namespace intel_x64::msrs::ia32_rtit_ctl;

    mtcen::enable();
    CHECK(mtcen::is_enabled());
    mtcen::disable();
    CHECK(mtcen::is_disabled());

    mtcen::enable(mtcen::mask);
    CHECK(mtcen::is_enabled(mtcen::mask));
    mtcen::disable(0x0);
    CHECK(mtcen::is_disabled(0x0));
}

TEST_CASE("ia32_rtit_ctl_tscen")
{
    using namespace intel_x64::msrs::ia32_rtit_ctl;

    tscen::enable();
    CHECK(tscen::is_enabled());
    tscen::disable();
    CHECK(tscen::is_disabled());

    tscen::enable(tscen::mask);
    CHECK(tscen::is_enabled(tscen::mask));
    tscen::disable(0x0);
    CHECK(tscen::is_disabled(0x0));
}

TEST_CASE("ia32_rtit_ctl_disretc")
{
    using namespace intel_x64::msrs::ia32_rtit_ctl;

    disretc::enable();
    CHECK(disretc::is_enabled());
    disretc::disable();
    CHECK(disretc::is_disabled());

    disretc::enable(disretc::mask);
    CHECK(disretc::is_enabled(disretc::mask));
    disretc::disable(0x0);
    CHECK(disretc::is_disabled(0x0));
}

TEST_CASE("ia32_rtit_ctl_branchen")
{
    using namespace intel_x64::msrs::ia32_rtit_ctl;

    branchen::enable();
    CHECK(branchen::is_enabled());
    branchen::disable();
    CHECK(branchen::is_disabled());

    branchen::enable(branchen::mask);
    CHECK(branchen::is_enabled(branchen::mask));
    branchen::disable(0x0);
    CHECK(branchen::is_disabled(0x0));
}

TEST_CASE("ia32_rtit_ctl_mtcfreq")
{
    using namespace intel_x64::msrs::ia32_rtit_ctl;

    mtcfreq::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(mtcfreq::get() == (mtcfreq::mask >> mtcfreq::from));

    mtcfreq::set(mtcfreq::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(mtcfreq::get(mtcfreq::mask) == (mtcfreq::mask >> mtcfreq::from));
}

TEST_CASE("ia32_rtit_ctl_cycthresh")
{
    using namespace intel_x64::msrs::ia32_rtit_ctl;

    cycthresh::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(cycthresh::get() == (cycthresh::mask >> cycthresh::from));

    cycthresh::set(cycthresh::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(cycthresh::get(cycthresh::mask) == (cycthresh::mask >> cycthresh::from));
}

TEST_CASE("ia32_rtit_ctl_psbfreq")
{
    using namespace intel_x64::msrs::ia32_rtit_ctl;

    psbfreq::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(psbfreq::get() == (psbfreq::mask >> psbfreq::from));

    psbfreq::set(psbfreq::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(psbfreq::get(psbfreq::mask) == (psbfreq::mask >> psbfreq::from));
}

TEST_CASE("ia32_rtit_ctl_addr0_cfg")
{
    using namespace intel_x64::msrs::ia32_rtit_ctl;

    addr0_cfg::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(addr0_cfg::get() == (addr0_cfg::mask >> addr0_cfg::from));

    addr0_cfg::set(addr0_cfg::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(addr0_cfg::get(addr0_cfg::mask) == (addr0_cfg::mask >> addr0_cfg::from));
}

TEST_CASE("ia32_rtit_ctl_addr1_cfg")
{
    using namespace intel_x64::msrs::ia32_rtit_ctl;

    addr1_cfg::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(addr1_cfg::get() == (addr1_cfg::mask >> addr1_cfg::from));

    addr1_cfg::set(addr1_cfg::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(addr1_cfg::get(addr1_cfg::mask) == (addr1_cfg::mask >> addr1_cfg::from));
}

TEST_CASE("ia32_rtit_ctl_addr2_cfg")
{
    using namespace intel_x64::msrs::ia32_rtit_ctl;

    addr2_cfg::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(addr2_cfg::get() == (addr2_cfg::mask >> addr2_cfg::from));

    addr2_cfg::set(addr2_cfg::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(addr2_cfg::get(addr2_cfg::mask) == (addr2_cfg::mask >> addr2_cfg::from));
}

TEST_CASE("ia32_rtit_ctl_addr3_cfg")
{
    using namespace intel_x64::msrs::ia32_rtit_ctl;

    addr3_cfg::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(addr3_cfg::get() == (addr3_cfg::mask >> addr3_cfg::from));

    addr3_cfg::set(addr3_cfg::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(addr3_cfg::get(addr3_cfg::mask) == (addr3_cfg::mask >> addr3_cfg::from));
}

TEST_CASE("ia32_rtit_status")
{
    using namespace intel_x64::msrs::ia32_rtit_status;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_rtit_status_filteren")
{
    using namespace intel_x64::msrs::ia32_rtit_status;

    g_msrs[addr] = filteren::mask;
    CHECK(filteren::is_enabled());
    g_msrs[addr] = 0x0;
    CHECK(filteren::is_disabled());

    g_msrs[addr] = filteren::mask;
    CHECK(filteren::is_enabled(filteren::mask));
    g_msrs[addr] = 0x0;
    CHECK(filteren::is_disabled(0x0));
}

TEST_CASE("ia32_rtit_status_contexen")
{
    using namespace intel_x64::msrs::ia32_rtit_status;

    g_msrs[addr] = contexen::mask;
    CHECK(contexen::is_enabled());
    g_msrs[addr] = 0x0;
    CHECK(contexen::is_disabled());

    g_msrs[addr] = contexen::mask;
    CHECK(contexen::is_enabled(contexen::mask));
    g_msrs[addr] = 0x0;
    CHECK(contexen::is_disabled(0x0));
}

TEST_CASE("ia32_rtit_status_triggeren")
{
    using namespace intel_x64::msrs::ia32_rtit_status;

    g_msrs[addr] = triggeren::mask;
    CHECK(triggeren::is_enabled());
    g_msrs[addr] = 0x0;
    CHECK(triggeren::is_disabled());

    g_msrs[addr] = triggeren::mask;
    CHECK(triggeren::is_enabled(triggeren::mask));
    g_msrs[addr] = 0x0;
    CHECK(triggeren::is_disabled(0x0));
}

TEST_CASE("ia32_rtit_status_error")
{
    using namespace intel_x64::msrs::ia32_rtit_status;

    error::enable();
    CHECK(error::is_enabled());
    error::disable();
    CHECK(error::is_disabled());

    error::enable(error::mask);
    CHECK(error::is_enabled(error::mask));
    error::disable(0x0);
    CHECK(error::is_disabled(0x0));
}

TEST_CASE("ia32_rtit_status_stopped")
{
    using namespace intel_x64::msrs::ia32_rtit_status;

    stopped::enable();
    CHECK(stopped::is_enabled());
    stopped::disable();
    CHECK(stopped::is_disabled());

    stopped::enable(stopped::mask);
    CHECK(stopped::is_enabled(stopped::mask));
    stopped::disable(0x0);
    CHECK(stopped::is_disabled(0x0));
}

TEST_CASE("ia32_rtit_status_packetbytecnt")
{
    using namespace intel_x64::msrs::ia32_rtit_status;

    packetbytecnt::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(packetbytecnt::get() == (packetbytecnt::mask >> packetbytecnt::from));

    packetbytecnt::set(packetbytecnt::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(packetbytecnt::get(packetbytecnt::mask) == (packetbytecnt::mask >> packetbytecnt::from));
}

TEST_CASE("ia32_rtit_cr3_match")
{
    using namespace intel_x64::msrs::ia32_rtit_cr3_match;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_rtit_cr3_match_cr3")
{
    using namespace intel_x64::msrs::ia32_rtit_cr3_match;

    cr3::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(cr3::get() == (cr3::mask >> cr3::from));

    cr3::set(cr3::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(cr3::get(cr3::mask) == (cr3::mask >> cr3::from));

}

TEST_CASE("ia32_rtit_addr0_a")
{
    using namespace intel_x64::msrs::ia32_rtit_addr0_a;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_rtit_addr0_a_virtual_address")
{
    using namespace intel_x64::msrs::ia32_rtit_addr0_a;

    virtual_address::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(virtual_address::get() == (virtual_address::mask >> virtual_address::from));

    virtual_address::set(virtual_address::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(virtual_address::get(virtual_address::mask) == (virtual_address::mask >> virtual_address::from));
}

TEST_CASE("ia32_rtit_addr0_a_signext_va")
{
    using namespace intel_x64::msrs::ia32_rtit_addr0_a;

    signext_va::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(signext_va::get() == (signext_va::mask >> signext_va::from));

    signext_va::set(signext_va::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(signext_va::get(signext_va::mask) == (signext_va::mask >> signext_va::from));
}

TEST_CASE("ia32_rtit_addr0_b")
{
    using namespace intel_x64::msrs::ia32_rtit_addr0_b;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_rtit_addr0_b_virtual_address")
{
    using namespace intel_x64::msrs::ia32_rtit_addr0_b;

    virtual_address::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(virtual_address::get() == (virtual_address::mask >> virtual_address::from));

    virtual_address::set(virtual_address::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(virtual_address::get(virtual_address::mask) == (virtual_address::mask >> virtual_address::from));
}

TEST_CASE("ia32_rtit_addr0_b_signext_va")
{
    using namespace intel_x64::msrs::ia32_rtit_addr0_b;

    signext_va::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(signext_va::get() == (signext_va::mask >> signext_va::from));

    signext_va::set(signext_va::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(signext_va::get(signext_va::mask) == (signext_va::mask >> signext_va::from));
}

TEST_CASE("ia32_rtit_addr1_a")
{
    using namespace intel_x64::msrs::ia32_rtit_addr1_a;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_rtit_addr1_a_virtual_address")
{
    using namespace intel_x64::msrs::ia32_rtit_addr1_a;

    virtual_address::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(virtual_address::get() == (virtual_address::mask >> virtual_address::from));

    virtual_address::set(virtual_address::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(virtual_address::get(virtual_address::mask) == (virtual_address::mask >> virtual_address::from));
}

TEST_CASE("ia32_rtit_addr1_a_signext_va")
{
    using namespace intel_x64::msrs::ia32_rtit_addr1_a;

    signext_va::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(signext_va::get() == (signext_va::mask >> signext_va::from));

    signext_va::set(signext_va::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(signext_va::get(signext_va::mask) == (signext_va::mask >> signext_va::from));
}

TEST_CASE("ia32_rtit_addr1_b")
{
    using namespace intel_x64::msrs::ia32_rtit_addr1_b;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_rtit_addr1_b_virtual_address")
{
    using namespace intel_x64::msrs::ia32_rtit_addr1_b;

    virtual_address::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(virtual_address::get() == (virtual_address::mask >> virtual_address::from));

    virtual_address::set(virtual_address::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(virtual_address::get(virtual_address::mask) == (virtual_address::mask >> virtual_address::from));
}

TEST_CASE("ia32_rtit_addr1_b_signext_va")
{
    using namespace intel_x64::msrs::ia32_rtit_addr1_b;

    signext_va::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(signext_va::get() == (signext_va::mask >> signext_va::from));

    signext_va::set(signext_va::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(signext_va::get(signext_va::mask) == (signext_va::mask >> signext_va::from));
}

TEST_CASE("ia32_rtit_addr2_a")
{
    using namespace intel_x64::msrs::ia32_rtit_addr2_a;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_rtit_addr2_a_virtual_address")
{
    using namespace intel_x64::msrs::ia32_rtit_addr2_a;

    virtual_address::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(virtual_address::get() == (virtual_address::mask >> virtual_address::from));

    virtual_address::set(virtual_address::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(virtual_address::get(virtual_address::mask) == (virtual_address::mask >> virtual_address::from));
}

TEST_CASE("ia32_rtit_addr2_a_signext_va")
{
    using namespace intel_x64::msrs::ia32_rtit_addr2_a;

    signext_va::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(signext_va::get() == (signext_va::mask >> signext_va::from));

    signext_va::set(signext_va::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(signext_va::get(signext_va::mask) == (signext_va::mask >> signext_va::from));
}

TEST_CASE("ia32_rtit_addr2_b")
{
    using namespace intel_x64::msrs::ia32_rtit_addr2_b;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_rtit_addr2_b_virtual_address")
{
    using namespace intel_x64::msrs::ia32_rtit_addr2_b;

    virtual_address::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(virtual_address::get() == (virtual_address::mask >> virtual_address::from));

    virtual_address::set(virtual_address::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(virtual_address::get(virtual_address::mask) == (virtual_address::mask >> virtual_address::from));
}

TEST_CASE("ia32_rtit_addr2_b_signext_va")
{
    using namespace intel_x64::msrs::ia32_rtit_addr2_b;

    signext_va::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(signext_va::get() == (signext_va::mask >> signext_va::from));

    signext_va::set(signext_va::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(signext_va::get(signext_va::mask) == (signext_va::mask >> signext_va::from));
}

TEST_CASE("ia32_rtit_addr3_a")
{
    using namespace intel_x64::msrs::ia32_rtit_addr3_a;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_rtit_addr3_a_virtual_address")
{
    using namespace intel_x64::msrs::ia32_rtit_addr3_a;

    virtual_address::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(virtual_address::get() == (virtual_address::mask >> virtual_address::from));

    virtual_address::set(virtual_address::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(virtual_address::get(virtual_address::mask) == (virtual_address::mask >> virtual_address::from));
}

TEST_CASE("ia32_rtit_addr3_a_signext_va")
{
    using namespace intel_x64::msrs::ia32_rtit_addr3_a;

    signext_va::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(signext_va::get() == (signext_va::mask >> signext_va::from));

    signext_va::set(signext_va::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(signext_va::get(signext_va::mask) == (signext_va::mask >> signext_va::from));
}

TEST_CASE("ia32_rtit_addr3_b")
{
    using namespace intel_x64::msrs::ia32_rtit_addr3_b;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_rtit_addr3_b_virtual_address")
{
    using namespace intel_x64::msrs::ia32_rtit_addr3_b;

    virtual_address::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(virtual_address::get() == (virtual_address::mask >> virtual_address::from));

    virtual_address::set(virtual_address::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(virtual_address::get(virtual_address::mask) == (virtual_address::mask >> virtual_address::from));
}

TEST_CASE("ia32_rtit_addr3_b_signext_va")
{
    using namespace intel_x64::msrs::ia32_rtit_addr3_b;

    signext_va::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(signext_va::get() == (signext_va::mask >> signext_va::from));

    signext_va::set(signext_va::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(signext_va::get(signext_va::mask) == (signext_va::mask >> signext_va::from));
}

TEST_CASE("ia32_ds_area")
{
    using namespace intel_x64::msrs::ia32_ds_area;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_tsc_deadline")
{
    using namespace intel_x64::msrs::ia32_tsc_deadline;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_pm_enable")
{
    using namespace intel_x64::msrs::ia32_pm_enable;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_pm_enable_hwp")
{
    using namespace intel_x64::msrs::ia32_pm_enable;

    hwp::enable();
    CHECK(hwp::is_enabled());
    hwp::disable();
    CHECK(hwp::is_disabled());

    hwp::enable(hwp::mask);
    CHECK(hwp::is_enabled(hwp::mask));
    hwp::disable(0x0);
    CHECK(hwp::is_disabled(0x0));
}

TEST_CASE("ia32_hwp_capabilities")
{
    using namespace intel_x64::msrs::ia32_hwp_capabilities;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_hwp_capabilities_highest_perf")
{
    using namespace intel_x64::msrs::ia32_hwp_capabilities;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(highest_perf::get() == (highest_perf::mask >> highest_perf::from));
    CHECK(highest_perf::get(highest_perf::mask) == (highest_perf::mask >> highest_perf::from));
}

TEST_CASE("ia32_hwp_capabilities_guaranteed_perf")
{
    using namespace intel_x64::msrs::ia32_hwp_capabilities;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(guaranteed_perf::get() == (guaranteed_perf::mask >> guaranteed_perf::from));
    CHECK(guaranteed_perf::get(guaranteed_perf::mask) == (guaranteed_perf::mask >> guaranteed_perf::from));
}

TEST_CASE("ia32_hwp_capabilities_most_efficient_perf")
{
    using namespace intel_x64::msrs::ia32_hwp_capabilities;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(most_efficient_perf::get() == (most_efficient_perf::mask >> most_efficient_perf::from));
    CHECK(most_efficient_perf::get(most_efficient_perf::mask) == (most_efficient_perf::mask >> most_efficient_perf::from));
}

TEST_CASE("ia32_hwp_capabilities_lowest_perf")
{
    using namespace intel_x64::msrs::ia32_hwp_capabilities;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(lowest_perf::get() == (lowest_perf::mask >> lowest_perf::from));
    CHECK(lowest_perf::get(lowest_perf::mask) == (lowest_perf::mask >> lowest_perf::from));
}

TEST_CASE("ia32_hwp_request_pkg")
{
    using namespace intel_x64::msrs::ia32_hwp_request_pkg;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_hwp_request_pkg_min_perf")
{
    using namespace intel_x64::msrs::ia32_hwp_request_pkg;

    min_perf::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(min_perf::get() == (min_perf::mask >> min_perf::from));

    min_perf::set(min_perf::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(min_perf::get(min_perf::mask) == (min_perf::mask >> min_perf::from));
}

TEST_CASE("ia32_hwp_request_pkg_max_perf")
{
    using namespace intel_x64::msrs::ia32_hwp_request_pkg;

    max_perf::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(max_perf::get() == (max_perf::mask >> max_perf::from));

    max_perf::set(max_perf::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(max_perf::get(max_perf::mask) == (max_perf::mask >> max_perf::from));
}

TEST_CASE("ia32_hwp_request_pkg_desired_perf")
{
    using namespace intel_x64::msrs::ia32_hwp_request_pkg;

    desired_perf::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(desired_perf::get() == (desired_perf::mask >> desired_perf::from));

    desired_perf::set(desired_perf::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(desired_perf::get(desired_perf::mask) == (desired_perf::mask >> desired_perf::from));
}

TEST_CASE("ia32_hwp_request_pkg_energy_perf_pref")
{
    using namespace intel_x64::msrs::ia32_hwp_request_pkg;

    energy_perf_pref::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(energy_perf_pref::get() == (energy_perf_pref::mask >> energy_perf_pref::from));

    energy_perf_pref::set(energy_perf_pref::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(energy_perf_pref::get(energy_perf_pref::mask) == (energy_perf_pref::mask >> energy_perf_pref::from));
}

TEST_CASE("ia32_hwp_request_pkg_activity_window")
{
    using namespace intel_x64::msrs::ia32_hwp_request_pkg;

    activity_window::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(activity_window::get() == (activity_window::mask >> activity_window::from));

    activity_window::set(activity_window::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(activity_window::get(activity_window::mask) == (activity_window::mask >> activity_window::from));
}

TEST_CASE("ia32_hwp_interrupt")
{
    using namespace intel_x64::msrs::ia32_hwp_interrupt;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_hwp_interrupt_perf_change")
{
    using namespace intel_x64::msrs::ia32_hwp_interrupt;

    perf_change::enable();
    CHECK(perf_change::is_enabled());
    perf_change::disable();
    CHECK(perf_change::is_disabled());

    perf_change::enable(perf_change::mask);
    CHECK(perf_change::is_enabled(perf_change::mask));
    perf_change::disable(0x0);
    CHECK(perf_change::is_disabled(0x0));
}

TEST_CASE("ia32_hwp_interrupt_excursion_min")
{
    using namespace intel_x64::msrs::ia32_hwp_interrupt;

    excursion_min::enable();
    CHECK(excursion_min::is_enabled());
    excursion_min::disable();
    CHECK(excursion_min::is_disabled());

    excursion_min::enable(excursion_min::mask);
    CHECK(excursion_min::is_enabled(excursion_min::mask));
    excursion_min::disable(0x0);
    CHECK(excursion_min::is_disabled(0x0));
}

TEST_CASE("ia32_hwp_request")
{
    using namespace intel_x64::msrs::ia32_hwp_request;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_hwp_request_min_perf")
{
    using namespace intel_x64::msrs::ia32_hwp_request;

    min_perf::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(min_perf::get() == (min_perf::mask >> min_perf::from));

    min_perf::set(min_perf::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(min_perf::get(min_perf::mask) == (min_perf::mask >> min_perf::from));
}

TEST_CASE("ia32_hwp_request_max_perf")
{
    using namespace intel_x64::msrs::ia32_hwp_request;

    max_perf::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(max_perf::get() == (max_perf::mask >> max_perf::from));

    max_perf::set(max_perf::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(max_perf::get(max_perf::mask) == (max_perf::mask >> max_perf::from));
}

TEST_CASE("ia32_hwp_request_desired_perf")
{
    using namespace intel_x64::msrs::ia32_hwp_request;

    desired_perf::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(desired_perf::get() == (desired_perf::mask >> desired_perf::from));

    desired_perf::set(desired_perf::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(desired_perf::get(desired_perf::mask) == (desired_perf::mask >> desired_perf::from));
}

TEST_CASE("ia32_hwp_request_energy_perf_pref")
{
    using namespace intel_x64::msrs::ia32_hwp_request;

    energy_perf_pref::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(energy_perf_pref::get() == (energy_perf_pref::mask >> energy_perf_pref::from));

    energy_perf_pref::set(energy_perf_pref::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(energy_perf_pref::get(energy_perf_pref::mask) == (energy_perf_pref::mask >> energy_perf_pref::from));
}

TEST_CASE("ia32_hwp_request_activity_window")
{
    using namespace intel_x64::msrs::ia32_hwp_request;

    activity_window::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(activity_window::get() == (activity_window::mask >> activity_window::from));

    activity_window::set(activity_window::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(activity_window::get(activity_window::mask) == (activity_window::mask >> activity_window::from));
}

TEST_CASE("ia32_hwp_request_package_control")
{
    using namespace intel_x64::msrs::ia32_hwp_request;

    package_control::enable();
    CHECK(package_control::is_enabled());
    package_control::disable();
    CHECK(package_control::is_disabled());

    package_control::enable(package_control::mask);
    CHECK(package_control::is_enabled(package_control::mask));
    package_control::disable(0x0);
    CHECK(package_control::is_disabled(0x0));
}

TEST_CASE("ia32_hwp_status")
{
    using namespace intel_x64::msrs::ia32_hwp_status;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_hwp_status_perf_change")
{
    using namespace intel_x64::msrs::ia32_hwp_status;

    perf_change::enable();
    CHECK(perf_change::is_enabled());
    perf_change::disable();
    CHECK(perf_change::is_disabled());

    perf_change::enable(perf_change::mask);
    CHECK(perf_change::is_enabled(perf_change::mask));
    perf_change::disable(0x0);
    CHECK(perf_change::is_disabled(0x0));
}

TEST_CASE("ia32_hwp_status_excursion_to_min")
{
    using namespace intel_x64::msrs::ia32_hwp_status;

    excursion_to_min::enable();
    CHECK(excursion_to_min::is_enabled());
    excursion_to_min::disable();
    CHECK(excursion_to_min::is_disabled());

    excursion_to_min::enable(excursion_to_min::mask);
    CHECK(excursion_to_min::is_enabled(excursion_to_min::mask));
    excursion_to_min::disable(0x0);
    CHECK(excursion_to_min::is_disabled(0x0));
}

TEST_CASE("ia32_debug_interface")
{
    using namespace intel_x64::msrs::ia32_debug_interface;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_debug_interface_enable")
{
    using namespace intel_x64::msrs::ia32_debug_interface;

    enable::enable();
    CHECK(enable::is_enabled());
    enable::disable();
    CHECK(enable::is_disabled());

    enable::enable(enable::mask);
    CHECK(enable::is_enabled(enable::mask));
    enable::disable(0x0);
    CHECK(enable::is_disabled(0x0));
}

TEST_CASE("ia32_debug_interface_lock")
{
    using namespace intel_x64::msrs::ia32_debug_interface;

    lock::enable();
    CHECK(lock::is_enabled());
    lock::disable();
    CHECK(lock::is_disabled());

    lock::enable(lock::mask);
    CHECK(lock::is_enabled(lock::mask));
    lock::disable(0x0);
    CHECK(lock::is_disabled(0x0));
}

TEST_CASE("ia32_debug_interface_debug_occurred")
{
    using namespace intel_x64::msrs::ia32_debug_interface;

    debug_occurred::enable();
    CHECK(debug_occurred::is_enabled());
    debug_occurred::disable();
    CHECK(debug_occurred::is_disabled());

    debug_occurred::enable(debug_occurred::mask);
    CHECK(debug_occurred::is_enabled(debug_occurred::mask));
    debug_occurred::disable(0x0);
    CHECK(debug_occurred::is_disabled(0x0));
}

TEST_CASE("ia32_l3_qos_cfg")
{
    using namespace intel_x64::msrs::ia32_l3_qos_cfg;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_l3_qos_cfg_enable")
{
    using namespace intel_x64::msrs::ia32_l3_qos_cfg;

    enable::enable();
    CHECK(enable::is_enabled());
    enable::disable();
    CHECK(enable::is_disabled());

    enable::enable(enable::mask);
    CHECK(enable::is_enabled(enable::mask));
    enable::disable(0x0);
    CHECK(enable::is_disabled(0x0));
}

TEST_CASE("ia32_qm_evtsel")
{
    using namespace intel_x64::msrs::ia32_qm_evtsel;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_qm_evtsel_event_id")
{
    using namespace intel_x64::msrs::ia32_qm_evtsel;

    event_id::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(event_id::get() == (event_id::mask >> event_id::from));

    event_id::set(event_id::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(event_id::get(event_id::mask) == (event_id::mask >> event_id::from));
}

TEST_CASE("ia32_qm_evtsel_resource_monitoring_id")
{
    using namespace intel_x64::msrs::ia32_qm_evtsel;

    resource_monitoring_id::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(resource_monitoring_id::get() == (resource_monitoring_id::mask >> resource_monitoring_id::from));

    resource_monitoring_id::set(resource_monitoring_id::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(resource_monitoring_id::get(resource_monitoring_id::mask) == (resource_monitoring_id::mask >> resource_monitoring_id::from));
}

TEST_CASE("ia32_qm_ctr")
{
    using namespace intel_x64::msrs::ia32_qm_ctr;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_qm_ctr_resource_monitored_data")
{
    using namespace intel_x64::msrs::ia32_qm_ctr;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(resource_monitored_data::get() == (resource_monitored_data::mask >> resource_monitored_data::from));
    CHECK(resource_monitored_data::get(resource_monitored_data::mask) == (resource_monitored_data::mask >> resource_monitored_data::from));
}

TEST_CASE("ia32_qm_ctr_unavailable")
{
    using namespace intel_x64::msrs::ia32_qm_ctr;

    g_msrs[addr] = unavailable::mask;
    CHECK(unavailable::is_enabled());
    g_msrs[addr] = 0x0;
    CHECK(unavailable::is_disabled());

    g_msrs[addr] = unavailable::mask;
    CHECK(unavailable::is_enabled(unavailable::mask));
    g_msrs[addr] = 0x0;
    CHECK(unavailable::is_disabled(0x0));
}

TEST_CASE("ia32_qm_ctr_error")
{
    using namespace intel_x64::msrs::ia32_qm_ctr;

    g_msrs[addr] = error::mask;
    CHECK(error::is_enabled());
    g_msrs[addr] = 0x0;
    CHECK(error::is_disabled());

    g_msrs[addr] = error::mask;
    CHECK(error::is_enabled(error::mask));
    g_msrs[addr] = 0x0;
    CHECK(error::is_disabled(0x0));
}

TEST_CASE("ia32_pqr_assoc")
{
    using namespace intel_x64::msrs::ia32_pqr_assoc;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_pqr_assoc_resource_monitoring_id")
{
    using namespace intel_x64::msrs::ia32_pqr_assoc;

    resource_monitoring_id::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(resource_monitoring_id::get() == (resource_monitoring_id::mask >> resource_monitoring_id::from));

    resource_monitoring_id::set(resource_monitoring_id::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(resource_monitoring_id::get(resource_monitoring_id::mask) == (resource_monitoring_id::mask >> resource_monitoring_id::from));
}

TEST_CASE("ia32_pqr_assoc_cos")
{
    using namespace intel_x64::msrs::ia32_pqr_assoc;

    cos::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(cos::get() == (cos::mask >> cos::from));

    cos::set(cos::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(cos::get(cos::mask) == (cos::mask >> cos::from));
}

TEST_CASE("ia32_bndcfgs")
{
    using namespace intel_x64::msrs::ia32_bndcfgs;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_bndcfgs_en")
{
    using namespace intel_x64::msrs::ia32_bndcfgs;

    en::enable();
    CHECK(en::is_enabled());
    en::disable();
    CHECK(en::is_disabled());

    en::enable(en::mask);
    CHECK(en::is_enabled(en::mask));
    en::disable(0x0);
    CHECK(en::is_disabled(0x0));
}

TEST_CASE("ia32_bndcfgs_bndpreserve")
{
    using namespace intel_x64::msrs::ia32_bndcfgs;

    bndpreserve::enable();
    CHECK(bndpreserve::is_enabled());
    bndpreserve::disable();
    CHECK(bndpreserve::is_disabled());

    bndpreserve::enable(bndpreserve::mask);
    CHECK(bndpreserve::is_enabled(bndpreserve::mask));
    bndpreserve::disable(0x0);
    CHECK(bndpreserve::is_disabled(0x0));
}

TEST_CASE("ia32_bndcfgs_base_address")
{
    using namespace intel_x64::msrs::ia32_bndcfgs;

    base_address::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(base_address::get() == (base_address::mask >> base_address::from));

    base_address::set(base_address::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(base_address::get(base_address::mask) == (base_address::mask >> base_address::from));
}

TEST_CASE("ia32_xss")
{
    using namespace intel_x64::msrs::ia32_xss;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_xss_trace_packet")
{
    using namespace intel_x64::msrs::ia32_xss;

    trace_packet::enable();
    CHECK(trace_packet::is_enabled());
    trace_packet::disable();
    CHECK(trace_packet::is_disabled());

    trace_packet::enable(trace_packet::mask);
    CHECK(trace_packet::is_enabled(trace_packet::mask));
    trace_packet::disable(0x0);
    CHECK(trace_packet::is_disabled(0x0));
}

TEST_CASE("ia32_pkg_hdc_ctl")
{
    using namespace intel_x64::msrs::ia32_pkg_hdc_ctl;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_pkg_hdc_ctl_hdc_pkg_enable")
{
    using namespace intel_x64::msrs::ia32_pkg_hdc_ctl;

    hdc_pkg_enable::enable();
    CHECK(hdc_pkg_enable::is_enabled());
    hdc_pkg_enable::disable();
    CHECK(hdc_pkg_enable::is_disabled());

    hdc_pkg_enable::enable(hdc_pkg_enable::mask);
    CHECK(hdc_pkg_enable::is_enabled(hdc_pkg_enable::mask));
    hdc_pkg_enable::disable(0x0);
    CHECK(hdc_pkg_enable::is_disabled(0x0));
}

TEST_CASE("ia32_pm_ctl1")
{
    using namespace intel_x64::msrs::ia32_pm_ctl1;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_pm_ctl1_hdc_allow_block")
{
    using namespace intel_x64::msrs::ia32_pm_ctl1;

    hdc_allow_block::enable();
    CHECK(hdc_allow_block::is_enabled());
    hdc_allow_block::disable();
    CHECK(hdc_allow_block::is_disabled());

    hdc_allow_block::enable(hdc_allow_block::mask);
    CHECK(hdc_allow_block::is_enabled(hdc_allow_block::mask));
    hdc_allow_block::disable(0x0);
    CHECK(hdc_allow_block::is_disabled(0x0));
}

TEST_CASE("ia32_thread_stall")
{
    using namespace intel_x64::msrs::ia32_thread_stall;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_thread_stall_stall_cycle_cnt")
{
    using namespace intel_x64::msrs::ia32_thread_stall;

    stall_cycle_cnt::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(stall_cycle_cnt::get() == (stall_cycle_cnt::mask >> stall_cycle_cnt::from));

    stall_cycle_cnt::set(stall_cycle_cnt::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(stall_cycle_cnt::get(stall_cycle_cnt::mask) == (stall_cycle_cnt::mask >> stall_cycle_cnt::from));
}

TEST_CASE("ia32_efer")
{
    using namespace intel_x64::msrs::ia32_efer;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_efer_sce")
{
    using namespace intel_x64::msrs::ia32_efer;

    sce::enable();
    CHECK(sce::is_enabled());
    sce::disable();
    CHECK(sce::is_disabled());

    sce::enable(sce::mask);
    CHECK(sce::is_enabled(sce::mask));
    sce::disable(0x0);
    CHECK(sce::is_disabled(0x0));
}

TEST_CASE("ia32_efer_lme")
{
    using namespace intel_x64::msrs::ia32_efer;

    lme::enable();
    CHECK(lme::is_enabled());
    lme::disable();
    CHECK(lme::is_disabled());

    lme::enable(lme::mask);
    CHECK(lme::is_enabled(lme::mask));
    lme::disable(0x0);
    CHECK(lme::is_disabled(0x0));
}

TEST_CASE("ia32_efer_lma")
{
    using namespace intel_x64::msrs::ia32_efer;

    lma::enable();
    CHECK(lma::is_enabled());
    lma::disable();
    CHECK(lma::is_disabled());

    lma::enable(lma::mask);
    CHECK(lma::is_enabled(lma::mask));
    lma::disable(0x0);
    CHECK(lma::is_disabled(0x0));
}

TEST_CASE("ia32_efer_nxe")
{
    using namespace intel_x64::msrs::ia32_efer;

    nxe::enable();
    CHECK(nxe::is_enabled());
    nxe::disable();
    CHECK(nxe::is_disabled());

    nxe::enable(nxe::mask);
    CHECK(nxe::is_enabled(nxe::mask));
    nxe::disable(0x0);
    CHECK(nxe::is_disabled(0x0));
}

TEST_CASE("ia32_fs_base")
{
    using namespace intel_x64::msrs::ia32_fs_base;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_gs_base")
{
    using namespace intel_x64::msrs::ia32_gs_base;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}
