//
// Bareflank Hypervisor
//
// Copyright (C) 2015 Assured Information Security, Inc.
// Author: Rian Quinn        <quinnr@ainfosec.com>
// Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
// Author: Connor Davis      <davisc@ainfosec.com>
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
#include <hippomocks.h>
#include <intrinsics/x86/intel_x64.h>
#include <intrinsics/x86/common_x64.h>
#include <test/vmcs_utils.h>

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

using namespace intel_x64;

std::map<uint32_t, uint64_t> g_msrs;
std::map<uint64_t, uint64_t> g_vmcs_fields;

uint64_t
test_read_msr(uint32_t addr) noexcept
{ return g_msrs[addr]; }

static bool
test_vmread(uint64_t field, uint64_t *val) noexcept
{
    *val = g_vmcs_fields[field];
    return true;
}

static bool
test_vmwrite(uint64_t field, uint64_t val) noexcept
{
    g_vmcs_fields[field] = val;
    return true;
}

static void
setup_intrinsics(MockRepository &mocks)
{
    mocks.OnCallFunc(_read_msr).Do(test_read_msr);
    mocks.OnCallFunc(_vmread).Do(test_vmread);
    mocks.OnCallFunc(_vmwrite).Do(test_vmwrite);
}

TEST_CASE("test name goes here")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(true);
}

TEST_CASE("vmcs_pin_based_vm_execution_controls")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::pin_based_vm_execution_controls::exists());

    vmcs::pin_based_vm_execution_controls::set(1UL);
    CHECK(vmcs::pin_based_vm_execution_controls::get() == 1UL);

    vmcs::pin_based_vm_execution_controls::set_if_exists(2UL);
    CHECK(vmcs::pin_based_vm_execution_controls::get_if_exists() == 2UL);
}

TEST_CASE("vmcs_pin_based_vm_execution_controls_external_interrupt_exiting")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::pin_based_vm_execution_controls::external_interrupt_exiting;

    g_msrs[msrs::ia32_vmx_true_pinbased_ctls::addr] = 0xffffffff00000000UL;

    enable();
    CHECK(is_enabled());

    disable();
    CHECK(is_disabled());

    enable_if_allowed();
    CHECK(is_enabled_if_exists());

    disable_if_allowed();
    CHECK(is_disabled_if_exists());
}

TEST_CASE("vmcs_pin_based_vm_execution_controls_nmi_exiting")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::pin_based_vm_execution_controls::nmi_exiting;

    g_msrs[msrs::ia32_vmx_true_pinbased_ctls::addr] = 0xffffffff00000000UL;

    enable();
    CHECK(is_enabled());

    disable();
    CHECK(is_disabled());

    enable_if_allowed();
    CHECK(is_enabled_if_exists());

    disable_if_allowed();
    CHECK(is_disabled_if_exists());
}

TEST_CASE("vmcs_pin_based_vm_execution_controls_virtual_nmis")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::pin_based_vm_execution_controls::virtual_nmis;

    g_msrs[msrs::ia32_vmx_true_pinbased_ctls::addr] = 0xffffffff00000000UL;

    enable();
    CHECK(is_enabled());

    disable();
    CHECK(is_disabled());

    enable_if_allowed();
    CHECK(is_enabled_if_exists());

    disable_if_allowed();
    CHECK(is_disabled_if_exists());
}

TEST_CASE("vmcs_pin_based_vm_execution_controls_activate_vmx_preemption_timer")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::pin_based_vm_execution_controls::activate_vmx_preemption_timer;

    g_msrs[msrs::ia32_vmx_true_pinbased_ctls::addr] = 0xffffffff00000000UL;

    enable();
    CHECK(is_enabled());

    disable();
    CHECK(is_disabled());

    enable_if_allowed();
    CHECK(is_enabled_if_exists());

    disable_if_allowed();
    CHECK(is_disabled_if_exists());
}

TEST_CASE("vmcs_pin_based_vm_execution_controls_process_posted_interrupts")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::pin_based_vm_execution_controls::process_posted_interrupts;

    g_msrs[msrs::ia32_vmx_true_pinbased_ctls::addr] = 0xffffffff00000000UL;

    enable();
    CHECK(is_enabled());

    disable();
    CHECK(is_disabled());

    enable_if_allowed();
    CHECK(is_enabled_if_exists());

    disable_if_allowed();
    CHECK(is_disabled_if_exists());
}

TEST_CASE("vmcs_primary_processor_based_vm_execution_controls")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::primary_processor_based_vm_execution_controls::exists());

    vmcs::primary_processor_based_vm_execution_controls::set(1UL);
    CHECK(vmcs::primary_processor_based_vm_execution_controls::get() == 1UL);

    vmcs::primary_processor_based_vm_execution_controls::set_if_exists(2UL);
    CHECK(vmcs::primary_processor_based_vm_execution_controls::get_if_exists() == 2UL);
}

TEST_CASE("vmcs_primary_processor_based_vm_execution_controls_interrupt_window_exiting")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::primary_processor_based_vm_execution_controls::interrupt_window_exiting;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL;

    enable();
    CHECK(is_enabled());

    disable();
    CHECK(is_disabled());

    enable_if_allowed();
    CHECK(is_enabled_if_exists());

    disable_if_allowed();
    CHECK(is_disabled_if_exists());
}

TEST_CASE("vmcs_primary_processor_based_vm_execution_controls_use_tsc_offsetting")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::primary_processor_based_vm_execution_controls::use_tsc_offsetting;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL;

    enable();
    CHECK(is_enabled());

    disable();
    CHECK(is_disabled());

    enable_if_allowed();
    CHECK(is_enabled_if_exists());

    disable_if_allowed();
    CHECK(is_disabled_if_exists());
}

TEST_CASE("vmcs_primary_processor_based_vm_execution_controls_hlt_exiting")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::primary_processor_based_vm_execution_controls::hlt_exiting;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL;

    enable();
    CHECK(is_enabled());

    disable();
    CHECK(is_disabled());

    enable_if_allowed();
    CHECK(is_enabled_if_exists());

    disable_if_allowed();
    CHECK(is_disabled_if_exists());
}

TEST_CASE("vmcs_primary_processor_based_vm_execution_controls_invlpg_exiting")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::primary_processor_based_vm_execution_controls::invlpg_exiting;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL;

    enable();
    CHECK(is_enabled());

    disable();
    CHECK(is_disabled());

    enable_if_allowed();
    CHECK(is_enabled_if_exists());

    disable_if_allowed();
    CHECK(is_disabled_if_exists());
}

TEST_CASE("vmcs_primary_processor_based_vm_execution_controls_mwait_exiting")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::primary_processor_based_vm_execution_controls::mwait_exiting;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL;

    enable();
    CHECK(is_enabled());

    disable();
    CHECK(is_disabled());

    enable_if_allowed();
    CHECK(is_enabled_if_exists());

    disable_if_allowed();
    CHECK(is_disabled_if_exists());
}

TEST_CASE("vmcs_primary_processor_based_vm_execution_controls_rdpmc_exiting")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::primary_processor_based_vm_execution_controls::rdpmc_exiting;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL;

    enable();
    CHECK(is_enabled());

    disable();
    CHECK(is_disabled());

    enable_if_allowed();
    CHECK(is_enabled_if_exists());

    disable_if_allowed();
    CHECK(is_disabled_if_exists());
}

TEST_CASE("vmcs_primary_processor_based_vm_execution_controls_rdtsc_exiting")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::primary_processor_based_vm_execution_controls::rdtsc_exiting;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL;

    enable();
    CHECK(is_enabled());

    disable();
    CHECK(is_disabled());

    enable_if_allowed();
    CHECK(is_enabled_if_exists());

    disable_if_allowed();
    CHECK(is_disabled_if_exists());
}

TEST_CASE("vmcs_primary_processor_based_vm_execution_controls_cr3_load_exiting")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::primary_processor_based_vm_execution_controls::cr3_load_exiting;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL;

    enable();
    CHECK(is_enabled());

    disable();
    CHECK(is_disabled());

    enable_if_allowed();
    CHECK(is_enabled_if_exists());

    disable_if_allowed();
    CHECK(is_disabled_if_exists());
}

TEST_CASE("vmcs_primary_processor_based_vm_execution_controls_cr3_store_exiting")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::primary_processor_based_vm_execution_controls::cr3_store_exiting;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL;

    enable();
    CHECK(is_enabled());

    disable();
    CHECK(is_disabled());

    enable_if_allowed();
    CHECK(is_enabled_if_exists());

    disable_if_allowed();
    CHECK(is_disabled_if_exists());
}

TEST_CASE("vmcs_primary_processor_based_vm_execution_controls_cr8_load_exiting")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::primary_processor_based_vm_execution_controls::cr8_load_exiting;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL;

    enable();
    CHECK(is_enabled());

    disable();
    CHECK(is_disabled());

    enable_if_allowed();
    CHECK(is_enabled_if_exists());

    disable_if_allowed();
    CHECK(is_disabled_if_exists());
}

TEST_CASE("vmcs_primary_processor_based_vm_execution_controls_cr8_store_exiting")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::primary_processor_based_vm_execution_controls::cr8_store_exiting;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL;

    enable();
    CHECK(is_enabled());

    disable();
    CHECK(is_disabled());

    enable_if_allowed();
    CHECK(is_enabled_if_exists());

    disable_if_allowed();
    CHECK(is_disabled_if_exists());
}

TEST_CASE("vmcs_primary_processor_based_vm_execution_controls_use_tpr_shadow")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::primary_processor_based_vm_execution_controls::use_tpr_shadow;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL;

    enable();
    CHECK(is_enabled());

    disable();
    CHECK(is_disabled());

    enable_if_allowed();
    CHECK(is_enabled_if_exists());

    disable_if_allowed();
    CHECK(is_disabled_if_exists());
}

TEST_CASE("vmcs_primary_processor_based_vm_execution_controls_nmi_window_exiting")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::primary_processor_based_vm_execution_controls::nmi_window_exiting;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL;

    enable();
    CHECK(is_enabled());

    disable();
    CHECK(is_disabled());

    enable_if_allowed();
    CHECK(is_enabled_if_exists());

    disable_if_allowed();
    CHECK(is_disabled_if_exists());
}

TEST_CASE("vmcs_primary_processor_based_vm_execution_controls_mov_dr_exiting")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::primary_processor_based_vm_execution_controls::mov_dr_exiting;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL;

    enable();
    CHECK(is_enabled());

    disable();
    CHECK(is_disabled());

    enable_if_allowed();
    CHECK(is_enabled_if_exists());

    disable_if_allowed();
    CHECK(is_disabled_if_exists());
}

TEST_CASE("vmcs_primary_processor_based_vm_execution_controls_unconditional_io_exiting")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::primary_processor_based_vm_execution_controls::unconditional_io_exiting;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL;

    enable();
    CHECK(is_enabled());

    disable();
    CHECK(is_disabled());

    enable_if_allowed();
    CHECK(is_enabled_if_exists());

    disable_if_allowed();
    CHECK(is_disabled_if_exists());
}

TEST_CASE("vmcs_primary_processor_based_vm_execution_controls_use_io_bitmaps")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::primary_processor_based_vm_execution_controls::use_io_bitmaps;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL;

    enable();
    CHECK(is_enabled());

    disable();
    CHECK(is_disabled());

    enable_if_allowed();
    CHECK(is_enabled_if_exists());

    disable_if_allowed();
    CHECK(is_disabled_if_exists());
}

TEST_CASE("vmcs_primary_processor_based_vm_execution_controls_monitor_trap_flag")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::primary_processor_based_vm_execution_controls::monitor_trap_flag;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL;

    enable();
    CHECK(is_enabled());

    disable();
    CHECK(is_disabled());

    enable_if_allowed();
    CHECK(is_enabled_if_exists());

    disable_if_allowed();
    CHECK(is_disabled_if_exists());
}

TEST_CASE("vmcs_primary_processor_based_vm_execution_controls_use_msr_bitmap")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::primary_processor_based_vm_execution_controls::use_msr_bitmap;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL;

    enable();
    CHECK(is_enabled());

    disable();
    CHECK(is_disabled());

    enable_if_allowed();
    CHECK(is_enabled_if_exists());

    disable_if_allowed();
    CHECK(is_disabled_if_exists());
}

TEST_CASE("vmcs_primary_processor_based_vm_execution_controls_monitor_exiting")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::primary_processor_based_vm_execution_controls::monitor_exiting;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL;

    enable();
    CHECK(is_enabled());

    disable();
    CHECK(is_disabled());

    enable_if_allowed();
    CHECK(is_enabled_if_exists());

    disable_if_allowed();
    CHECK(is_disabled_if_exists());
}

TEST_CASE("vmcs_primary_processor_based_vm_execution_controls_pause_exiting")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::primary_processor_based_vm_execution_controls::pause_exiting;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL;

    enable();
    CHECK(is_enabled());

    disable();
    CHECK(is_disabled());

    enable_if_allowed();
    CHECK(is_enabled_if_exists());

    disable_if_allowed();
    CHECK(is_disabled_if_exists());
}

TEST_CASE("vmcs_primary_processor_based_vm_execution_controls_activate_secondary_controls")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::primary_processor_based_vm_execution_controls::activate_secondary_controls;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL;

    enable();
    CHECK(is_enabled());

    disable();
    CHECK(is_disabled());

    enable_if_allowed();
    CHECK(is_enabled_if_exists());

    disable_if_allowed();
    CHECK(is_disabled_if_exists());
}

TEST_CASE("vmcs_exception_bitmap")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::exception_bitmap::exists());

    vmcs::exception_bitmap::set(1UL);
    CHECK(vmcs::exception_bitmap::get() == 1UL);

    vmcs::exception_bitmap::set_if_exists(2UL);
    CHECK(vmcs::exception_bitmap::get_if_exists() == 2UL);
}

TEST_CASE("vmcs_page_fault_error_code_mask")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::page_fault_error_code_mask::exists());

    vmcs::page_fault_error_code_mask::set(1UL);
    CHECK(vmcs::page_fault_error_code_mask::get() == 1UL);

    vmcs::page_fault_error_code_mask::set_if_exists(2UL);
    CHECK(vmcs::page_fault_error_code_mask::get_if_exists() == 2UL);
}

TEST_CASE("vmcs_page_fault_error_code_match")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::page_fault_error_code_match::exists());

    vmcs::page_fault_error_code_match::set(1UL);
    CHECK(vmcs::page_fault_error_code_match::get() == 1UL);

    vmcs::page_fault_error_code_match::set_if_exists(2UL);
    CHECK(vmcs::page_fault_error_code_match::get_if_exists() == 2UL);
}

TEST_CASE("vmcs_cr3_target_count")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::cr3_target_count::exists());

    vmcs::cr3_target_count::set(1UL);
    CHECK(vmcs::cr3_target_count::get() == 1UL);

    vmcs::cr3_target_count::set_if_exists(2UL);
    CHECK(vmcs::cr3_target_count::get_if_exists() == 2UL);
}

TEST_CASE("vmcs_vm_exit_controls")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::vm_exit_controls::exists());

    vmcs::vm_exit_controls::set(1UL);
    CHECK(vmcs::vm_exit_controls::get() == 1UL);

    vmcs::vm_exit_controls::set_if_exists(2UL);
    CHECK(vmcs::vm_exit_controls::get_if_exists() == 2UL);
}

TEST_CASE("vmcs_vm_exit_controls_save_debug_controls")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_controls::save_debug_controls;

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] = 0xffffffff00000000UL;

    enable();
    CHECK(is_enabled());

    disable();
    CHECK(is_disabled());

    enable_if_allowed();
    CHECK(is_enabled_if_exists());

    disable_if_allowed();
    CHECK(is_disabled_if_exists());
}

TEST_CASE("vmcs_vm_exit_controls_host_address_space_size")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_controls::host_address_space_size;

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] = 0xffffffff00000000UL;

    enable();
    CHECK(is_enabled());

    disable();
    CHECK(is_disabled());

    enable_if_allowed();
    CHECK(is_enabled_if_exists());

    disable_if_allowed();
    CHECK(is_disabled_if_exists());
}

TEST_CASE("vmcs_vm_exit_controls_load_ia32_perf_global_ctrl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_controls::load_ia32_perf_global_ctrl;

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] = 0xffffffff00000000UL;

    enable();
    CHECK(is_enabled());

    disable();
    CHECK(is_disabled());

    enable_if_allowed();
    CHECK(is_enabled_if_exists());

    disable_if_allowed();
    CHECK(is_disabled_if_exists());
}

TEST_CASE("vmcs_vm_exit_controls_acknowledge_interrupt_on_exit")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_controls::acknowledge_interrupt_on_exit;

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] = 0xffffffff00000000UL;

    enable();
    CHECK(is_enabled());

    disable();
    CHECK(is_disabled());

    enable_if_allowed();
    CHECK(is_enabled_if_exists());

    disable_if_allowed();
    CHECK(is_disabled_if_exists());
}

TEST_CASE("vmcs_vm_exit_controls_save_ia32_pat")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_controls::save_ia32_pat;

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] = 0xffffffff00000000UL;

    enable();
    CHECK(is_enabled());

    disable();
    CHECK(is_disabled());

    enable_if_allowed();
    CHECK(is_enabled_if_exists());

    disable_if_allowed();
    CHECK(is_disabled_if_exists());
}

TEST_CASE("vmcs_vm_exit_controls_load_ia32_pat")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_controls::load_ia32_pat;

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] = 0xffffffff00000000UL;

    enable();
    CHECK(is_enabled());

    disable();
    CHECK(is_disabled());

    enable_if_allowed();
    CHECK(is_enabled_if_exists());

    disable_if_allowed();
    CHECK(is_disabled_if_exists());
}

TEST_CASE("vmcs_vm_exit_controls_save_ia32_efer")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_controls::save_ia32_efer;

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] = 0xffffffff00000000UL;

    enable();
    CHECK(is_enabled());

    disable();
    CHECK(is_disabled());

    enable_if_allowed();
    CHECK(is_enabled_if_exists());

    disable_if_allowed();
    CHECK(is_disabled_if_exists());
}

TEST_CASE("vmcs_vm_exit_controls_load_ia32_efer")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_controls::load_ia32_efer;

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] = 0xffffffff00000000UL;

    enable();
    CHECK(is_enabled());

    disable();
    CHECK(is_disabled());

    enable_if_allowed();
    CHECK(is_enabled_if_exists());

    disable_if_allowed();
    CHECK(is_disabled_if_exists());
}

TEST_CASE("vmcs_vm_exit_controls_save_vmx_preemption_timer_value")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_controls::save_vmx_preemption_timer_value;

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] = 0xffffffff00000000UL;

    enable();
    CHECK(is_enabled());

    disable();
    CHECK(is_disabled());

    enable_if_allowed();
    CHECK(is_enabled_if_exists());

    disable_if_allowed();
    CHECK(is_disabled_if_exists());
}

TEST_CASE("vmcs_vm_exit_controls_clear_ia32_bndcfgs")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_controls::clear_ia32_bndcfgs;

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] = 0xffffffff00000000UL;

    enable();
    CHECK(is_enabled());

    disable();
    CHECK(is_disabled());

    enable_if_allowed();
    CHECK(is_enabled_if_exists());

    disable_if_allowed();
    CHECK(is_disabled_if_exists());
}

TEST_CASE("vmcs_vm_exit_controls_pt_conceal_vm_exits")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_controls::pt_conceal_vm_exits;

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] = 0xffffffff00000000UL;

    enable();
    CHECK(is_enabled());

    disable();
    CHECK(is_disabled());

    enable_if_allowed();
    CHECK(is_enabled_if_exists());

    disable_if_allowed();
    CHECK(is_disabled_if_exists());
}

TEST_CASE("vmcs_vm_exit_msr_store_count")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::vm_exit_msr_store_count::exists());

    vmcs::vm_exit_msr_store_count::set(1UL);
    CHECK(vmcs::vm_exit_msr_store_count::get() == 1UL);

    vmcs::vm_exit_msr_store_count::set_if_exists(2UL);
    CHECK(vmcs::vm_exit_msr_store_count::get_if_exists() == 2UL);
}

TEST_CASE("vmcs_vm_exit_msr_load_count")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::vm_exit_msr_load_count::exists());

    vmcs::vm_exit_msr_load_count::set(1UL);
    CHECK(vmcs::vm_exit_msr_load_count::get() == 1UL);

    vmcs::vm_exit_msr_load_count::set_if_exists(2UL);
    CHECK(vmcs::vm_exit_msr_load_count::get_if_exists() == 2UL);
}

TEST_CASE("vmcs_vm_entry_controls")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::vm_entry_controls::exists());

    vmcs::vm_entry_controls::set(1UL);
    CHECK(vmcs::vm_entry_controls::get() == 1UL);

    vmcs::vm_entry_controls::set_if_exists(2UL);
    CHECK(vmcs::vm_entry_controls::get_if_exists() == 2UL);
}

TEST_CASE("vmcs_vm_entry_controls_load_debug_controls")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_entry_controls::load_debug_controls;

    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] = 0xffffffff00000000UL;

    enable();
    CHECK(is_enabled());

    disable();
    CHECK(is_disabled());

    enable_if_allowed();
    CHECK(is_enabled_if_exists());

    disable_if_allowed();
    CHECK(is_disabled_if_exists());
}

TEST_CASE("vmcs_vm_entry_controls_ia_32e_mode_guest")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_entry_controls::ia_32e_mode_guest;

    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] = 0xffffffff00000000UL;

    enable();
    CHECK(is_enabled());

    disable();
    CHECK(is_disabled());

    enable_if_allowed();
    CHECK(is_enabled_if_exists());

    disable_if_allowed();
    CHECK(is_disabled_if_exists());
}

TEST_CASE("vmcs_vm_entry_controls_entry_to_smm")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_entry_controls::entry_to_smm;

    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] = 0xffffffff00000000UL;

    enable();
    CHECK(is_enabled());

    disable();
    CHECK(is_disabled());

    enable_if_allowed();
    CHECK(is_enabled_if_exists());

    disable_if_allowed();
    CHECK(is_disabled_if_exists());
}

TEST_CASE("vmcs_vm_entry_controls_deactivate_dual_monitor_treatment")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_entry_controls::deactivate_dual_monitor_treatment;

    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] = 0xffffffff00000000UL;

    enable();
    CHECK(is_enabled());

    disable();
    CHECK(is_disabled());

    enable_if_allowed();
    CHECK(is_enabled_if_exists());

    disable_if_allowed();
    CHECK(is_disabled_if_exists());
}

TEST_CASE("vmcs_vm_entry_controls_load_ia32_perf_global_ctrl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_entry_controls::load_ia32_perf_global_ctrl;

    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] = 0xffffffff00000000UL;

    enable();
    CHECK(is_enabled());

    disable();
    CHECK(is_disabled());

    enable_if_allowed();
    CHECK(is_enabled_if_exists());

    disable_if_allowed();
    CHECK(is_disabled_if_exists());
}

TEST_CASE("vmcs_vm_entry_controls_load_ia32_pat")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_entry_controls::load_ia32_pat;

    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] = 0xffffffff00000000UL;

    enable();
    CHECK(is_enabled());

    disable();
    CHECK(is_disabled());

    enable_if_allowed();
    CHECK(is_enabled_if_exists());

    disable_if_allowed();
    CHECK(is_disabled_if_exists());
}

TEST_CASE("vmcs_vm_entry_controls_load_ia32_efer")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_entry_controls::load_ia32_efer;

    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] = 0xffffffff00000000UL;

    enable();
    CHECK(is_enabled());

    disable();
    CHECK(is_disabled());

    enable_if_allowed();
    CHECK(is_enabled_if_exists());

    disable_if_allowed();
    CHECK(is_disabled_if_exists());
}

TEST_CASE("vmcs_vm_entry_controls_load_ia32_bndcfgs")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_entry_controls::load_ia32_bndcfgs;

    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] = 0xffffffff00000000UL;

    enable();
    CHECK(is_enabled());

    disable();
    CHECK(is_disabled());

    enable_if_allowed();
    CHECK(is_enabled_if_exists());

    disable_if_allowed();
    CHECK(is_disabled_if_exists());
}

TEST_CASE("vmcs_vm_entry_controls_pt_conceal_vm_entries")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_entry_controls::pt_conceal_vm_entries;

    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] = 0xffffffff00000000UL;

    enable();
    CHECK(is_enabled());

    disable();
    CHECK(is_disabled());

    enable_if_allowed();
    CHECK(is_enabled_if_exists());

    disable_if_allowed();
    CHECK(is_disabled_if_exists());
}

TEST_CASE("vmcs_vm_entry_msr_load_count")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::vm_entry_msr_load_count::exists());

    vmcs::vm_entry_msr_load_count::set(1UL);
    CHECK(vmcs::vm_entry_msr_load_count::get() == 1UL);

    vmcs::vm_entry_msr_load_count::set_if_exists(2UL);
    CHECK(vmcs::vm_entry_msr_load_count::get_if_exists() == 2UL);
}

TEST_CASE("vmcs_vm_entry_interruption_information_field")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::vm_entry_interruption_information_field::exists());

    vmcs::vm_entry_interruption_information_field::set(1UL);
    CHECK(vmcs::vm_entry_interruption_information_field::get() == 1UL);

    vmcs::vm_entry_interruption_information_field::set_if_exists(2UL);
    CHECK(vmcs::vm_entry_interruption_information_field::get_if_exists() == 2UL);
}

TEST_CASE("vmcs_vm_entry_interruption_information_field_vector")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_entry_interruption_information_field;

    set(0x101UL);
    CHECK(vector::get() == 0x1UL);
    CHECK(get() == 0x101UL);

    set_if_exists(0x222UL);
    CHECK(vector::get_if_exists() == 0x22UL);
    CHECK(get_if_exists() == 0x222UL);
}

TEST_CASE("vmcs_vm_entry_interruption_information_field_type")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_entry_interruption_information_field;

    set(0xf701UL);
    interruption_type::set(0x701UL);
    CHECK(interruption_type::get() == interruption_type::reserved);
    CHECK(get() == 0xf101UL);

    interruption_type::set_if_exists(0x303UL);
    CHECK(interruption_type::get_if_exists() == interruption_type::hardware_exception);
    CHECK(get() == 0xf301UL);
}

TEST_CASE("vmcs_vm_entry_interruption_information_field_deliver_error_code_bit")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_entry_interruption_information_field;

    set(0xffff0000UL);
    deliver_error_code_bit::enable();
    CHECK(deliver_error_code_bit::is_enabled());
    CHECK(get() == (0xffff0000UL | deliver_error_code_bit::mask));

    deliver_error_code_bit::disable();
    CHECK(deliver_error_code_bit::is_disabled());
    CHECK(get() == 0xffff0000UL);

    deliver_error_code_bit::enable_if_exists();
    CHECK(deliver_error_code_bit::is_enabled_if_exists());
    CHECK(get() == (0xffff0000UL | deliver_error_code_bit::mask));

    deliver_error_code_bit::disable_if_exists();
    CHECK(deliver_error_code_bit::is_disabled_if_exists());
    CHECK(get() == 0xffff0000UL);
}

TEST_CASE("vmcs_vm_entry_interruption_information_field_reserved")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_entry_interruption_information_field;

    set(0x701UL);
    reserved::set(0xbc02UL);
    CHECK(reserved::get() == 0xbc02UL);
    CHECK(get() == 0xbc02701UL);

    reserved::set_if_exists(0x1UL);
    CHECK(reserved::get_if_exists() == 0x1UL);
    CHECK(get() == 0x01701UL);
}

TEST_CASE("vmcs_vm_entry_interruption_information_field_valid_bit")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_entry_interruption_information_field;

    set(0x0fff0000UL);
    valid_bit::enable();
    CHECK(valid_bit::is_enabled());
    CHECK(get() == (0x0fff0000UL | valid_bit::mask));

    valid_bit::disable();
    CHECK(valid_bit::is_disabled());
    CHECK(get() == 0x0fff0000UL);

    valid_bit::enable_if_exists();
    CHECK(valid_bit::is_enabled_if_exists());
    CHECK(get() == (0x0fff0000UL | valid_bit::mask));

    valid_bit::disable_if_exists();
    CHECK(valid_bit::is_disabled_if_exists());
    CHECK(get() == 0x0fff0000UL);
}

TEST_CASE("vmcs_vm_entry_exception_error_code")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::vm_entry_exception_error_code::exists());

    vmcs::vm_entry_exception_error_code::set(1UL);
    CHECK(vmcs::vm_entry_exception_error_code::get() == 1UL);

    vmcs::vm_entry_exception_error_code::set_if_exists(2UL);
    CHECK(vmcs::vm_entry_exception_error_code::get_if_exists() == 2UL);
}

TEST_CASE("vmcs_vm_entry_instruction_length")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::vm_entry_instruction_length::exists());

    vmcs::vm_entry_instruction_length::set(1UL);
    CHECK(vmcs::vm_entry_instruction_length::get() == 1UL);

    vmcs::vm_entry_instruction_length::set_if_exists(2UL);
    CHECK(vmcs::vm_entry_instruction_length::get_if_exists() == 2UL);
}

TEST_CASE("vmcs_tpr_threshold")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace msrs::ia32_vmx_true_procbased_ctls;

    g_msrs[addr] = ~(use_tpr_shadow::mask << 32);
    CHECK_FALSE(vmcs::tpr_threshold::exists());

    g_msrs[addr] = use_tpr_shadow::mask << 32;
    CHECK(vmcs::tpr_threshold::exists());

    vmcs::tpr_threshold::set(0xF03UL);
    CHECK(vmcs::tpr_threshold::get() == 0xF03UL);

    vmcs::tpr_threshold::set_if_exists(0x333UL);
    CHECK(vmcs::tpr_threshold::get_if_exists() == 0x333UL);
}

TEST_CASE("vmcs_secondary_processor_based_vm_execution_controls")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace msrs::ia32_vmx_true_procbased_ctls;

    g_msrs[addr] = ~(activate_secondary_controls::mask << 32);
    CHECK_FALSE(vmcs::secondary_processor_based_vm_execution_controls::exists());

    g_msrs[addr] = activate_secondary_controls::mask << 32;
    CHECK(vmcs::secondary_processor_based_vm_execution_controls::exists());

    vmcs::secondary_processor_based_vm_execution_controls::set(1UL);
    CHECK(vmcs::secondary_processor_based_vm_execution_controls::get() == 1UL);

    vmcs::secondary_processor_based_vm_execution_controls::set_if_exists(2UL);
    CHECK(vmcs::secondary_processor_based_vm_execution_controls::get_if_exists() == 2UL);
}

TEST_CASE("vmcs_secondary_processor_based_vm_execution_controls_virtualize_apic_accesses")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::secondary_processor_based_vm_execution_controls::virtualize_apic_accesses;
    using namespace msrs::ia32_vmx_true_procbased_ctls;

    g_msrs[addr] = activate_secondary_controls::mask << 32;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0xffffffff00000000UL;

    enable();
    CHECK(is_enabled());

    disable();
    CHECK(is_disabled());

    enable_if_allowed();
    CHECK(is_enabled_if_exists());

    disable_if_allowed();
    CHECK(is_disabled_if_exists());
}

TEST_CASE("vmcs_secondary_processor_based_vm_execution_controls_enable_ept")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::secondary_processor_based_vm_execution_controls::enable_ept;
    using namespace msrs::ia32_vmx_true_procbased_ctls;

    g_msrs[addr] = activate_secondary_controls::mask << 32;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0xffffffff00000000UL;

    enable();
    CHECK(is_enabled());

    disable();
    CHECK(is_disabled());

    enable_if_allowed();
    CHECK(is_enabled_if_exists());

    disable_if_allowed();
    CHECK(is_disabled_if_exists());
}

TEST_CASE("vmcs_secondary_processor_based_vm_execution_controls_descriptor_table_exiting")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::secondary_processor_based_vm_execution_controls::descriptor_table_exiting;
    using namespace msrs::ia32_vmx_true_procbased_ctls;

    g_msrs[addr] = activate_secondary_controls::mask << 32;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0xffffffff00000000UL;

    enable();
    CHECK(is_enabled());

    disable();
    CHECK(is_disabled());

    enable_if_allowed();
    CHECK(is_enabled_if_exists());

    disable_if_allowed();
    CHECK(is_disabled_if_exists());
}

TEST_CASE("vmcs_secondary_processor_based_vm_execution_controls_enable_rdtscp")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::secondary_processor_based_vm_execution_controls::enable_rdtscp;
    using namespace msrs::ia32_vmx_true_procbased_ctls;

    g_msrs[addr] = activate_secondary_controls::mask << 32;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0xffffffff00000000UL;

    enable();
    CHECK(is_enabled());

    disable();
    CHECK(is_disabled());

    enable_if_allowed();
    CHECK(is_enabled_if_exists());

    disable_if_allowed();
    CHECK(is_disabled_if_exists());
}

TEST_CASE("vmcs_secondary_processor_based_vm_execution_controls_virtualize_x2apic_mode")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::secondary_processor_based_vm_execution_controls::virtualize_x2apic_mode;
    using namespace msrs::ia32_vmx_true_procbased_ctls;

    g_msrs[addr] = activate_secondary_controls::mask << 32;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0xffffffff00000000UL;

    enable();
    CHECK(is_enabled());

    disable();
    CHECK(is_disabled());

    enable_if_allowed();
    CHECK(is_enabled_if_exists());

    disable_if_allowed();
    CHECK(is_disabled_if_exists());
}

TEST_CASE("vmcs_secondary_processor_based_vm_execution_controls_enable_vpid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::secondary_processor_based_vm_execution_controls::enable_vpid;
    using namespace msrs::ia32_vmx_true_procbased_ctls;

    g_msrs[addr] = activate_secondary_controls::mask << 32;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0xffffffff00000000UL;

    enable();
    CHECK(is_enabled());

    disable();
    CHECK(is_disabled());

    enable_if_allowed();
    CHECK(is_enabled_if_exists());

    disable_if_allowed();
    CHECK(is_disabled_if_exists());
}

TEST_CASE("vmcs_secondary_processor_based_vm_execution_controls_wbinvd_exiting")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::secondary_processor_based_vm_execution_controls::wbinvd_exiting;
    using namespace msrs::ia32_vmx_true_procbased_ctls;

    g_msrs[addr] = activate_secondary_controls::mask << 32;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0xffffffff00000000UL;

    enable();
    CHECK(is_enabled());

    disable();
    CHECK(is_disabled());

    enable_if_allowed();
    CHECK(is_enabled_if_exists());

    disable_if_allowed();
    CHECK(is_disabled_if_exists());
}

TEST_CASE("vmcs_secondary_processor_based_vm_execution_controls_unrestricted_guest")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::secondary_processor_based_vm_execution_controls::unrestricted_guest;
    using namespace msrs::ia32_vmx_true_procbased_ctls;

    g_msrs[addr] = activate_secondary_controls::mask << 32;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0xffffffff00000000UL;

    enable();
    CHECK(is_enabled());

    disable();
    CHECK(is_disabled());

    enable_if_allowed();
    CHECK(is_enabled_if_exists());

    disable_if_allowed();
    CHECK(is_disabled_if_exists());
}

TEST_CASE("vmcs_secondary_processor_based_vm_execution_controls_apic_register_virtualization")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::secondary_processor_based_vm_execution_controls::apic_register_virtualization;
    using namespace msrs::ia32_vmx_true_procbased_ctls;

    g_msrs[addr] = activate_secondary_controls::mask << 32;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0xffffffff00000000UL;

    enable();
    CHECK(is_enabled());

    disable();
    CHECK(is_disabled());

    enable_if_allowed();
    CHECK(is_enabled_if_exists());

    disable_if_allowed();
    CHECK(is_disabled_if_exists());
}

TEST_CASE("vmcs_secondary_processor_based_vm_execution_controls_virtual_interrupt_delivery")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::secondary_processor_based_vm_execution_controls::virtual_interrupt_delivery;
    using namespace msrs::ia32_vmx_true_procbased_ctls;

    g_msrs[addr] = activate_secondary_controls::mask << 32;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0xffffffff00000000UL;

    enable();
    CHECK(is_enabled());

    disable();
    CHECK(is_disabled());

    enable_if_allowed();
    CHECK(is_enabled_if_exists());

    disable_if_allowed();
    CHECK(is_disabled_if_exists());
}

TEST_CASE("vmcs_secondary_processor_based_vm_execution_controls_pause_loop_exiting")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::secondary_processor_based_vm_execution_controls::pause_loop_exiting;
    using namespace msrs::ia32_vmx_true_procbased_ctls;

    g_msrs[addr] = activate_secondary_controls::mask << 32;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0xffffffff00000000UL;

    enable();
    CHECK(is_enabled());

    disable();
    CHECK(is_disabled());

    enable_if_allowed();
    CHECK(is_enabled_if_exists());

    disable_if_allowed();
    CHECK(is_disabled_if_exists());
}

TEST_CASE("vmcs_secondary_processor_based_vm_execution_controls_rdrand_exiting")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::secondary_processor_based_vm_execution_controls::rdrand_exiting;
    using namespace msrs::ia32_vmx_true_procbased_ctls;

    g_msrs[addr] = activate_secondary_controls::mask << 32;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0xffffffff00000000UL;

    enable();
    CHECK(is_enabled());

    disable();
    CHECK(is_disabled());

    enable_if_allowed();
    CHECK(is_enabled_if_exists());

    disable_if_allowed();
    CHECK(is_disabled_if_exists());
}

TEST_CASE("vmcs_secondary_processor_based_vm_execution_controls_enable_invpcid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::secondary_processor_based_vm_execution_controls::enable_invpcid;
    using namespace msrs::ia32_vmx_true_procbased_ctls;

    g_msrs[addr] = activate_secondary_controls::mask << 32;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0xffffffff00000000UL;

    enable();
    CHECK(is_enabled());

    disable();
    CHECK(is_disabled());

    enable_if_allowed();
    CHECK(is_enabled_if_exists());

    disable_if_allowed();
    CHECK(is_disabled_if_exists());
}

TEST_CASE("vmcs_secondary_processor_based_vm_execution_controls_enable_vm_functions")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::secondary_processor_based_vm_execution_controls::enable_vm_functions;
    using namespace msrs::ia32_vmx_true_procbased_ctls;

    g_msrs[addr] = activate_secondary_controls::mask << 32;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0xffffffff00000000UL;

    enable();
    CHECK(is_enabled());

    disable();
    CHECK(is_disabled());

    enable_if_allowed();
    CHECK(is_enabled_if_exists());

    disable_if_allowed();
    CHECK(is_disabled_if_exists());
}

TEST_CASE("vmcs_secondary_processor_based_vm_execution_controls_vmcs_shadowing")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::secondary_processor_based_vm_execution_controls::vmcs_shadowing;
    using namespace msrs::ia32_vmx_true_procbased_ctls;

    g_msrs[addr] = activate_secondary_controls::mask << 32;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0xffffffff00000000UL;

    enable();
    CHECK(is_enabled());

    disable();
    CHECK(is_disabled());

    enable_if_allowed();
    CHECK(is_enabled_if_exists());

    disable_if_allowed();
    CHECK(is_disabled_if_exists());
}

TEST_CASE("vmcs_secondary_processor_based_vm_execution_controls_enable_encls_exiting")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::secondary_processor_based_vm_execution_controls::enable_encls_exiting;
    using namespace msrs::ia32_vmx_true_procbased_ctls;

    g_msrs[addr] = activate_secondary_controls::mask << 32;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0xffffffff00000000UL;

    enable();
    CHECK(is_enabled());

    disable();
    CHECK(is_disabled());

    enable_if_allowed();
    CHECK(is_enabled_if_exists());

    disable_if_allowed();
    CHECK(is_disabled_if_exists());
}

TEST_CASE("vmcs_secondary_processor_based_vm_execution_controls_rdseed_exiting")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::secondary_processor_based_vm_execution_controls::rdseed_exiting;
    using namespace msrs::ia32_vmx_true_procbased_ctls;

    g_msrs[addr] = activate_secondary_controls::mask << 32;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0xffffffff00000000UL;

    enable();
    CHECK(is_enabled());

    disable();
    CHECK(is_disabled());

    enable_if_allowed();
    CHECK(is_enabled_if_exists());

    disable_if_allowed();
    CHECK(is_disabled_if_exists());
}

TEST_CASE("vmcs_secondary_processor_based_vm_execution_controls_enable_pml")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::secondary_processor_based_vm_execution_controls::enable_pml;
    using namespace msrs::ia32_vmx_true_procbased_ctls;

    g_msrs[addr] = activate_secondary_controls::mask << 32;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0xffffffff00000000UL;

    enable();
    CHECK(is_enabled());

    disable();
    CHECK(is_disabled());

    enable_if_allowed();
    CHECK(is_enabled_if_exists());

    disable_if_allowed();
    CHECK(is_disabled_if_exists());
}

TEST_CASE("vmcs_secondary_processor_based_vm_execution_controls_ept_violation_ve")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::secondary_processor_based_vm_execution_controls::ept_violation_ve;
    using namespace msrs::ia32_vmx_true_procbased_ctls;

    g_msrs[addr] = activate_secondary_controls::mask << 32;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0xffffffff00000000UL;

    enable();
    CHECK(is_enabled());

    disable();
    CHECK(is_disabled());

    enable_if_allowed();
    CHECK(is_enabled_if_exists());

    disable_if_allowed();
    CHECK(is_disabled_if_exists());
}

TEST_CASE("vmcs_secondary_processor_based_vm_execution_controls_pt_conceal_vmx_nonroot_operation")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::secondary_processor_based_vm_execution_controls::pt_conceal_vmx_nonroot_operation;
    using namespace msrs::ia32_vmx_true_procbased_ctls;

    g_msrs[addr] = activate_secondary_controls::mask << 32;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0xffffffff00000000UL;

    enable();
    CHECK(is_enabled());

    disable();
    CHECK(is_disabled());

    enable_if_allowed();
    CHECK(is_enabled_if_exists());

    disable_if_allowed();
    CHECK(is_disabled_if_exists());
}

TEST_CASE("vmcs_secondary_processor_based_vm_execution_controls_enable_xsaves_xrstors")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::secondary_processor_based_vm_execution_controls::enable_xsaves_xrstors;
    using namespace msrs::ia32_vmx_true_procbased_ctls;

    g_msrs[addr] = activate_secondary_controls::mask << 32;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0xffffffff00000000UL;

    enable();
    CHECK(is_enabled());

    disable();
    CHECK(is_disabled());

    enable_if_allowed();
    CHECK(is_enabled_if_exists());

    disable_if_allowed();
    CHECK(is_disabled_if_exists());
}

TEST_CASE("vmcs_secondary_processor_based_vm_execution_controls_ept_mode_based_control")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::secondary_processor_based_vm_execution_controls::ept_mode_based_control;
    using namespace msrs::ia32_vmx_true_procbased_ctls;

    g_msrs[addr] = activate_secondary_controls::mask << 32;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0xffffffff00000000UL;

    enable();
    CHECK(is_enabled());

    disable();
    CHECK(is_disabled());

    enable_if_allowed();
    CHECK(is_enabled_if_exists());

    disable_if_allowed();
    CHECK(is_disabled_if_exists());
}

TEST_CASE("vmcs_secondary_processor_based_vm_execution_controls_use_tsc_scaling")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::secondary_processor_based_vm_execution_controls::use_tsc_scaling;
    using namespace msrs::ia32_vmx_true_procbased_ctls;

    g_msrs[addr] = activate_secondary_controls::mask << 32;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0xffffffff00000000UL;

    enable();
    CHECK(is_enabled());

    disable();
    CHECK(is_disabled());

    enable_if_allowed();
    CHECK(is_enabled_if_exists());

    disable_if_allowed();
    CHECK(is_disabled_if_exists());
}

TEST_CASE("vmcs_ple_gap")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace msrs::ia32_vmx_true_procbased_ctls;

    g_msrs[addr] = activate_secondary_controls::mask << 32;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] =
        msrs::ia32_vmx_procbased_ctls2::pause_loop_exiting::mask << 32;

    CHECK(vmcs::ple_gap::exists());

    vmcs::ple_gap::set(0x11UL);
    CHECK(vmcs::ple_gap::get() == 0x11UL);

    vmcs::ple_gap::set_if_exists(0xFFFUL);
    CHECK(vmcs::ple_gap::get_if_exists() == 0xFFFUL);

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0UL;
    CHECK_FALSE(vmcs::ple_gap::exists());
    CHECK_THROWS(vmcs::ple_gap::set(0x3UL));
    CHECK_THROWS(vmcs::ple_gap::get());
    CHECK_NOTHROW(vmcs::ple_gap::set_if_exists(0x3UL));
    CHECK_NOTHROW(vmcs::ple_gap::get_if_exists());

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] =
        msrs::ia32_vmx_procbased_ctls2::pause_loop_exiting::mask << 32;
    CHECK(vmcs::ple_gap::get() == 0xFFFUL);
}

TEST_CASE("vmcs_ple_window")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace msrs::ia32_vmx_true_procbased_ctls;

    g_msrs[addr] = activate_secondary_controls::mask << 32;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] =
        msrs::ia32_vmx_procbased_ctls2::pause_loop_exiting::mask << 32;

    CHECK(vmcs::ple_window::exists());

    vmcs::ple_window::set(0x11UL);
    CHECK(vmcs::ple_window::get() == 0x11UL);

    vmcs::ple_window::set_if_exists(0xFFFUL);
    CHECK(vmcs::ple_window::get_if_exists() == 0xFFFUL);

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0UL;
    CHECK_FALSE(vmcs::ple_window::exists());
    CHECK_THROWS(vmcs::ple_window::set(0x3UL));
    CHECK_THROWS(vmcs::ple_window::get());
    CHECK_NOTHROW(vmcs::ple_window::set_if_exists(0x3UL));
    CHECK_NOTHROW(vmcs::ple_window::get_if_exists());

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] =
        msrs::ia32_vmx_procbased_ctls2::pause_loop_exiting::mask << 32;
    CHECK(vmcs::ple_window::get() == 0xFFFUL);
}

#endif
