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

    using namespace vmcs::pin_based_vm_execution_controls;

    CHECK(exists());

    set(1UL);
    CHECK(get() == 1UL);

    set_if_exists(2UL);
    CHECK(get_if_exists() == 2UL);

    dump(0);
}

TEST_CASE("vmcs_pin_based_vm_execution_controls_external_interrupt_exiting")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::pin_based_vm_execution_controls;

    g_msrs[msrs::ia32_vmx_true_pinbased_ctls::addr] = 0xffffffff00000000UL;

    external_interrupt_exiting::set(true);
    CHECK(external_interrupt_exiting::is_enabled());

    external_interrupt_exiting::set(false);
    CHECK(external_interrupt_exiting::is_disabled());

    external_interrupt_exiting::set_if_allowed(true);
    CHECK(external_interrupt_exiting::is_enabled_if_exists());

    external_interrupt_exiting::set_if_allowed(false);
    CHECK(external_interrupt_exiting::is_disabled_if_exists());
}

TEST_CASE("vmcs_pin_based_vm_execution_controls_nmi_exiting")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::pin_based_vm_execution_controls;

    g_msrs[msrs::ia32_vmx_true_pinbased_ctls::addr] = 0xffffffff00000000UL;

    nmi_exiting::set(true);
    CHECK(nmi_exiting::is_enabled());

    nmi_exiting::set(false);
    CHECK(nmi_exiting::is_disabled());

    nmi_exiting::set_if_allowed(true);
    CHECK(nmi_exiting::is_enabled_if_exists());

    nmi_exiting::set_if_allowed(false);
    CHECK(nmi_exiting::is_disabled_if_exists());
}

TEST_CASE("vmcs_pin_based_vm_execution_controls_virtual_nmis")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::pin_based_vm_execution_controls;

    g_msrs[msrs::ia32_vmx_true_pinbased_ctls::addr] = 0xffffffff00000000UL;

    virtual_nmis::set(true);
    CHECK(virtual_nmis::is_enabled());

    virtual_nmis::set(false);
    CHECK(virtual_nmis::is_disabled());

    virtual_nmis::set_if_allowed(true);
    CHECK(virtual_nmis::is_enabled_if_exists());

    virtual_nmis::set_if_allowed(false);
    CHECK(virtual_nmis::is_disabled_if_exists());
}

TEST_CASE("vmcs_pin_based_vm_execution_controls_activate_vmx_preemption_timer")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::pin_based_vm_execution_controls;

    g_msrs[msrs::ia32_vmx_true_pinbased_ctls::addr] = 0xffffffff00000000UL;

    activate_vmx_preemption_timer::set(true);
    CHECK(activate_vmx_preemption_timer::is_enabled());

    activate_vmx_preemption_timer::set(false);
    CHECK(activate_vmx_preemption_timer::is_disabled());

    activate_vmx_preemption_timer::set_if_allowed(true);
    CHECK(activate_vmx_preemption_timer::is_enabled_if_exists());

    activate_vmx_preemption_timer::set_if_allowed(false);
    CHECK(activate_vmx_preemption_timer::is_disabled_if_exists());
}

TEST_CASE("vmcs_pin_based_vm_execution_controls_process_posted_interrupts")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::pin_based_vm_execution_controls;

    g_msrs[msrs::ia32_vmx_true_pinbased_ctls::addr] = 0xffffffff00000000UL;

    process_posted_interrupts::set(true);
    CHECK(process_posted_interrupts::is_enabled());

    process_posted_interrupts::set(false);
    CHECK(process_posted_interrupts::is_disabled());

    process_posted_interrupts::set_if_allowed(true);
    CHECK(process_posted_interrupts::is_enabled_if_exists());

    process_posted_interrupts::set_if_allowed(false);
    CHECK(process_posted_interrupts::is_disabled_if_exists());
}

TEST_CASE("vmcs_primary_processor_based_vm_execution_controls")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::primary_processor_based_vm_execution_controls;

    CHECK(exists());

    set(1UL);
    CHECK(get() == 1UL);

    set_if_exists(2UL);
    CHECK(get_if_exists() == 2UL);

    dump(0);
}

TEST_CASE("vmcs_primary_processor_based_vm_execution_controls_interrupt_window_exiting")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::primary_processor_based_vm_execution_controls;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL;

    interrupt_window_exiting::set(true);
    CHECK(interrupt_window_exiting::is_enabled());

    interrupt_window_exiting::set(false);
    CHECK(interrupt_window_exiting::is_disabled());

    interrupt_window_exiting::set_if_allowed(true);
    CHECK(interrupt_window_exiting::is_enabled_if_exists());

    interrupt_window_exiting::set_if_allowed(false);
    CHECK(interrupt_window_exiting::is_disabled_if_exists());
}

TEST_CASE("vmcs_primary_processor_based_vm_execution_controls_use_tsc_offsetting")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::primary_processor_based_vm_execution_controls;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL;

    use_tsc_offsetting::set(true);
    CHECK(use_tsc_offsetting::is_enabled());

    use_tsc_offsetting::set(false);
    CHECK(use_tsc_offsetting::is_disabled());

    use_tsc_offsetting::set_if_allowed(true);
    CHECK(use_tsc_offsetting::is_enabled_if_exists());

    use_tsc_offsetting::set_if_allowed(false);
    CHECK(use_tsc_offsetting::is_disabled_if_exists());
}

TEST_CASE("vmcs_primary_processor_based_vm_execution_controls_hlt_exiting")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::primary_processor_based_vm_execution_controls;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL;

    hlt_exiting::set(true);
    CHECK(hlt_exiting::is_enabled());

    hlt_exiting::set(false);
    CHECK(hlt_exiting::is_disabled());

    hlt_exiting::set_if_allowed(true);
    CHECK(hlt_exiting::is_enabled_if_exists());

    hlt_exiting::set_if_allowed(false);
    CHECK(hlt_exiting::is_disabled_if_exists());
}

TEST_CASE("vmcs_primary_processor_based_vm_execution_controls_invlpg_exiting")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::primary_processor_based_vm_execution_controls;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL;

    invlpg_exiting::set(true);
    CHECK(invlpg_exiting::is_enabled());

    invlpg_exiting::set(false);
    CHECK(invlpg_exiting::is_disabled());

    invlpg_exiting::set_if_allowed(true);
    CHECK(invlpg_exiting::is_enabled_if_exists());

    invlpg_exiting::set_if_allowed(false);
    CHECK(invlpg_exiting::is_disabled_if_exists());
}

TEST_CASE("vmcs_primary_processor_based_vm_execution_controls_mwait_exiting")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::primary_processor_based_vm_execution_controls;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL;

    mwait_exiting::set(true);
    CHECK(mwait_exiting::is_enabled());

    mwait_exiting::set(false);
    CHECK(mwait_exiting::is_disabled());

    mwait_exiting::set_if_allowed(true);
    CHECK(mwait_exiting::is_enabled_if_exists());

    mwait_exiting::set_if_allowed(false);
    CHECK(mwait_exiting::is_disabled_if_exists());
}

TEST_CASE("vmcs_primary_processor_based_vm_execution_controls_rdpmc_exiting")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::primary_processor_based_vm_execution_controls;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL;

    rdpmc_exiting::set(true);
    CHECK(rdpmc_exiting::is_enabled());

    rdpmc_exiting::set(false);
    CHECK(rdpmc_exiting::is_disabled());

    rdpmc_exiting::set_if_allowed(true);
    CHECK(rdpmc_exiting::is_enabled_if_exists());

    rdpmc_exiting::set_if_allowed(false);
    CHECK(rdpmc_exiting::is_disabled_if_exists());
}

TEST_CASE("vmcs_primary_processor_based_vm_execution_controls_rdtsc_exiting")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::primary_processor_based_vm_execution_controls;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL;

    rdtsc_exiting::set(true);
    CHECK(rdtsc_exiting::is_enabled());

    rdtsc_exiting::set(false);
    CHECK(rdtsc_exiting::is_disabled());

    rdtsc_exiting::set_if_allowed(true);
    CHECK(rdtsc_exiting::is_enabled_if_exists());

    rdtsc_exiting::set_if_allowed(false);
    CHECK(rdtsc_exiting::is_disabled_if_exists());
}

TEST_CASE("vmcs_primary_processor_based_vm_execution_controls_cr3_load_exiting")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::primary_processor_based_vm_execution_controls;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL;

    cr3_load_exiting::set(true);
    CHECK(cr3_load_exiting::is_enabled());

    cr3_load_exiting::set(false);
    CHECK(cr3_load_exiting::is_disabled());

    cr3_load_exiting::set_if_allowed(true);
    CHECK(cr3_load_exiting::is_enabled_if_exists());

    cr3_load_exiting::set_if_allowed(false);
    CHECK(cr3_load_exiting::is_disabled_if_exists());
}

TEST_CASE("vmcs_primary_processor_based_vm_execution_controls_cr3_store_exiting")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::primary_processor_based_vm_execution_controls;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL;

    cr3_store_exiting::set(true);
    CHECK(cr3_store_exiting::is_enabled());

    cr3_store_exiting::set(false);
    CHECK(cr3_store_exiting::is_disabled());

    cr3_store_exiting::set_if_allowed(true);
    CHECK(cr3_store_exiting::is_enabled_if_exists());

    cr3_store_exiting::set_if_allowed(false);
    CHECK(cr3_store_exiting::is_disabled_if_exists());
}

TEST_CASE("vmcs_primary_processor_based_vm_execution_controls_cr8_load_exiting")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::primary_processor_based_vm_execution_controls;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL;

    cr8_load_exiting::set(true);
    CHECK(cr8_load_exiting::is_enabled());

    cr8_load_exiting::set(false);
    CHECK(cr8_load_exiting::is_disabled());

    cr8_load_exiting::set_if_allowed(true);
    CHECK(cr8_load_exiting::is_enabled_if_exists());

    cr8_load_exiting::set_if_allowed(false);
    CHECK(cr8_load_exiting::is_disabled_if_exists());
}

TEST_CASE("vmcs_primary_processor_based_vm_execution_controls_cr8_store_exiting")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::primary_processor_based_vm_execution_controls;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL;

    cr8_store_exiting::set(true);
    CHECK(cr8_store_exiting::is_enabled());

    cr8_store_exiting::set(false);
    CHECK(cr8_store_exiting::is_disabled());

    cr8_store_exiting::set_if_allowed(true);
    CHECK(cr8_store_exiting::is_enabled_if_exists());

    cr8_store_exiting::set_if_allowed(false);
    CHECK(cr8_store_exiting::is_disabled_if_exists());
}

TEST_CASE("vmcs_primary_processor_based_vm_execution_controls_use_tpr_shadow")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::primary_processor_based_vm_execution_controls;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL;

    use_tpr_shadow::set(true);
    CHECK(use_tpr_shadow::is_enabled());

    use_tpr_shadow::set(false);
    CHECK(use_tpr_shadow::is_disabled());

    use_tpr_shadow::set_if_allowed(true);
    CHECK(use_tpr_shadow::is_enabled_if_exists());

    use_tpr_shadow::set_if_allowed(false);
    CHECK(use_tpr_shadow::is_disabled_if_exists());
}

TEST_CASE("vmcs_primary_processor_based_vm_execution_controls_nmi_window_exiting")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::primary_processor_based_vm_execution_controls;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL;

    nmi_window_exiting::set(true);
    CHECK(nmi_window_exiting::is_enabled());

    nmi_window_exiting::set(false);
    CHECK(nmi_window_exiting::is_disabled());

    nmi_window_exiting::set_if_allowed(true);
    CHECK(nmi_window_exiting::is_enabled_if_exists());

    nmi_window_exiting::set_if_allowed(false);
    CHECK(nmi_window_exiting::is_disabled_if_exists());
}

TEST_CASE("vmcs_primary_processor_based_vm_execution_controls_mov_dr_exiting")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::primary_processor_based_vm_execution_controls;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL;

    mov_dr_exiting::set(true);
    CHECK(mov_dr_exiting::is_enabled());

    mov_dr_exiting::set(false);
    CHECK(mov_dr_exiting::is_disabled());

    mov_dr_exiting::set_if_allowed(true);
    CHECK(mov_dr_exiting::is_enabled_if_exists());

    mov_dr_exiting::set_if_allowed(false);
    CHECK(mov_dr_exiting::is_disabled_if_exists());
}

TEST_CASE("vmcs_primary_processor_based_vm_execution_controls_unconditional_io_exiting")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::primary_processor_based_vm_execution_controls;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL;

    unconditional_io_exiting::set(true);
    CHECK(unconditional_io_exiting::is_enabled());

    unconditional_io_exiting::set(false);
    CHECK(unconditional_io_exiting::is_disabled());

    unconditional_io_exiting::set_if_allowed(true);
    CHECK(unconditional_io_exiting::is_enabled_if_exists());

    unconditional_io_exiting::set_if_allowed(false);
    CHECK(unconditional_io_exiting::is_disabled_if_exists());
}

TEST_CASE("vmcs_primary_processor_based_vm_execution_controls_use_io_bitmaps")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::primary_processor_based_vm_execution_controls;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL;

    use_io_bitmaps::set(true);
    CHECK(use_io_bitmaps::is_enabled());

    use_io_bitmaps::set(false);
    CHECK(use_io_bitmaps::is_disabled());

    use_io_bitmaps::set_if_allowed(true);
    CHECK(use_io_bitmaps::is_enabled_if_exists());

    use_io_bitmaps::set_if_allowed(false);
    CHECK(use_io_bitmaps::is_disabled_if_exists());
}

TEST_CASE("vmcs_primary_processor_based_vm_execution_controls_monitor_trap_flag")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::primary_processor_based_vm_execution_controls;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL;

    monitor_trap_flag::set(true);
    CHECK(monitor_trap_flag::is_enabled());

    monitor_trap_flag::set(false);
    CHECK(monitor_trap_flag::is_disabled());

    monitor_trap_flag::set_if_allowed(true);
    CHECK(monitor_trap_flag::is_enabled_if_exists());

    monitor_trap_flag::set_if_allowed(false);
    CHECK(monitor_trap_flag::is_disabled_if_exists());
}

TEST_CASE("vmcs_primary_processor_based_vm_execution_controls_use_msr_bitmap")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::primary_processor_based_vm_execution_controls;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL;

    use_msr_bitmap::set(true);
    CHECK(use_msr_bitmap::is_enabled());

    use_msr_bitmap::set(false);
    CHECK(use_msr_bitmap::is_disabled());

    use_msr_bitmap::set_if_allowed(true);
    CHECK(use_msr_bitmap::is_enabled_if_exists());

    use_msr_bitmap::set_if_allowed(false);
    CHECK(use_msr_bitmap::is_disabled_if_exists());
}

TEST_CASE("vmcs_primary_processor_based_vm_execution_controls_monitor_exiting")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::primary_processor_based_vm_execution_controls;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL;

    monitor_exiting::set(true);
    CHECK(monitor_exiting::is_enabled());

    monitor_exiting::set(false);
    CHECK(monitor_exiting::is_disabled());

    monitor_exiting::set_if_allowed(true);
    CHECK(monitor_exiting::is_enabled_if_exists());

    monitor_exiting::set_if_allowed(false);
    CHECK(monitor_exiting::is_disabled_if_exists());
}

TEST_CASE("vmcs_primary_processor_based_vm_execution_controls_pause_exiting")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::primary_processor_based_vm_execution_controls;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL;

    pause_exiting::set(true);
    CHECK(pause_exiting::is_enabled());

    pause_exiting::set(false);
    CHECK(pause_exiting::is_disabled());

    pause_exiting::set_if_allowed(true);
    CHECK(pause_exiting::is_enabled_if_exists());

    pause_exiting::set_if_allowed(false);
    CHECK(pause_exiting::is_disabled_if_exists());
}

TEST_CASE("vmcs_primary_processor_based_vm_execution_controls_activate_secondary_controls")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::primary_processor_based_vm_execution_controls;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL;

    activate_secondary_controls::set(true);
    CHECK(activate_secondary_controls::is_enabled());

    activate_secondary_controls::set(false);
    CHECK(activate_secondary_controls::is_disabled());

    activate_secondary_controls::set_if_allowed(true);
    CHECK(activate_secondary_controls::is_enabled_if_exists());

    activate_secondary_controls::set_if_allowed(false);
    CHECK(activate_secondary_controls::is_disabled_if_exists());
}

TEST_CASE("vmcs_exception_bitmap")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::exception_bitmap;

    CHECK(exists());

    set(1UL);
    CHECK(get() == 1UL);

    set_if_exists(2UL);
    CHECK(get_if_exists() == 2UL);

    dump(0);
}

TEST_CASE("vmcs_page_fault_error_code_mask")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::page_fault_error_code_mask;

    CHECK(exists());

    set(1UL);
    CHECK(get() == 1UL);

    set_if_exists(2UL);
    CHECK(get_if_exists() == 2UL);

    dump(0);
}

TEST_CASE("vmcs_page_fault_error_code_match")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::page_fault_error_code_match;

    CHECK(exists());

    set(1UL);
    CHECK(get() == 1UL);

    set_if_exists(2UL);
    CHECK(get_if_exists() == 2UL);

    dump(0);
}

TEST_CASE("vmcs_cr3_target_count")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::cr3_target_count;

    CHECK(exists());

    set(1UL);
    CHECK(get() == 1UL);

    set_if_exists(2UL);
    CHECK(get_if_exists() == 2UL);

    dump(0);
}

TEST_CASE("vmcs_vm_exit_controls")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_controls;

    CHECK(exists());

    set(1UL);
    CHECK(get() == 1UL);

    set_if_exists(2UL);
    CHECK(get_if_exists() == 2UL);

    dump(0);
}

TEST_CASE("vmcs_vm_exit_controls_save_debug_controls")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_controls;

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] = 0xffffffff00000000UL;

    save_debug_controls::set(true);
    CHECK(save_debug_controls::is_enabled());

    save_debug_controls::set(false);
    CHECK(save_debug_controls::is_disabled());

    save_debug_controls::set_if_allowed(true);
    CHECK(save_debug_controls::is_enabled_if_exists());

    save_debug_controls::set_if_allowed(false);
    CHECK(save_debug_controls::is_disabled_if_exists());
}

TEST_CASE("vmcs_vm_exit_controls_host_address_space_size")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_controls;

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] = 0xffffffff00000000UL;

    host_address_space_size::set(true);
    CHECK(host_address_space_size::is_enabled());

    host_address_space_size::set(false);
    CHECK(host_address_space_size::is_disabled());

    host_address_space_size::set_if_allowed(true);
    CHECK(host_address_space_size::is_enabled_if_exists());

    host_address_space_size::set_if_allowed(false);
    CHECK(host_address_space_size::is_disabled_if_exists());
}

TEST_CASE("vmcs_vm_exit_controls_load_ia32_perf_global_ctrl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_controls;

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] = 0xffffffff00000000UL;

    load_ia32_perf_global_ctrl::set(true);
    CHECK(load_ia32_perf_global_ctrl::is_enabled());

    load_ia32_perf_global_ctrl::set(false);
    CHECK(load_ia32_perf_global_ctrl::is_disabled());

    load_ia32_perf_global_ctrl::set_if_allowed(true);
    CHECK(load_ia32_perf_global_ctrl::is_enabled_if_exists());

    load_ia32_perf_global_ctrl::set_if_allowed(false);
    CHECK(load_ia32_perf_global_ctrl::is_disabled_if_exists());
}

TEST_CASE("vmcs_vm_exit_controls_acknowledge_interrupt_on_exit")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_controls;

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] = 0xffffffff00000000UL;

    acknowledge_interrupt_on_exit::set(true);
    CHECK(acknowledge_interrupt_on_exit::is_enabled());

    acknowledge_interrupt_on_exit::set(false);
    CHECK(acknowledge_interrupt_on_exit::is_disabled());

    acknowledge_interrupt_on_exit::set_if_allowed(true);
    CHECK(acknowledge_interrupt_on_exit::is_enabled_if_exists());

    acknowledge_interrupt_on_exit::set_if_allowed(false);
    CHECK(acknowledge_interrupt_on_exit::is_disabled_if_exists());
}

TEST_CASE("vmcs_vm_exit_controls_save_ia32_pat")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_controls;

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] = 0xffffffff00000000UL;

    save_ia32_pat::set(true);
    CHECK(save_ia32_pat::is_enabled());

    save_ia32_pat::set(false);
    CHECK(save_ia32_pat::is_disabled());

    save_ia32_pat::set_if_allowed(true);
    CHECK(save_ia32_pat::is_enabled_if_exists());

    save_ia32_pat::set_if_allowed(false);
    CHECK(save_ia32_pat::is_disabled_if_exists());
}

TEST_CASE("vmcs_vm_exit_controls_load_ia32_pat")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_controls;

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] = 0xffffffff00000000UL;

    load_ia32_pat::set(true);
    CHECK(load_ia32_pat::is_enabled());

    load_ia32_pat::set(false);
    CHECK(load_ia32_pat::is_disabled());

    load_ia32_pat::set_if_allowed(true);
    CHECK(load_ia32_pat::is_enabled_if_exists());

    load_ia32_pat::set_if_allowed(false);
    CHECK(load_ia32_pat::is_disabled_if_exists());
}

TEST_CASE("vmcs_vm_exit_controls_save_ia32_efer")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_controls;

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] = 0xffffffff00000000UL;

    save_ia32_efer::set(true);
    CHECK(save_ia32_efer::is_enabled());

    save_ia32_efer::set(false);
    CHECK(save_ia32_efer::is_disabled());

    save_ia32_efer::set_if_allowed(true);
    CHECK(save_ia32_efer::is_enabled_if_exists());

    save_ia32_efer::set_if_allowed(false);
    CHECK(save_ia32_efer::is_disabled_if_exists());
}

TEST_CASE("vmcs_vm_exit_controls_load_ia32_efer")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_controls;

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] = 0xffffffff00000000UL;

    load_ia32_efer::set(true);
    CHECK(load_ia32_efer::is_enabled());

    load_ia32_efer::set(false);
    CHECK(load_ia32_efer::is_disabled());

    load_ia32_efer::set_if_allowed(true);
    CHECK(load_ia32_efer::is_enabled_if_exists());

    load_ia32_efer::set_if_allowed(false);
    CHECK(load_ia32_efer::is_disabled_if_exists());
}

TEST_CASE("vmcs_vm_exit_controls_save_vmx_preemption_timer_value")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_controls;

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] = 0xffffffff00000000UL;

    save_vmx_preemption_timer_value::set(true);
    CHECK(save_vmx_preemption_timer_value::is_enabled());

    save_vmx_preemption_timer_value::set(false);
    CHECK(save_vmx_preemption_timer_value::is_disabled());

    save_vmx_preemption_timer_value::set_if_allowed(true);
    CHECK(save_vmx_preemption_timer_value::is_enabled_if_exists());

    save_vmx_preemption_timer_value::set_if_allowed(false);
    CHECK(save_vmx_preemption_timer_value::is_disabled_if_exists());
}

TEST_CASE("vmcs_vm_exit_controls_clear_ia32_bndcfgs")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_controls;

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] = 0xffffffff00000000UL;

    clear_ia32_bndcfgs::set(true);
    CHECK(clear_ia32_bndcfgs::is_enabled());

    clear_ia32_bndcfgs::set(false);
    CHECK(clear_ia32_bndcfgs::is_disabled());

    clear_ia32_bndcfgs::set_if_allowed(true);
    CHECK(clear_ia32_bndcfgs::is_enabled_if_exists());

    clear_ia32_bndcfgs::set_if_allowed(false);
    CHECK(clear_ia32_bndcfgs::is_disabled_if_exists());
}

TEST_CASE("vmcs_vm_exit_controls_pt_conceal_vm_exits")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_controls;

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0xffffffff00000000UL;

    pt_conceal_vm_exits::set(true);
    CHECK(pt_conceal_vm_exits::is_enabled());

    pt_conceal_vm_exits::set(false);
    CHECK(pt_conceal_vm_exits::is_disabled());

    pt_conceal_vm_exits::set_if_allowed(true);
    CHECK(pt_conceal_vm_exits::is_enabled_if_exists());

    pt_conceal_vm_exits::set_if_allowed(false);
    CHECK(pt_conceal_vm_exits::is_disabled_if_exists());
}

TEST_CASE("vmcs_vm_exit_msr_store_count")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_msr_store_count;

    CHECK(exists());

    set(1UL);
    CHECK(get() == 1UL);

    set_if_exists(2UL);
    CHECK(get_if_exists() == 2UL);

    dump(0);
}

TEST_CASE("vmcs_vm_exit_msr_load_count")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_msr_load_count;

    CHECK(exists());

    set(1UL);
    CHECK(get() == 1UL);

    set_if_exists(2UL);
    CHECK(get_if_exists() == 2UL);

    dump(0);
}

TEST_CASE("vmcs_vm_entry_controls")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_entry_controls;

    CHECK(exists());

    set(1UL);
    CHECK(get() == 1UL);

    set_if_exists(2UL);
    CHECK(get_if_exists() == 2UL);

    dump(0);
}

TEST_CASE("vmcs_vm_entry_controls_load_debug_controls")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_entry_controls;

    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] = 0xffffffff00000000UL;

    load_debug_controls::set(true);
    CHECK(load_debug_controls::is_enabled());

    load_debug_controls::set(false);
    CHECK(load_debug_controls::is_disabled());

    load_debug_controls::set_if_allowed(true);
    CHECK(load_debug_controls::is_enabled_if_exists());

    load_debug_controls::set_if_allowed(false);
    CHECK(load_debug_controls::is_disabled_if_exists());
}

TEST_CASE("vmcs_vm_entry_controls_ia_32e_mode_guest")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_entry_controls;

    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] = 0xffffffff00000000UL;

    ia_32e_mode_guest::set(true);
    CHECK(ia_32e_mode_guest::is_enabled());

    ia_32e_mode_guest::set(false);
    CHECK(ia_32e_mode_guest::is_disabled());

    ia_32e_mode_guest::set_if_allowed(true);
    CHECK(ia_32e_mode_guest::is_enabled_if_exists());

    ia_32e_mode_guest::set_if_allowed(false);
    CHECK(ia_32e_mode_guest::is_disabled_if_exists());
}

TEST_CASE("vmcs_vm_entry_controls_entry_to_smm")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_entry_controls;

    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] = 0xffffffff00000000UL;

    entry_to_smm::set(true);
    CHECK(entry_to_smm::is_enabled());

    entry_to_smm::set(false);
    CHECK(entry_to_smm::is_disabled());

    entry_to_smm::set_if_allowed(true);
    CHECK(entry_to_smm::is_enabled_if_exists());

    entry_to_smm::set_if_allowed(false);
    CHECK(entry_to_smm::is_disabled_if_exists());
}

TEST_CASE("vmcs_vm_entry_controls_deactivate_dual_monitor_treatment")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_entry_controls;

    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] = 0xffffffff00000000UL;

    deactivate_dual_monitor_treatment::set(true);
    CHECK(deactivate_dual_monitor_treatment::is_enabled());

    deactivate_dual_monitor_treatment::set(false);
    CHECK(deactivate_dual_monitor_treatment::is_disabled());

    deactivate_dual_monitor_treatment::set_if_allowed(true);
    CHECK(deactivate_dual_monitor_treatment::is_enabled_if_exists());

    deactivate_dual_monitor_treatment::set_if_allowed(false);
    CHECK(deactivate_dual_monitor_treatment::is_disabled_if_exists());
}

TEST_CASE("vmcs_vm_entry_controls_load_ia32_perf_global_ctrl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_entry_controls;

    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] = 0xffffffff00000000UL;

    load_ia32_perf_global_ctrl::set(true);
    CHECK(load_ia32_perf_global_ctrl::is_enabled());

    load_ia32_perf_global_ctrl::set(false);
    CHECK(load_ia32_perf_global_ctrl::is_disabled());

    load_ia32_perf_global_ctrl::set_if_allowed(true);
    CHECK(load_ia32_perf_global_ctrl::is_enabled_if_exists());

    load_ia32_perf_global_ctrl::set_if_allowed(false);
    CHECK(load_ia32_perf_global_ctrl::is_disabled_if_exists());
}

TEST_CASE("vmcs_vm_entry_controls_load_ia32_pat")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_entry_controls;

    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] = 0xffffffff00000000UL;

    load_ia32_pat::set(true);
    CHECK(load_ia32_pat::is_enabled());

    load_ia32_pat::set(false);
    CHECK(load_ia32_pat::is_disabled());

    load_ia32_pat::set_if_allowed(true);
    CHECK(load_ia32_pat::is_enabled_if_exists());

    load_ia32_pat::set_if_allowed(false);
    CHECK(load_ia32_pat::is_disabled_if_exists());
}

TEST_CASE("vmcs_vm_entry_controls_load_ia32_efer")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_entry_controls;

    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] = 0xffffffff00000000UL;

    load_ia32_efer::set(true);
    CHECK(load_ia32_efer::is_enabled());

    load_ia32_efer::set(false);
    CHECK(load_ia32_efer::is_disabled());

    load_ia32_efer::set_if_allowed(true);
    CHECK(load_ia32_efer::is_enabled_if_exists());

    load_ia32_efer::set_if_allowed(false);
    CHECK(load_ia32_efer::is_disabled_if_exists());
}

TEST_CASE("vmcs_vm_entry_controls_load_ia32_bndcfgs")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_entry_controls;

    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] = 0xffffffff00000000UL;

    load_ia32_bndcfgs::set(true);
    CHECK(load_ia32_bndcfgs::is_enabled());

    load_ia32_bndcfgs::set(false);
    CHECK(load_ia32_bndcfgs::is_disabled());

    load_ia32_bndcfgs::set_if_allowed(true);
    CHECK(load_ia32_bndcfgs::is_enabled_if_exists());

    load_ia32_bndcfgs::set_if_allowed(false);
    CHECK(load_ia32_bndcfgs::is_disabled_if_exists());
}

TEST_CASE("vmcs_vm_entry_controls_pt_conceal_vm_entries")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_entry_controls;

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0xffffffff00000000UL;

    pt_conceal_vm_entries::set(true);
    CHECK(pt_conceal_vm_entries::is_enabled());

    pt_conceal_vm_entries::set(false);
    CHECK(pt_conceal_vm_entries::is_disabled());

    pt_conceal_vm_entries::set_if_allowed(true);
    CHECK(pt_conceal_vm_entries::is_enabled_if_exists());

    pt_conceal_vm_entries::set_if_allowed(false);
    CHECK(pt_conceal_vm_entries::is_disabled_if_exists());
}

TEST_CASE("vmcs_vm_entry_msr_load_count")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_entry_msr_load_count;

    CHECK(exists());

    set(1UL);
    CHECK(get() == 1UL);

    set_if_exists(2UL);
    CHECK(get_if_exists() == 2UL);
}

TEST_CASE("vmcs_vm_entry_interruption_information")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_entry_interruption_information;

    CHECK(exists());

    set(1UL);
    CHECK(get() == 1UL);

    set_if_exists(2UL);
    CHECK(get_if_exists() == 2UL);
}

TEST_CASE("vmcs_vm_entry_interruption_information_vector")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_entry_interruption_information;

    vector::set(0xFFFFFFFFULL);
    CHECK(vector::get() == (vector::mask >> vector::from));

    vector::set(vector::mask, 0xFFFFFFFFULL);
    CHECK(vector::get(vector::mask) == (vector::mask >> vector::from));

    vector::set_if_exists(0xFFFFFFFFULL);
    CHECK(vector::get_if_exists() == (vector::mask >> vector::from));
}

TEST_CASE("vmcs_vm_entry_interruption_information_type")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_entry_interruption_information;

    interruption_type::set(0xFFFFFFFFULL);
    CHECK(interruption_type::get() == (interruption_type::mask >> interruption_type::from));

    interruption_type::set(interruption_type::mask, 0xFFFFFFFFULL);
    CHECK(interruption_type::get(interruption_type::mask) == (interruption_type::mask >> interruption_type::from));

    interruption_type::set_if_exists(0xFFFFFFFFULL);
    CHECK(interruption_type::get_if_exists() == (interruption_type::mask >> interruption_type::from));
}

TEST_CASE("vmcs_vm_entry_interruption_information_deliver_error_code_bit")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_entry_interruption_information;

    deliver_error_code_bit::set(true);
    CHECK(deliver_error_code_bit::is_enabled());
    deliver_error_code_bit::set(false);
    CHECK(deliver_error_code_bit::is_disabled());

    deliver_error_code_bit::set(deliver_error_code_bit::mask, true);
    CHECK(deliver_error_code_bit::is_enabled(deliver_error_code_bit::mask));
    deliver_error_code_bit::set(0x0, false);
    CHECK(deliver_error_code_bit::is_disabled(0x0));

    deliver_error_code_bit::set_if_exists(true);
    CHECK(deliver_error_code_bit::is_enabled_if_exists());
    deliver_error_code_bit::set_if_exists(false);
    CHECK(deliver_error_code_bit::is_disabled_if_exists());
}

TEST_CASE("vmcs_vm_entry_interruption_information_reserved")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_entry_interruption_information;

    reserved::set(0xFFFFFFFFULL);
    CHECK(reserved::get() == (reserved::mask >> reserved::from));

    reserved::set(reserved::mask, 0xFFFFFFFFULL);
    CHECK(reserved::get(reserved::mask) == (reserved::mask >> reserved::from));

    reserved::set_if_exists(0xFFFFFFFFULL);
    CHECK(reserved::get_if_exists() == (reserved::mask >> reserved::from));
}

TEST_CASE("vmcs_vm_entry_interruption_information_valid_bit")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_entry_interruption_information;

    valid_bit::set(true);
    CHECK(valid_bit::is_enabled());
    valid_bit::set(false);
    CHECK(valid_bit::is_disabled());

    valid_bit::set(valid_bit::mask, true);
    CHECK(valid_bit::is_enabled(valid_bit::mask));
    valid_bit::set(0x0, false);
    CHECK(valid_bit::is_disabled(0x0));

    valid_bit::set_if_exists(true);
    CHECK(valid_bit::is_enabled_if_exists());
    valid_bit::set_if_exists(false);
    CHECK(valid_bit::is_disabled_if_exists());
}

TEST_CASE("vmcs_vm_entry_exception_error_code")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_entry_exception_error_code;

    CHECK(exists());

    set(1UL);
    CHECK(get() == 1UL);

    set_if_exists(2UL);
    CHECK(get_if_exists() == 2UL);

    dump(0);
}

TEST_CASE("vmcs_vm_entry_instruction_length")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_entry_instruction_length;

    CHECK(exists());

    set(1UL);
    CHECK(get() == 1UL);

    set_if_exists(2UL);
    CHECK(get_if_exists() == 2UL);

    dump(0);
}

TEST_CASE("vmcs_tpr_threshold")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::tpr_threshold;

    CHECK(exists());

    set(1UL);
    CHECK(get() == 1UL);

    set_if_exists(2UL);
    CHECK(get_if_exists() == 2UL);

    dump(0);
}

TEST_CASE("vmcs_secondary_processor_based_vm_execution_controls")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::secondary_processor_based_vm_execution_controls;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0x0;
    CHECK_FALSE(exists());
    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL;
    CHECK(exists());

    set(1UL);
    CHECK(get() == 1UL);

    set_if_exists(2UL);
    CHECK(get_if_exists() == 2UL);

    dump(0);
}

TEST_CASE("vmcs_secondary_processor_based_vm_execution_controls_virtualize_apic_accesses")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::secondary_processor_based_vm_execution_controls;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0xffffffff00000000UL;

    virtualize_apic_accesses::set(true);
    CHECK(virtualize_apic_accesses::is_enabled());

    virtualize_apic_accesses::set(false);
    CHECK(virtualize_apic_accesses::is_disabled());

    virtualize_apic_accesses::set_if_allowed(true);
    CHECK(virtualize_apic_accesses::is_enabled_if_exists());

    virtualize_apic_accesses::set_if_allowed(false);
    CHECK(virtualize_apic_accesses::is_disabled_if_exists());
}

TEST_CASE("vmcs_secondary_processor_based_vm_execution_controls_enable_ept")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::secondary_processor_based_vm_execution_controls;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0xffffffff00000000UL;

    enable_ept::set(true);
    CHECK(enable_ept::is_enabled());

    enable_ept::set(false);
    CHECK(enable_ept::is_disabled());

    enable_ept::set_if_allowed(true);
    CHECK(enable_ept::is_enabled_if_exists());

    enable_ept::set_if_allowed(false);
    CHECK(enable_ept::is_disabled_if_exists());
}

TEST_CASE("vmcs_secondary_processor_based_vm_execution_controls_descriptor_table_exiting")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::secondary_processor_based_vm_execution_controls;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0xffffffff00000000UL;

    descriptor_table_exiting::set(true);
    CHECK(descriptor_table_exiting::is_enabled());

    descriptor_table_exiting::set(false);
    CHECK(descriptor_table_exiting::is_disabled());

    descriptor_table_exiting::set_if_allowed(true);
    CHECK(descriptor_table_exiting::is_enabled_if_exists());

    descriptor_table_exiting::set_if_allowed(false);
    CHECK(descriptor_table_exiting::is_disabled_if_exists());
}

TEST_CASE("vmcs_secondary_processor_based_vm_execution_controls_enable_rdtscp")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::secondary_processor_based_vm_execution_controls;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0xffffffff00000000UL;

    enable_rdtscp::set(true);
    CHECK(enable_rdtscp::is_enabled());

    enable_rdtscp::set(false);
    CHECK(enable_rdtscp::is_disabled());

    enable_rdtscp::set_if_allowed(true);
    CHECK(enable_rdtscp::is_enabled_if_exists());

    enable_rdtscp::set_if_allowed(false);
    CHECK(enable_rdtscp::is_disabled_if_exists());
}

TEST_CASE("vmcs_secondary_processor_based_vm_execution_controls_virtualize_x2apic_mode")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::secondary_processor_based_vm_execution_controls;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0xffffffff00000000UL;

    virtualize_x2apic_mode::set(true);
    CHECK(virtualize_x2apic_mode::is_enabled());

    virtualize_x2apic_mode::set(false);
    CHECK(virtualize_x2apic_mode::is_disabled());

    virtualize_x2apic_mode::set_if_allowed(true);
    CHECK(virtualize_x2apic_mode::is_enabled_if_exists());

    virtualize_x2apic_mode::set_if_allowed(false);
    CHECK(virtualize_x2apic_mode::is_disabled_if_exists());
}

TEST_CASE("vmcs_secondary_processor_based_vm_execution_controls_enable_vpid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::secondary_processor_based_vm_execution_controls;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0xffffffff00000000UL;

    enable_vpid::set(true);
    CHECK(enable_vpid::is_enabled());

    enable_vpid::set(false);
    CHECK(enable_vpid::is_disabled());

    enable_vpid::set_if_allowed(true);
    CHECK(enable_vpid::is_enabled_if_exists());

    enable_vpid::set_if_allowed(false);
    CHECK(enable_vpid::is_disabled_if_exists());
}

TEST_CASE("vmcs_secondary_processor_based_vm_execution_controls_wbinvd_exiting")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::secondary_processor_based_vm_execution_controls;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0xffffffff00000000UL;

    wbinvd_exiting::set(true);
    CHECK(wbinvd_exiting::is_enabled());

    wbinvd_exiting::set(false);
    CHECK(wbinvd_exiting::is_disabled());

    wbinvd_exiting::set_if_allowed(true);
    CHECK(wbinvd_exiting::is_enabled_if_exists());

    wbinvd_exiting::set_if_allowed(false);
    CHECK(wbinvd_exiting::is_disabled_if_exists());
}

TEST_CASE("vmcs_secondary_processor_based_vm_execution_controls_unrestricted_guest")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::secondary_processor_based_vm_execution_controls;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0xffffffff00000000UL;

    unrestricted_guest::set(true);
    CHECK(unrestricted_guest::is_enabled());

    unrestricted_guest::set(false);
    CHECK(unrestricted_guest::is_disabled());

    unrestricted_guest::set_if_allowed(true);
    CHECK(unrestricted_guest::is_enabled_if_exists());

    unrestricted_guest::set_if_allowed(false);
    CHECK(unrestricted_guest::is_disabled_if_exists());
}

TEST_CASE("vmcs_secondary_processor_based_vm_execution_controls_apic_register_virtualization")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::secondary_processor_based_vm_execution_controls;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0xffffffff00000000UL;

    apic_register_virtualization::set(true);
    CHECK(apic_register_virtualization::is_enabled());

    apic_register_virtualization::set(false);
    CHECK(apic_register_virtualization::is_disabled());

    apic_register_virtualization::set_if_allowed(true);
    CHECK(apic_register_virtualization::is_enabled_if_exists());

    apic_register_virtualization::set_if_allowed(false);
    CHECK(apic_register_virtualization::is_disabled_if_exists());
}

TEST_CASE("vmcs_secondary_processor_based_vm_execution_controls_virtual_interrupt_delivery")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::secondary_processor_based_vm_execution_controls;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0xffffffff00000000UL;

    virtual_interrupt_delivery::set(true);
    CHECK(virtual_interrupt_delivery::is_enabled());

    virtual_interrupt_delivery::set(false);
    CHECK(virtual_interrupt_delivery::is_disabled());

    virtual_interrupt_delivery::set_if_allowed(true);
    CHECK(virtual_interrupt_delivery::is_enabled_if_exists());

    virtual_interrupt_delivery::set_if_allowed(false);
    CHECK(virtual_interrupt_delivery::is_disabled_if_exists());
}

TEST_CASE("vmcs_secondary_processor_based_vm_execution_controls_pause_loop_exiting")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::secondary_processor_based_vm_execution_controls;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0xffffffff00000000UL;

    pause_loop_exiting::set(true);
    CHECK(pause_loop_exiting::is_enabled());

    pause_loop_exiting::set(false);
    CHECK(pause_loop_exiting::is_disabled());

    pause_loop_exiting::set_if_allowed(true);
    CHECK(pause_loop_exiting::is_enabled_if_exists());

    pause_loop_exiting::set_if_allowed(false);
    CHECK(pause_loop_exiting::is_disabled_if_exists());
}

TEST_CASE("vmcs_secondary_processor_based_vm_execution_controls_rdrand_exiting")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::secondary_processor_based_vm_execution_controls;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0xffffffff00000000UL;

    rdrand_exiting::set(true);
    CHECK(rdrand_exiting::is_enabled());

    rdrand_exiting::set(false);
    CHECK(rdrand_exiting::is_disabled());

    rdrand_exiting::set_if_allowed(true);
    CHECK(rdrand_exiting::is_enabled_if_exists());

    rdrand_exiting::set_if_allowed(false);
    CHECK(rdrand_exiting::is_disabled_if_exists());
}

TEST_CASE("vmcs_secondary_processor_based_vm_execution_controls_enable_invpcid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::secondary_processor_based_vm_execution_controls;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0xffffffff00000000UL;

    enable_invpcid::set(true);
    CHECK(enable_invpcid::is_enabled());

    enable_invpcid::set(false);
    CHECK(enable_invpcid::is_disabled());

    enable_invpcid::set_if_allowed(true);
    CHECK(enable_invpcid::is_enabled_if_exists());

    enable_invpcid::set_if_allowed(false);
    CHECK(enable_invpcid::is_disabled_if_exists());
}

TEST_CASE("vmcs_secondary_processor_based_vm_execution_controls_enable_vm_functions")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::secondary_processor_based_vm_execution_controls;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0xffffffff00000000UL;

    enable_vm_functions::set(true);
    CHECK(enable_vm_functions::is_enabled());

    enable_vm_functions::set(false);
    CHECK(enable_vm_functions::is_disabled());

    enable_vm_functions::set_if_allowed(true);
    CHECK(enable_vm_functions::is_enabled_if_exists());

    enable_vm_functions::set_if_allowed(false);
    CHECK(enable_vm_functions::is_disabled_if_exists());
}

TEST_CASE("vmcs_secondary_processor_based_vm_execution_controls_vmcs_shadowing")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::secondary_processor_based_vm_execution_controls;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0xffffffff00000000UL;

    vmcs_shadowing::set(true);
    CHECK(vmcs_shadowing::is_enabled());

    vmcs_shadowing::set(false);
    CHECK(vmcs_shadowing::is_disabled());

    vmcs_shadowing::set_if_allowed(true);
    CHECK(vmcs_shadowing::is_enabled_if_exists());

    vmcs_shadowing::set_if_allowed(false);
    CHECK(vmcs_shadowing::is_disabled_if_exists());
}

TEST_CASE("vmcs_secondary_processor_based_vm_execution_controls_enable_encls_exiting")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::secondary_processor_based_vm_execution_controls;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0xffffffff00000000UL;

    enable_encls_exiting::set(true);
    CHECK(enable_encls_exiting::is_enabled());

    enable_encls_exiting::set(false);
    CHECK(enable_encls_exiting::is_disabled());

    enable_encls_exiting::set_if_allowed(true);
    CHECK(enable_encls_exiting::is_enabled_if_exists());

    enable_encls_exiting::set_if_allowed(false);
    CHECK(enable_encls_exiting::is_disabled_if_exists());
}

TEST_CASE("vmcs_secondary_processor_based_vm_execution_controls_rdseed_exiting")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::secondary_processor_based_vm_execution_controls;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0xffffffff00000000UL;

    rdseed_exiting::set(true);
    CHECK(rdseed_exiting::is_enabled());

    rdseed_exiting::set(false);
    CHECK(rdseed_exiting::is_disabled());

    rdseed_exiting::set_if_allowed(true);
    CHECK(rdseed_exiting::is_enabled_if_exists());

    rdseed_exiting::set_if_allowed(false);
    CHECK(rdseed_exiting::is_disabled_if_exists());
}

TEST_CASE("vmcs_secondary_processor_based_vm_execution_controls_enable_pml")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::secondary_processor_based_vm_execution_controls;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0xffffffff00000000UL;

    enable_pml::set(true);
    CHECK(enable_pml::is_enabled());

    enable_pml::set(false);
    CHECK(enable_pml::is_disabled());

    enable_pml::set_if_allowed(true);
    CHECK(enable_pml::is_enabled_if_exists());

    enable_pml::set_if_allowed(false);
    CHECK(enable_pml::is_disabled_if_exists());
}

TEST_CASE("vmcs_secondary_processor_based_vm_execution_controls_ept_violation_ve")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::secondary_processor_based_vm_execution_controls;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0xffffffff00000000UL;

    ept_violation_ve::set(true);
    CHECK(ept_violation_ve::is_enabled());

    ept_violation_ve::set(false);
    CHECK(ept_violation_ve::is_disabled());

    ept_violation_ve::set_if_allowed(true);
    CHECK(ept_violation_ve::is_enabled_if_exists());

    ept_violation_ve::set_if_allowed(false);
    CHECK(ept_violation_ve::is_disabled_if_exists());
}

TEST_CASE("vmcs_secondary_processor_based_vm_execution_controls_pt_conceal_vmx_nonroot_operation")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::secondary_processor_based_vm_execution_controls;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0xffffffff00000000UL;

    pt_conceal_vmx_nonroot_operation::set(true);
    CHECK(pt_conceal_vmx_nonroot_operation::is_enabled());

    pt_conceal_vmx_nonroot_operation::set(false);
    CHECK(pt_conceal_vmx_nonroot_operation::is_disabled());

    pt_conceal_vmx_nonroot_operation::set_if_allowed(true);
    CHECK(pt_conceal_vmx_nonroot_operation::is_enabled_if_exists());

    pt_conceal_vmx_nonroot_operation::set_if_allowed(false);
    CHECK(pt_conceal_vmx_nonroot_operation::is_disabled_if_exists());
}

TEST_CASE("vmcs_secondary_processor_based_vm_execution_controls_enable_xsaves_xrstors")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::secondary_processor_based_vm_execution_controls;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0xffffffff00000000UL;

    enable_xsaves_xrstors::set(true);
    CHECK(enable_xsaves_xrstors::is_enabled());

    enable_xsaves_xrstors::set(false);
    CHECK(enable_xsaves_xrstors::is_disabled());

    enable_xsaves_xrstors::set_if_allowed(true);
    CHECK(enable_xsaves_xrstors::is_enabled_if_exists());

    enable_xsaves_xrstors::set_if_allowed(false);
    CHECK(enable_xsaves_xrstors::is_disabled_if_exists());
}

TEST_CASE("vmcs_secondary_processor_based_vm_execution_controls_ept_mode_based_control")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::secondary_processor_based_vm_execution_controls;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0xffffffff00000000UL;

    ept_mode_based_control::set(true);
    CHECK(ept_mode_based_control::is_enabled());

    ept_mode_based_control::set(false);
    CHECK(ept_mode_based_control::is_disabled());

    ept_mode_based_control::set_if_allowed(true);
    CHECK(ept_mode_based_control::is_enabled_if_exists());

    ept_mode_based_control::set_if_allowed(false);
    CHECK(ept_mode_based_control::is_disabled_if_exists());
}

TEST_CASE("vmcs_secondary_processor_based_vm_execution_controls_use_tsc_scaling")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::secondary_processor_based_vm_execution_controls;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0xffffffff00000000UL;

    use_tsc_scaling::set(true);
    CHECK(use_tsc_scaling::is_enabled());

    use_tsc_scaling::set(false);
    CHECK(use_tsc_scaling::is_disabled());

    use_tsc_scaling::set_if_allowed(true);
    CHECK(use_tsc_scaling::is_enabled_if_exists());

    use_tsc_scaling::set_if_allowed(false);
    CHECK(use_tsc_scaling::is_disabled_if_exists());
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

    vmcs::ple_gap::dump(0);
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

    vmcs::ple_window::dump(0);
}

#endif
