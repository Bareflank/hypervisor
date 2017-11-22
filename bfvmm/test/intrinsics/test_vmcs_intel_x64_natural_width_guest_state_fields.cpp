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
    mocks.OnCallFunc(_vmread).Do(test_vmread);
    mocks.OnCallFunc(_vmwrite).Do(test_vmwrite);
}

TEST_CASE("test name goes here")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(true);
}

TEST_CASE("vmcs_guest_cr0")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_cr0;

    CHECK(exists());
    set(100UL);
    CHECK(get() == 100UL);
    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    dump(0);
}

TEST_CASE("vmcs_guest_cr0_protection_enable")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_cr0;

    protection_enable::set(true);
    CHECK(protection_enable::is_enabled());
    protection_enable::set(false);
    CHECK(protection_enable::is_disabled());

    protection_enable::set(protection_enable::mask, true);
    CHECK(protection_enable::is_enabled(protection_enable::mask));
    protection_enable::set(0x0, false);
    CHECK(protection_enable::is_disabled(0x0));

    protection_enable::set_if_exists(true);
    CHECK(protection_enable::is_enabled_if_exists());
    protection_enable::set_if_exists(false);
    CHECK(protection_enable::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_cr0_monitor_coprocessor")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_cr0;

    monitor_coprocessor::set(true);
    CHECK(monitor_coprocessor::is_enabled());
    monitor_coprocessor::set(false);
    CHECK(monitor_coprocessor::is_disabled());

    monitor_coprocessor::set(monitor_coprocessor::mask, true);
    CHECK(monitor_coprocessor::is_enabled(monitor_coprocessor::mask));
    monitor_coprocessor::set(0x0, false);
    CHECK(monitor_coprocessor::is_disabled(0x0));

    monitor_coprocessor::set_if_exists(true);
    CHECK(monitor_coprocessor::is_enabled_if_exists());
    monitor_coprocessor::set_if_exists(false);
    CHECK(monitor_coprocessor::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_cr0_emulation")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_cr0;

    emulation::set(true);
    CHECK(emulation::is_enabled());
    emulation::set(false);
    CHECK(emulation::is_disabled());

    emulation::set(emulation::mask, true);
    CHECK(emulation::is_enabled(emulation::mask));
    emulation::set(0x0, false);
    CHECK(emulation::is_disabled(0x0));

    emulation::set_if_exists(true);
    CHECK(emulation::is_enabled_if_exists());
    emulation::set_if_exists(false);
    CHECK(emulation::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_cr0_task_switched")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_cr0;

    task_switched::set(true);
    CHECK(task_switched::is_enabled());
    task_switched::set(false);
    CHECK(task_switched::is_disabled());

    task_switched::set(task_switched::mask, true);
    CHECK(task_switched::is_enabled(task_switched::mask));
    task_switched::set(0x0, false);
    CHECK(task_switched::is_disabled(0x0));

    task_switched::set_if_exists(true);
    CHECK(task_switched::is_enabled_if_exists());
    task_switched::set_if_exists(false);
    CHECK(task_switched::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_cr0_extension_type")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_cr0;

    extension_type::set(true);
    CHECK(extension_type::is_enabled());
    extension_type::set(false);
    CHECK(extension_type::is_disabled());

    extension_type::set(extension_type::mask, true);
    CHECK(extension_type::is_enabled(extension_type::mask));
    extension_type::set(0x0, false);
    CHECK(extension_type::is_disabled(0x0));

    extension_type::set_if_exists(true);
    CHECK(extension_type::is_enabled_if_exists());
    extension_type::set_if_exists(false);
    CHECK(extension_type::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_cr0_numeric_error")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_cr0;

    numeric_error::set(true);
    CHECK(numeric_error::is_enabled());
    numeric_error::set(false);
    CHECK(numeric_error::is_disabled());

    numeric_error::set(numeric_error::mask, true);
    CHECK(numeric_error::is_enabled(numeric_error::mask));
    numeric_error::set(0x0, false);
    CHECK(numeric_error::is_disabled(0x0));

    numeric_error::set_if_exists(true);
    CHECK(numeric_error::is_enabled_if_exists());
    numeric_error::set_if_exists(false);
    CHECK(numeric_error::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_cr0_write_protect")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_cr0;

    write_protect::set(true);
    CHECK(write_protect::is_enabled());
    write_protect::set(false);
    CHECK(write_protect::is_disabled());

    write_protect::set(write_protect::mask, true);
    CHECK(write_protect::is_enabled(write_protect::mask));
    write_protect::set(0x0, false);
    CHECK(write_protect::is_disabled(0x0));

    write_protect::set_if_exists(true);
    CHECK(write_protect::is_enabled_if_exists());
    write_protect::set_if_exists(false);
    CHECK(write_protect::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_cr0_alignment_mask")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_cr0;

    alignment_mask::set(true);
    CHECK(alignment_mask::is_enabled());
    alignment_mask::set(false);
    CHECK(alignment_mask::is_disabled());

    alignment_mask::set(alignment_mask::mask, true);
    CHECK(alignment_mask::is_enabled(alignment_mask::mask));
    alignment_mask::set(0x0, false);
    CHECK(alignment_mask::is_disabled(0x0));

    alignment_mask::set_if_exists(true);
    CHECK(alignment_mask::is_enabled_if_exists());
    alignment_mask::set_if_exists(false);
    CHECK(alignment_mask::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_cr0_not_write_through")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_cr0;

    not_write_through::set(true);
    CHECK(not_write_through::is_enabled());
    not_write_through::set(false);
    CHECK(not_write_through::is_disabled());

    not_write_through::set(not_write_through::mask, true);
    CHECK(not_write_through::is_enabled(not_write_through::mask));
    not_write_through::set(0x0, false);
    CHECK(not_write_through::is_disabled(0x0));

    not_write_through::set_if_exists(true);
    CHECK(not_write_through::is_enabled_if_exists());
    not_write_through::set_if_exists(false);
    CHECK(not_write_through::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_cr0_cache_disable")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_cr0;

    cache_disable::set(true);
    CHECK(cache_disable::is_enabled());
    cache_disable::set(false);
    CHECK(cache_disable::is_disabled());

    cache_disable::set(cache_disable::mask, true);
    CHECK(cache_disable::is_enabled(cache_disable::mask));
    cache_disable::set(0x0, false);
    CHECK(cache_disable::is_disabled(0x0));

    cache_disable::set_if_exists(true);
    CHECK(cache_disable::is_enabled_if_exists());
    cache_disable::set_if_exists(false);
    CHECK(cache_disable::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_cr0_paging")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_cr0;

    paging::set(true);
    CHECK(paging::is_enabled());
    paging::set(false);
    CHECK(paging::is_disabled());

    paging::set(paging::mask, true);
    CHECK(paging::is_enabled(paging::mask));
    paging::set(0x0, false);
    CHECK(paging::is_disabled(0x0));

    paging::set_if_exists(true);
    CHECK(paging::is_enabled_if_exists());
    paging::set_if_exists(false);
    CHECK(paging::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_cr3")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_cr3;

    CHECK(exists());
    set(100UL);
    CHECK(get() == 100UL);
    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    dump(0);
}

TEST_CASE("vmcs_guest_cr4")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_cr4;

    CHECK(exists());
    set(100UL);
    CHECK(get() == 100UL);
    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    dump(0);
}

TEST_CASE("vmcs_guest_cr4_v8086_mode_extensions")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_cr4;

    v8086_mode_extensions::set(true);
    CHECK(v8086_mode_extensions::is_enabled());
    v8086_mode_extensions::set(false);
    CHECK(v8086_mode_extensions::is_disabled());

    v8086_mode_extensions::set(v8086_mode_extensions::mask, true);
    CHECK(v8086_mode_extensions::is_enabled(v8086_mode_extensions::mask));
    v8086_mode_extensions::set(0x0, false);
    CHECK(v8086_mode_extensions::is_disabled(0x0));

    v8086_mode_extensions::set_if_exists(true);
    CHECK(v8086_mode_extensions::is_enabled_if_exists());
    v8086_mode_extensions::set_if_exists(false);
    CHECK(v8086_mode_extensions::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_cr4_protected_mode_virtual_interrupts")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_cr4;

    protected_mode_virtual_interrupts::set(true);
    CHECK(protected_mode_virtual_interrupts::is_enabled());
    protected_mode_virtual_interrupts::set(false);
    CHECK(protected_mode_virtual_interrupts::is_disabled());

    protected_mode_virtual_interrupts::set(protected_mode_virtual_interrupts::mask, true);
    CHECK(protected_mode_virtual_interrupts::is_enabled(protected_mode_virtual_interrupts::mask));
    protected_mode_virtual_interrupts::set(0x0, false);
    CHECK(protected_mode_virtual_interrupts::is_disabled(0x0));

    protected_mode_virtual_interrupts::set_if_exists(true);
    CHECK(protected_mode_virtual_interrupts::is_enabled_if_exists());
    protected_mode_virtual_interrupts::set_if_exists(false);
    CHECK(protected_mode_virtual_interrupts::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_cr4_time_stamp_disable")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_cr4;

    time_stamp_disable::set(true);
    CHECK(time_stamp_disable::is_enabled());
    time_stamp_disable::set(false);
    CHECK(time_stamp_disable::is_disabled());

    time_stamp_disable::set(time_stamp_disable::mask, true);
    CHECK(time_stamp_disable::is_enabled(time_stamp_disable::mask));
    time_stamp_disable::set(0x0, false);
    CHECK(time_stamp_disable::is_disabled(0x0));

    time_stamp_disable::set_if_exists(true);
    CHECK(time_stamp_disable::is_enabled_if_exists());
    time_stamp_disable::set_if_exists(false);
    CHECK(time_stamp_disable::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_cr4_debugging_extensions")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_cr4;

    debugging_extensions::set(true);
    CHECK(debugging_extensions::is_enabled());
    debugging_extensions::set(false);
    CHECK(debugging_extensions::is_disabled());

    debugging_extensions::set(debugging_extensions::mask, true);
    CHECK(debugging_extensions::is_enabled(debugging_extensions::mask));
    debugging_extensions::set(0x0, false);
    CHECK(debugging_extensions::is_disabled(0x0));

    debugging_extensions::set_if_exists(true);
    CHECK(debugging_extensions::is_enabled_if_exists());
    debugging_extensions::set_if_exists(false);
    CHECK(debugging_extensions::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_cr4_page_size_extensions")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_cr4;

    page_size_extensions::set(true);
    CHECK(page_size_extensions::is_enabled());
    page_size_extensions::set(false);
    CHECK(page_size_extensions::is_disabled());

    page_size_extensions::set(page_size_extensions::mask, true);
    CHECK(page_size_extensions::is_enabled(page_size_extensions::mask));
    page_size_extensions::set(0x0, false);
    CHECK(page_size_extensions::is_disabled(0x0));

    page_size_extensions::set_if_exists(true);
    CHECK(page_size_extensions::is_enabled_if_exists());
    page_size_extensions::set_if_exists(false);
    CHECK(page_size_extensions::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_cr4_physical_address_extensions")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_cr4;

    physical_address_extensions::set(true);
    CHECK(physical_address_extensions::is_enabled());
    physical_address_extensions::set(false);
    CHECK(physical_address_extensions::is_disabled());

    physical_address_extensions::set(physical_address_extensions::mask, true);
    CHECK(physical_address_extensions::is_enabled(physical_address_extensions::mask));
    physical_address_extensions::set(0x0, false);
    CHECK(physical_address_extensions::is_disabled(0x0));

    physical_address_extensions::set_if_exists(true);
    CHECK(physical_address_extensions::is_enabled_if_exists());
    physical_address_extensions::set_if_exists(false);
    CHECK(physical_address_extensions::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_cr4_machine_check_enable")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_cr4;

    machine_check_enable::set(true);
    CHECK(machine_check_enable::is_enabled());
    machine_check_enable::set(false);
    CHECK(machine_check_enable::is_disabled());

    machine_check_enable::set(machine_check_enable::mask, true);
    CHECK(machine_check_enable::is_enabled(machine_check_enable::mask));
    machine_check_enable::set(0x0, false);
    CHECK(machine_check_enable::is_disabled(0x0));

    machine_check_enable::set_if_exists(true);
    CHECK(machine_check_enable::is_enabled_if_exists());
    machine_check_enable::set_if_exists(false);
    CHECK(machine_check_enable::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_cr4_page_global_enable")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_cr4;

    page_global_enable::set(true);
    CHECK(page_global_enable::is_enabled());
    page_global_enable::set(false);
    CHECK(page_global_enable::is_disabled());

    page_global_enable::set(page_global_enable::mask, true);
    CHECK(page_global_enable::is_enabled(page_global_enable::mask));
    page_global_enable::set(0x0, false);
    CHECK(page_global_enable::is_disabled(0x0));

    page_global_enable::set_if_exists(true);
    CHECK(page_global_enable::is_enabled_if_exists());
    page_global_enable::set_if_exists(false);
    CHECK(page_global_enable::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_cr4_performance_monitor_counter_enable")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_cr4;

    performance_monitor_counter_enable::set(true);
    CHECK(performance_monitor_counter_enable::is_enabled());
    performance_monitor_counter_enable::set(false);
    CHECK(performance_monitor_counter_enable::is_disabled());

    performance_monitor_counter_enable::set(performance_monitor_counter_enable::mask, true);
    CHECK(performance_monitor_counter_enable::is_enabled(performance_monitor_counter_enable::mask));
    performance_monitor_counter_enable::set(0x0, false);
    CHECK(performance_monitor_counter_enable::is_disabled(0x0));

    performance_monitor_counter_enable::set_if_exists(true);
    CHECK(performance_monitor_counter_enable::is_enabled_if_exists());
    performance_monitor_counter_enable::set_if_exists(false);
    CHECK(performance_monitor_counter_enable::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_cr4_osfxsr")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_cr4;

    osfxsr::set(true);
    CHECK(osfxsr::is_enabled());
    osfxsr::set(false);
    CHECK(osfxsr::is_disabled());

    osfxsr::set(osfxsr::mask, true);
    CHECK(osfxsr::is_enabled(osfxsr::mask));
    osfxsr::set(0x0, false);
    CHECK(osfxsr::is_disabled(0x0));

    osfxsr::set_if_exists(true);
    CHECK(osfxsr::is_enabled_if_exists());
    osfxsr::set_if_exists(false);
    CHECK(osfxsr::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_cr4_osxmmexcpt")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_cr4;

    osxmmexcpt::set(true);
    CHECK(osxmmexcpt::is_enabled());
    osxmmexcpt::set(false);
    CHECK(osxmmexcpt::is_disabled());

    osxmmexcpt::set(osxmmexcpt::mask, true);
    CHECK(osxmmexcpt::is_enabled(osxmmexcpt::mask));
    osxmmexcpt::set(0x0, false);
    CHECK(osxmmexcpt::is_disabled(0x0));

    osxmmexcpt::set_if_exists(true);
    CHECK(osxmmexcpt::is_enabled_if_exists());
    osxmmexcpt::set_if_exists(false);
    CHECK(osxmmexcpt::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_cr4_vmx_enable_bit")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_cr4;

    vmx_enable_bit::set(true);
    CHECK(vmx_enable_bit::is_enabled());
    vmx_enable_bit::set(false);
    CHECK(vmx_enable_bit::is_disabled());

    vmx_enable_bit::set(vmx_enable_bit::mask, true);
    CHECK(vmx_enable_bit::is_enabled(vmx_enable_bit::mask));
    vmx_enable_bit::set(0x0, false);
    CHECK(vmx_enable_bit::is_disabled(0x0));

    vmx_enable_bit::set_if_exists(true);
    CHECK(vmx_enable_bit::is_enabled_if_exists());
    vmx_enable_bit::set_if_exists(false);
    CHECK(vmx_enable_bit::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_cr4_smx_enable_bit")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_cr4;

    smx_enable_bit::set(true);
    CHECK(smx_enable_bit::is_enabled());
    smx_enable_bit::set(false);
    CHECK(smx_enable_bit::is_disabled());

    smx_enable_bit::set(smx_enable_bit::mask, true);
    CHECK(smx_enable_bit::is_enabled(smx_enable_bit::mask));
    smx_enable_bit::set(0x0, false);
    CHECK(smx_enable_bit::is_disabled(0x0));

    smx_enable_bit::set_if_exists(true);
    CHECK(smx_enable_bit::is_enabled_if_exists());
    smx_enable_bit::set_if_exists(false);
    CHECK(smx_enable_bit::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_cr4_fsgsbase_enable_bit")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_cr4;

    fsgsbase_enable_bit::set(true);
    CHECK(fsgsbase_enable_bit::is_enabled());
    fsgsbase_enable_bit::set(false);
    CHECK(fsgsbase_enable_bit::is_disabled());

    fsgsbase_enable_bit::set(fsgsbase_enable_bit::mask, true);
    CHECK(fsgsbase_enable_bit::is_enabled(fsgsbase_enable_bit::mask));
    fsgsbase_enable_bit::set(0x0, false);
    CHECK(fsgsbase_enable_bit::is_disabled(0x0));

    fsgsbase_enable_bit::set_if_exists(true);
    CHECK(fsgsbase_enable_bit::is_enabled_if_exists());
    fsgsbase_enable_bit::set_if_exists(false);
    CHECK(fsgsbase_enable_bit::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_cr4_pcid_enable_bit")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_cr4;

    pcid_enable_bit::set(true);
    CHECK(pcid_enable_bit::is_enabled());
    pcid_enable_bit::set(false);
    CHECK(pcid_enable_bit::is_disabled());

    pcid_enable_bit::set(pcid_enable_bit::mask, true);
    CHECK(pcid_enable_bit::is_enabled(pcid_enable_bit::mask));
    pcid_enable_bit::set(0x0, false);
    CHECK(pcid_enable_bit::is_disabled(0x0));

    pcid_enable_bit::set_if_exists(true);
    CHECK(pcid_enable_bit::is_enabled_if_exists());
    pcid_enable_bit::set_if_exists(false);
    CHECK(pcid_enable_bit::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_cr4_osxsave")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_cr4;

    osxsave::set(true);
    CHECK(osxsave::is_enabled());
    osxsave::set(false);
    CHECK(osxsave::is_disabled());

    osxsave::set(osxsave::mask, true);
    CHECK(osxsave::is_enabled(osxsave::mask));
    osxsave::set(0x0, false);
    CHECK(osxsave::is_disabled(0x0));

    osxsave::set_if_exists(true);
    CHECK(osxsave::is_enabled_if_exists());
    osxsave::set_if_exists(false);
    CHECK(osxsave::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_cr4_smep_enable_bit")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_cr4;

    smep_enable_bit::set(true);
    CHECK(smep_enable_bit::is_enabled());
    smep_enable_bit::set(false);
    CHECK(smep_enable_bit::is_disabled());

    smep_enable_bit::set(smep_enable_bit::mask, true);
    CHECK(smep_enable_bit::is_enabled(smep_enable_bit::mask));
    smep_enable_bit::set(0x0, false);
    CHECK(smep_enable_bit::is_disabled(0x0));

    smep_enable_bit::set_if_exists(true);
    CHECK(smep_enable_bit::is_enabled_if_exists());
    smep_enable_bit::set_if_exists(false);
    CHECK(smep_enable_bit::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_cr4_smap_enable_bit")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_cr4;

    smap_enable_bit::set(true);
    CHECK(smap_enable_bit::is_enabled());
    smap_enable_bit::set(false);
    CHECK(smap_enable_bit::is_disabled());

    smap_enable_bit::set(smap_enable_bit::mask, true);
    CHECK(smap_enable_bit::is_enabled(smap_enable_bit::mask));
    smap_enable_bit::set(0x0, false);
    CHECK(smap_enable_bit::is_disabled(0x0));

    smap_enable_bit::set_if_exists(true);
    CHECK(smap_enable_bit::is_enabled_if_exists());
    smap_enable_bit::set_if_exists(false);
    CHECK(smap_enable_bit::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_cr4_protection_key_enable_bit")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_cr4;

    protection_key_enable_bit::set(true);
    CHECK(protection_key_enable_bit::is_enabled());
    protection_key_enable_bit::set(false);
    CHECK(protection_key_enable_bit::is_disabled());

    protection_key_enable_bit::set(protection_key_enable_bit::mask, true);
    CHECK(protection_key_enable_bit::is_enabled(protection_key_enable_bit::mask));
    protection_key_enable_bit::set(0x0, false);
    CHECK(protection_key_enable_bit::is_disabled(0x0));

    protection_key_enable_bit::set_if_exists(true);
    CHECK(protection_key_enable_bit::is_enabled_if_exists());
    protection_key_enable_bit::set_if_exists(false);
    CHECK(protection_key_enable_bit::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_es_base")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_es_base;

    CHECK(exists());
    set(100UL);
    CHECK(get() == 100UL);
    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    dump(0);
}

TEST_CASE("vmcs_guest_cs_base")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_cs_base;

    CHECK(exists());
    set(100UL);
    CHECK(get() == 100UL);
    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    dump(0);
}

TEST_CASE("vmcs_guest_ss_base")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_ss_base;

    CHECK(exists());
    set(100UL);
    CHECK(get() == 100UL);
    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    dump(0);
}

TEST_CASE("vmcs_guest_ds_base")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_ds_base;

    CHECK(exists());
    set(100UL);
    CHECK(get() == 100UL);
    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    dump(0);
}

TEST_CASE("vmcs_guest_fs_base")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_fs_base;

    CHECK(exists());
    set(100UL);
    CHECK(get() == 100UL);
    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    dump(0);
}

TEST_CASE("vmcs_guest_gs_base")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_gs_base;

    CHECK(exists());
    set(100UL);
    CHECK(get() == 100UL);
    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    dump(0);
}

TEST_CASE("vmcs_guest_ldtr_base")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_ldtr_base;

    CHECK(exists());
    set(100UL);
    CHECK(get() == 100UL);
    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    dump(0);
}

TEST_CASE("vmcs_guest_tr_base")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_tr_base;

    CHECK(exists());
    set(100UL);
    CHECK(get() == 100UL);
    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    dump(0);
}

TEST_CASE("vmcs_guest_gdtr_base")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_gdtr_base;

    CHECK(exists());
    set(100UL);
    CHECK(get() == 100UL);
    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    dump(0);
}

TEST_CASE("vmcs_guest_idtr_base")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_idtr_base;

    CHECK(exists());
    set(100UL);
    CHECK(get() == 100UL);
    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    dump(0);
}

TEST_CASE("vmcs_guest_dr7")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_dr7;

    CHECK(exists());
    set(100UL);
    CHECK(get() == 100UL);
    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    dump(0);
}

TEST_CASE("vmcs_guest_rsp")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_rsp;

    CHECK(exists());
    set(100UL);
    CHECK(get() == 100UL);
    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    dump(0);
}

TEST_CASE("vmcs_guest_rip")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_rip;

    CHECK(exists());
    set(100UL);
    CHECK(get() == 100UL);
    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    dump(0);
}

TEST_CASE("vmcs_guest_rflags")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_rflags;

    CHECK(exists());
    set(100UL);
    CHECK(get() == 100UL);
    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    dump(0);
}

TEST_CASE("vmcs_guest_rflags_carry_flag")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_rflags;

    carry_flag::set(true);
    CHECK(carry_flag::is_enabled());
    carry_flag::set(false);
    CHECK(carry_flag::is_disabled());

    carry_flag::set(carry_flag::mask, true);
    CHECK(carry_flag::is_enabled(carry_flag::mask));
    carry_flag::set(0x0, false);
    CHECK(carry_flag::is_disabled(0x0));

    carry_flag::set_if_exists(true);
    CHECK(carry_flag::is_enabled_if_exists());
    carry_flag::set_if_exists(false);
    CHECK(carry_flag::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_rflags_parity_flag")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_rflags;

    parity_flag::set(true);
    CHECK(parity_flag::is_enabled());
    parity_flag::set(false);
    CHECK(parity_flag::is_disabled());

    parity_flag::set(parity_flag::mask, true);
    CHECK(parity_flag::is_enabled(parity_flag::mask));
    parity_flag::set(0x0, false);
    CHECK(parity_flag::is_disabled(0x0));

    parity_flag::set_if_exists(true);
    CHECK(parity_flag::is_enabled_if_exists());
    parity_flag::set_if_exists(false);
    CHECK(parity_flag::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_rflags_auxiliary_carry_flag")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_rflags;

    auxiliary_carry_flag::set(true);
    CHECK(auxiliary_carry_flag::is_enabled());
    auxiliary_carry_flag::set(false);
    CHECK(auxiliary_carry_flag::is_disabled());

    auxiliary_carry_flag::set(auxiliary_carry_flag::mask, true);
    CHECK(auxiliary_carry_flag::is_enabled(auxiliary_carry_flag::mask));
    auxiliary_carry_flag::set(0x0, false);
    CHECK(auxiliary_carry_flag::is_disabled(0x0));

    auxiliary_carry_flag::set_if_exists(true);
    CHECK(auxiliary_carry_flag::is_enabled_if_exists());
    auxiliary_carry_flag::set_if_exists(false);
    CHECK(auxiliary_carry_flag::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_rflags_zero_flag")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_rflags;

    zero_flag::set(true);
    CHECK(zero_flag::is_enabled());
    zero_flag::set(false);
    CHECK(zero_flag::is_disabled());

    zero_flag::set(zero_flag::mask, true);
    CHECK(zero_flag::is_enabled(zero_flag::mask));
    zero_flag::set(0x0, false);
    CHECK(zero_flag::is_disabled(0x0));

    zero_flag::set_if_exists(true);
    CHECK(zero_flag::is_enabled_if_exists());
    zero_flag::set_if_exists(false);
    CHECK(zero_flag::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_rflags_sign_flag")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_rflags;

    sign_flag::set(true);
    CHECK(sign_flag::is_enabled());
    sign_flag::set(false);
    CHECK(sign_flag::is_disabled());

    sign_flag::set(sign_flag::mask, true);
    CHECK(sign_flag::is_enabled(sign_flag::mask));
    sign_flag::set(0x0, false);
    CHECK(sign_flag::is_disabled(0x0));

    sign_flag::set_if_exists(true);
    CHECK(sign_flag::is_enabled_if_exists());
    sign_flag::set_if_exists(false);
    CHECK(sign_flag::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_rflags_trap_flag")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_rflags;

    trap_flag::set(true);
    CHECK(trap_flag::is_enabled());
    trap_flag::set(false);
    CHECK(trap_flag::is_disabled());

    trap_flag::set(trap_flag::mask, true);
    CHECK(trap_flag::is_enabled(trap_flag::mask));
    trap_flag::set(0x0, false);
    CHECK(trap_flag::is_disabled(0x0));

    trap_flag::set_if_exists(true);
    CHECK(trap_flag::is_enabled_if_exists());
    trap_flag::set_if_exists(false);
    CHECK(trap_flag::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_rflags_interrupt_enable_flag")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_rflags;

    interrupt_enable_flag::set(true);
    CHECK(interrupt_enable_flag::is_enabled());
    interrupt_enable_flag::set(false);
    CHECK(interrupt_enable_flag::is_disabled());

    interrupt_enable_flag::set(interrupt_enable_flag::mask, true);
    CHECK(interrupt_enable_flag::is_enabled(interrupt_enable_flag::mask));
    interrupt_enable_flag::set(0x0, false);
    CHECK(interrupt_enable_flag::is_disabled(0x0));

    interrupt_enable_flag::set_if_exists(true);
    CHECK(interrupt_enable_flag::is_enabled_if_exists());
    interrupt_enable_flag::set_if_exists(false);
    CHECK(interrupt_enable_flag::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_rflags_direction_flag")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_rflags;

    direction_flag::set(true);
    CHECK(direction_flag::is_enabled());
    direction_flag::set(false);
    CHECK(direction_flag::is_disabled());

    direction_flag::set(direction_flag::mask, true);
    CHECK(direction_flag::is_enabled(direction_flag::mask));
    direction_flag::set(0x0, false);
    CHECK(direction_flag::is_disabled(0x0));

    direction_flag::set_if_exists(true);
    CHECK(direction_flag::is_enabled_if_exists());
    direction_flag::set_if_exists(false);
    CHECK(direction_flag::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_rflags_overflow_flag")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_rflags;

    overflow_flag::set(true);
    CHECK(overflow_flag::is_enabled());
    overflow_flag::set(false);
    CHECK(overflow_flag::is_disabled());

    overflow_flag::set(overflow_flag::mask, true);
    CHECK(overflow_flag::is_enabled(overflow_flag::mask));
    overflow_flag::set(0x0, false);
    CHECK(overflow_flag::is_disabled(0x0));

    overflow_flag::set_if_exists(true);
    CHECK(overflow_flag::is_enabled_if_exists());
    overflow_flag::set_if_exists(false);
    CHECK(overflow_flag::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_rflags_privilege_level")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_rflags;

    privilege_level::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(privilege_level::get() == (privilege_level::mask >> privilege_level::from));

    privilege_level::set(privilege_level::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(privilege_level::get(privilege_level::mask) == (privilege_level::mask >> privilege_level::from));

    privilege_level::set_if_exists(0xFFFFFFFFFFFFFFFFULL);
    CHECK(privilege_level::get_if_exists() == (privilege_level::mask >> privilege_level::from));
}

TEST_CASE("vmcs_guest_rflags_nested_task")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_rflags;

    nested_task::set(true);
    CHECK(nested_task::is_enabled());
    nested_task::set(false);
    CHECK(nested_task::is_disabled());

    nested_task::set(nested_task::mask, true);
    CHECK(nested_task::is_enabled(nested_task::mask));
    nested_task::set(0x0, false);
    CHECK(nested_task::is_disabled(0x0));

    nested_task::set_if_exists(true);
    CHECK(nested_task::is_enabled_if_exists());
    nested_task::set_if_exists(false);
    CHECK(nested_task::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_rflags_resume_flag")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_rflags;

    resume_flag::set(true);
    CHECK(resume_flag::is_enabled());
    resume_flag::set(false);
    CHECK(resume_flag::is_disabled());

    resume_flag::set(resume_flag::mask, true);
    CHECK(resume_flag::is_enabled(resume_flag::mask));
    resume_flag::set(0x0, false);
    CHECK(resume_flag::is_disabled(0x0));

    resume_flag::set_if_exists(true);
    CHECK(resume_flag::is_enabled_if_exists());
    resume_flag::set_if_exists(false);
    CHECK(resume_flag::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_rflags_virtual_8086_mode")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_rflags;

    virtual_8086_mode::set(true);
    CHECK(virtual_8086_mode::is_enabled());
    virtual_8086_mode::set(false);
    CHECK(virtual_8086_mode::is_disabled());

    virtual_8086_mode::set(virtual_8086_mode::mask, true);
    CHECK(virtual_8086_mode::is_enabled(virtual_8086_mode::mask));
    virtual_8086_mode::set(0x0, false);
    CHECK(virtual_8086_mode::is_disabled(0x0));

    virtual_8086_mode::set_if_exists(true);
    CHECK(virtual_8086_mode::is_enabled_if_exists());
    virtual_8086_mode::set_if_exists(false);
    CHECK(virtual_8086_mode::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_rflags_alignment_check_access_control")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_rflags;

    alignment_check_access_control::set(true);
    CHECK(alignment_check_access_control::is_enabled());
    alignment_check_access_control::set(false);
    CHECK(alignment_check_access_control::is_disabled());

    alignment_check_access_control::set(alignment_check_access_control::mask, true);
    CHECK(alignment_check_access_control::is_enabled(alignment_check_access_control::mask));
    alignment_check_access_control::set(0x0, false);
    CHECK(alignment_check_access_control::is_disabled(0x0));

    alignment_check_access_control::set_if_exists(true);
    CHECK(alignment_check_access_control::is_enabled_if_exists());
    alignment_check_access_control::set_if_exists(false);
    CHECK(alignment_check_access_control::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_rflags_virtual_interupt_flag")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_rflags;

    virtual_interrupt_flag::set(true);
    CHECK(virtual_interrupt_flag::is_enabled());
    virtual_interrupt_flag::set(false);
    CHECK(virtual_interrupt_flag::is_disabled());

    virtual_interrupt_flag::set(virtual_interrupt_flag::mask, true);
    CHECK(virtual_interrupt_flag::is_enabled(virtual_interrupt_flag::mask));
    virtual_interrupt_flag::set(0x0, false);
    CHECK(virtual_interrupt_flag::is_disabled(0x0));

    virtual_interrupt_flag::set_if_exists(true);
    CHECK(virtual_interrupt_flag::is_enabled_if_exists());
    virtual_interrupt_flag::set_if_exists(false);
    CHECK(virtual_interrupt_flag::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_rflags_virtual_interupt_pending")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_rflags;

    virtual_interrupt_pending::set(true);
    CHECK(virtual_interrupt_pending::is_enabled());
    virtual_interrupt_pending::set(false);
    CHECK(virtual_interrupt_pending::is_disabled());

    virtual_interrupt_pending::set(virtual_interrupt_pending::mask, true);
    CHECK(virtual_interrupt_pending::is_enabled(virtual_interrupt_pending::mask));
    virtual_interrupt_pending::set(0x0, false);
    CHECK(virtual_interrupt_pending::is_disabled(0x0));

    virtual_interrupt_pending::set_if_exists(true);
    CHECK(virtual_interrupt_pending::is_enabled_if_exists());
    virtual_interrupt_pending::set_if_exists(false);
    CHECK(virtual_interrupt_pending::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_rflags_id_flag")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_rflags;

    id_flag::set(true);
    CHECK(id_flag::is_enabled());
    id_flag::set(false);
    CHECK(id_flag::is_disabled());

    id_flag::set(id_flag::mask, true);
    CHECK(id_flag::is_enabled(id_flag::mask));
    id_flag::set(0x0, false);
    CHECK(id_flag::is_disabled(0x0));

    id_flag::set_if_exists(true);
    CHECK(id_flag::is_enabled_if_exists());
    id_flag::set_if_exists(false);
    CHECK(id_flag::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_rflags_reserved")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_rflags;

    reserved::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(reserved::get() == (reserved::mask >> reserved::from));

    reserved::set(reserved::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(reserved::get(reserved::mask) == (reserved::mask >> reserved::from));

    reserved::set_if_exists(0xFFFFFFFFFFFFFFFFULL);
    CHECK(reserved::get_if_exists() == (reserved::mask >> reserved::from));
}

TEST_CASE("vmcs_guest_rflags_always_disabled")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_rflags;

    always_disabled::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(always_disabled::get() == (always_disabled::mask >> always_disabled::from));

    always_disabled::set(always_disabled::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(always_disabled::get(always_disabled::mask) == (always_disabled::mask >> always_disabled::from));

    always_disabled::set_if_exists(0xFFFFFFFFFFFFFFFFULL);
    CHECK(always_disabled::get_if_exists() == (always_disabled::mask >> always_disabled::from));
}

TEST_CASE("vmcs_guest_rflags_always_enabled")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_rflags;

    always_enabled::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(always_enabled::get() == (always_enabled::mask >> always_enabled::from));

    always_enabled::set(always_enabled::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(always_enabled::get(always_enabled::mask) == (always_enabled::mask >> always_enabled::from));

    always_enabled::set_if_exists(0xFFFFFFFFFFFFFFFFULL);
    CHECK(always_enabled::get_if_exists() == (always_enabled::mask >> always_enabled::from));
}

TEST_CASE("vmcs_guest_pending_debug_exceptions")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_pending_debug_exceptions;

    CHECK(exists());
    set(100UL);
    CHECK(get() == 100UL);
    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    dump(0);
}

TEST_CASE("vmcs_guest_pending_debug_exceptions_b0")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_pending_debug_exceptions;

    b0::set(true);
    CHECK(b0::is_enabled());
    b0::set(false);
    CHECK(b0::is_disabled());

    b0::set(b0::mask, true);
    CHECK(b0::is_enabled(b0::mask));
    b0::set(0x0, false);
    CHECK(b0::is_disabled(0x0));

    b0::set_if_exists(true);
    CHECK(b0::is_enabled_if_exists());
    b0::set_if_exists(false);
    CHECK(b0::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_pending_debug_exceptions_b1")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_pending_debug_exceptions;

    b1::set(true);
    CHECK(b1::is_enabled());
    b1::set(false);
    CHECK(b1::is_disabled());

    b1::set(b1::mask, true);
    CHECK(b1::is_enabled(b1::mask));
    b1::set(0x0, false);
    CHECK(b1::is_disabled(0x0));

    b1::set_if_exists(true);
    CHECK(b1::is_enabled_if_exists());
    b1::set_if_exists(false);
    CHECK(b1::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_pending_debug_exceptions_b2")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_pending_debug_exceptions;

    b2::set(true);
    CHECK(b2::is_enabled());
    b2::set(false);
    CHECK(b2::is_disabled());

    b2::set(b2::mask, true);
    CHECK(b2::is_enabled(b2::mask));
    b2::set(0x0, false);
    CHECK(b2::is_disabled(0x0));

    b2::set_if_exists(true);
    CHECK(b2::is_enabled_if_exists());
    b2::set_if_exists(false);
    CHECK(b2::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_pending_debug_exceptions_b3")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_pending_debug_exceptions;

    b3::set(true);
    CHECK(b3::is_enabled());
    b3::set(false);
    CHECK(b3::is_disabled());

    b3::set(b3::mask, true);
    CHECK(b3::is_enabled(b3::mask));
    b3::set(0x0, false);
    CHECK(b3::is_disabled(0x0));

    b3::set_if_exists(true);
    CHECK(b3::is_enabled_if_exists());
    b3::set_if_exists(false);
    CHECK(b3::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_pending_debug_exceptions_reserved")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_pending_debug_exceptions::reserved::set(0x10UL);
    CHECK(vmcs::guest_pending_debug_exceptions::reserved::get() == 0x10UL);

    vmcs::guest_pending_debug_exceptions::reserved::set_if_exists(0x0UL);
    CHECK(vmcs::guest_pending_debug_exceptions::reserved::get_if_exists() == 0x0UL);

    using namespace vmcs::guest_pending_debug_exceptions;

    reserved::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(reserved::get() == (reserved::mask >> reserved::from));

    reserved::set(reserved::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(reserved::get(reserved::mask) == (reserved::mask >> reserved::from));

    reserved::set_if_exists(0xFFFFFFFFFFFFFFFFULL);
    CHECK(reserved::get_if_exists() == (reserved::mask >> reserved::from));
}

TEST_CASE("vmcs_guest_pending_debug_exceptions_enabled_breakpoint")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_pending_debug_exceptions;

    enabled_breakpoint::set(true);
    CHECK(enabled_breakpoint::is_enabled());
    enabled_breakpoint::set(false);
    CHECK(enabled_breakpoint::is_disabled());

    enabled_breakpoint::set(enabled_breakpoint::mask, true);
    CHECK(enabled_breakpoint::is_enabled(enabled_breakpoint::mask));
    enabled_breakpoint::set(0x0, false);
    CHECK(enabled_breakpoint::is_disabled(0x0));

    enabled_breakpoint::set_if_exists(true);
    CHECK(enabled_breakpoint::is_enabled_if_exists());
    enabled_breakpoint::set_if_exists(false);
    CHECK(enabled_breakpoint::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_pending_debug_exceptions_bs")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_pending_debug_exceptions;

    bs::set(true);
    CHECK(bs::is_enabled());
    bs::set(false);
    CHECK(bs::is_disabled());

    bs::set(bs::mask, true);
    CHECK(bs::is_enabled(bs::mask));
    bs::set(0x0, false);
    CHECK(bs::is_disabled(0x0));

    bs::set_if_exists(true);
    CHECK(bs::is_enabled_if_exists());
    bs::set_if_exists(false);
    CHECK(bs::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_pending_debug_exceptions_rtm")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_pending_debug_exceptions;

    rtm::set(true);
    CHECK(rtm::is_enabled());
    rtm::set(false);
    CHECK(rtm::is_disabled());

    rtm::set(rtm::mask, true);
    CHECK(rtm::is_enabled(rtm::mask));
    rtm::set(0x0, false);
    CHECK(rtm::is_disabled(0x0));

    rtm::set_if_exists(true);
    CHECK(rtm::is_enabled_if_exists());
    rtm::set_if_exists(false);
    CHECK(rtm::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_ia32_sysenter_esp")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_ia32_sysenter_esp;

    CHECK(exists());
    set(100UL);
    CHECK(get() == 100UL);
    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    dump(0);
}

TEST_CASE("vmcs_guest_ia32_sysenter_eip")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_ia32_sysenter_eip;

    CHECK(exists());
    set(100UL);
    CHECK(get() == 100UL);
    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    dump(0);
}

#endif
