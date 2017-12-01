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

TEST_CASE("vmcs_host_cr0")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::host_cr0;

    CHECK(exists());
    set(100UL);
    CHECK(get() == 100UL);
    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    dump(0);
}

TEST_CASE("vmcs_host_cr0_protection_enable")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::host_cr0;

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

TEST_CASE("vmcs_host_cr0_monitor_coprocessor")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::host_cr0;

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

TEST_CASE("vmcs_host_cr0_emulation")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::host_cr0;

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

TEST_CASE("vmcs_host_cr0_task_switched")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::host_cr0;

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

TEST_CASE("vmcs_host_cr0_extension_type")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::host_cr0;

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

TEST_CASE("vmcs_host_cr0_numeric_error")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::host_cr0;

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

TEST_CASE("vmcs_host_cr0_write_protect")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::host_cr0;

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

TEST_CASE("vmcs_host_cr0_alignment_mask")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::host_cr0;

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

TEST_CASE("vmcs_host_cr0_not_write_through")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::host_cr0;

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

TEST_CASE("vmcs_host_cr0_cache_disable")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::host_cr0;

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

TEST_CASE("vmcs_host_cr0_paging")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::host_cr0;

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

TEST_CASE("vmcs_host_cr3")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::host_cr3;

    CHECK(exists());
    set(100UL);
    CHECK(get() == 100UL);
    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    dump(0);
}

TEST_CASE("vmcs_host_cr4")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::host_cr4;

    CHECK(exists());
    set(100UL);
    CHECK(get() == 100UL);
    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    dump(0);
}

TEST_CASE("vmcs_host_cr4_v8086_mode_extensions")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::host_cr4;

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

TEST_CASE("vmcs_host_cr4_protected_mode_virtual_interrupts")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::host_cr4;

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

TEST_CASE("vmcs_host_cr4_time_stamp_disable")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::host_cr4;

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

TEST_CASE("vmcs_host_cr4_debugging_extensions")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::host_cr4;

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

TEST_CASE("vmcs_host_cr4_page_size_extensions")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::host_cr4;

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

TEST_CASE("vmcs_host_cr4_physical_address_extensions")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::host_cr4;

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

TEST_CASE("vmcs_host_cr4_machine_check_enable")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::host_cr4;

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

TEST_CASE("vmcs_host_cr4_page_global_enable")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::host_cr4;

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

TEST_CASE("vmcs_host_cr4_performance_monitor_counter_enable")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::host_cr4;

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

TEST_CASE("vmcs_host_cr4_osfxsr")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::host_cr4;

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

TEST_CASE("vmcs_host_cr4_osxmmexcpt")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::host_cr4;

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

TEST_CASE("vmcs_host_cr4_vmx_enable_bit")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::host_cr4;

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

TEST_CASE("vmcs_host_cr4_smx_enable_bit")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::host_cr4;

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

TEST_CASE("vmcs_host_cr4_fsgsbase_enable_bit")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::host_cr4;

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

TEST_CASE("vmcs_host_cr4_pcid_enable_bit")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::host_cr4;

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

TEST_CASE("vmcs_host_cr4_osxsave")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::host_cr4;

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

TEST_CASE("vmcs_host_cr4_smep_enable_bit")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::host_cr4;

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

TEST_CASE("vmcs_host_cr4_smap_enable_bit")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::host_cr4;

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

TEST_CASE("vmcs_host_cr4_protection_key_enable_bit")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::host_cr4;

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

TEST_CASE("vmcs_host_fs_base")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::host_fs_base;

    CHECK(exists());
    set(100UL);
    CHECK(get() == 100UL);
    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    dump(0);
}

TEST_CASE("vmcs_host_gs_base")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::host_gs_base;

    CHECK(exists());
    set(100UL);
    CHECK(get() == 100UL);
    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    dump(0);
}

TEST_CASE("vmcs_host_tr_base")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::host_tr_base;

    CHECK(exists());
    set(100UL);
    CHECK(get() == 100UL);
    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    dump(0);
}

TEST_CASE("vmcs_host_gdtr_base")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::host_gdtr_base;

    CHECK(exists());
    set(100UL);
    CHECK(get() == 100UL);
    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    dump(0);
}

TEST_CASE("vmcs_host_idtr_base")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::host_idtr_base;

    CHECK(exists());
    set(100UL);
    CHECK(get() == 100UL);
    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    dump(0);
}

TEST_CASE("vmcs_host_ia32_sysenter_esp")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::host_ia32_sysenter_esp;

    CHECK(exists());
    set(100UL);
    CHECK(get() == 100UL);
    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    dump(0);
}

TEST_CASE("vmcs_host_ia32_sysenter_eip")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::host_ia32_sysenter_eip;

    CHECK(exists());
    set(100UL);
    CHECK(get() == 100UL);
    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    dump(0);
}

TEST_CASE("vmcs_host_rsp")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::host_rsp;

    CHECK(exists());
    set(100UL);
    CHECK(get() == 100UL);
    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    dump(0);
}

TEST_CASE("vmcs_host_rip")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::host_rip;

    CHECK(exists());
    set(100UL);
    CHECK(get() == 100UL);
    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    dump(0);
}

#endif
