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
#include <intrinsics.h>

using namespace intel_x64;

cr0::value_type g_cr0 = 0;
cr2::value_type g_cr2 = 0;
cr3::value_type g_cr3 = 0;
cr4::value_type g_cr4 = 0;
cr8::value_type g_cr8 = 0;

extern "C" uint64_t
_read_cr0() noexcept
{ return g_cr0; }

extern "C" void
_write_cr0(uint64_t val) noexcept
{ g_cr0 = val; }

extern "C" uint64_t
_read_cr2() noexcept
{ return g_cr2; }

extern "C" void
_write_cr2(uint64_t val) noexcept
{ g_cr2 = val; }

extern "C" uint64_t
_read_cr3() noexcept
{ return g_cr3; }

extern "C" void
_write_cr3(uint64_t val) noexcept
{ g_cr3 = val; }

extern "C" uint64_t
_read_cr4() noexcept
{ return g_cr4; }

extern "C" void
_write_cr4(uint64_t val) noexcept
{ g_cr4 = val; }

extern "C" uint64_t
_read_cr8() noexcept
{ return g_cr8; }

extern "C" void
_write_cr8(uint64_t val) noexcept
{ g_cr8 = val; }

TEST_CASE("cr0")
{
    using namespace cr0;

    set(0xFFFFFFFFU);
    CHECK(get() == 0xFFFFFFFFU);
    dump(0);
}

TEST_CASE("cr0_protection_enable")
{
    using namespace cr0;

    protection_enable::enable();
    CHECK(protection_enable::is_enabled());
    protection_enable::disable();
    CHECK(protection_enable::is_disabled());

    protection_enable::enable(protection_enable::mask);
    CHECK(protection_enable::is_enabled(protection_enable::mask));
    protection_enable::disable(0x0);
    CHECK(protection_enable::is_disabled(0x0));
}

TEST_CASE("cr0_monitor_coprocessor")
{
    using namespace cr0;

    monitor_coprocessor::enable();
    CHECK(monitor_coprocessor::is_enabled());
    monitor_coprocessor::disable();
    CHECK(monitor_coprocessor::is_disabled());

    monitor_coprocessor::enable(monitor_coprocessor::mask);
    CHECK(monitor_coprocessor::is_enabled(monitor_coprocessor::mask));
    monitor_coprocessor::disable(0x0);
    CHECK(monitor_coprocessor::is_disabled(0x0));
}

TEST_CASE("cr0_emulation")
{
    using namespace cr0;

    emulation::enable();
    CHECK(emulation::is_enabled());
    emulation::disable();
    CHECK(emulation::is_disabled());

    emulation::enable(emulation::mask);
    CHECK(emulation::is_enabled(emulation::mask));
    emulation::disable(0x0);
    CHECK(emulation::is_disabled(0x0));
}

TEST_CASE("cr0_task_switched")
{
    using namespace cr0;

    task_switched::enable();
    CHECK(task_switched::is_enabled());
    task_switched::disable();
    CHECK(task_switched::is_disabled());

    task_switched::enable(task_switched::mask);
    CHECK(task_switched::is_enabled(task_switched::mask));
    task_switched::disable(0x0);
    CHECK(task_switched::is_disabled(0x0));
}

TEST_CASE("cr0_extension_type")
{
    using namespace cr0;

    extension_type::enable();
    CHECK(extension_type::is_enabled());
    extension_type::disable();
    CHECK(extension_type::is_disabled());

    extension_type::enable(extension_type::mask);
    CHECK(extension_type::is_enabled(extension_type::mask));
    extension_type::disable(0x0);
    CHECK(extension_type::is_disabled(0x0));
}

TEST_CASE("cr0_numeric_error")
{
    using namespace cr0;

    numeric_error::enable();
    CHECK(numeric_error::is_enabled());
    numeric_error::disable();
    CHECK(numeric_error::is_disabled());

    numeric_error::enable(numeric_error::mask);
    CHECK(numeric_error::is_enabled(numeric_error::mask));
    numeric_error::disable(0x0);
    CHECK(numeric_error::is_disabled(0x0));
}

TEST_CASE("cr0_write_protect")
{
    using namespace cr0;

    write_protect::enable();
    CHECK(write_protect::is_enabled());
    write_protect::disable();
    CHECK(write_protect::is_disabled());

    write_protect::enable(write_protect::mask);
    CHECK(write_protect::is_enabled(write_protect::mask));
    write_protect::disable(0x0);
    CHECK(write_protect::is_disabled(0x0));
}

TEST_CASE("cr0_alignment_mask")
{
    using namespace cr0;

    alignment_mask::enable();
    CHECK(alignment_mask::is_enabled());
    alignment_mask::disable();
    CHECK(alignment_mask::is_disabled());

    alignment_mask::enable(alignment_mask::mask);
    CHECK(alignment_mask::is_enabled(alignment_mask::mask));
    alignment_mask::disable(0x0);
    CHECK(alignment_mask::is_disabled(0x0));
}

TEST_CASE("cr0_not_write_through")
{
    using namespace cr0;

    not_write_through::enable();
    CHECK(not_write_through::is_enabled());
    not_write_through::disable();
    CHECK(not_write_through::is_disabled());

    not_write_through::enable(not_write_through::mask);
    CHECK(not_write_through::is_enabled(not_write_through::mask));
    not_write_through::disable(0x0);
    CHECK(not_write_through::is_disabled(0x0));
}

TEST_CASE("cr0_cache_disable")
{
    using namespace cr0;

    cache_disable::enable();
    CHECK(cache_disable::is_enabled());
    cache_disable::disable();
    CHECK(cache_disable::is_disabled());

    cache_disable::enable(cache_disable::mask);
    CHECK(cache_disable::is_enabled(cache_disable::mask));
    cache_disable::disable(0x0);
    CHECK(cache_disable::is_disabled(0x0));
}

TEST_CASE("cr0_paging")
{
    using namespace cr0;

    paging::enable();
    CHECK(paging::is_enabled());
    paging::disable();
    CHECK(paging::is_disabled());

    paging::enable(paging::mask);
    CHECK(paging::is_enabled(paging::mask));
    paging::disable(0x0);
    CHECK(paging::is_disabled(0x0));
}

TEST_CASE("cr2")
{
    using namespace cr2;

    set(0xFFFFFFFFU);
    CHECK(get() == 0xFFFFFFFFU);
    dump(0);
}

TEST_CASE("cr3")
{
    using namespace cr3;

    set(0xFFFFFFFFU);
    CHECK(get() == 0xFFFFFFFFU);
    dump(0);
}

TEST_CASE("cr4")
{
    using namespace cr4;

    set(0xFFFFFFFFU);
    CHECK(get() == 0xFFFFFFFFU);
    dump(0);
}

TEST_CASE("cr4_v8086_mode_extensions")
{
    using namespace cr4;

    v8086_mode_extensions::enable();
    CHECK(v8086_mode_extensions::is_enabled());
    v8086_mode_extensions::disable();
    CHECK(v8086_mode_extensions::is_disabled());

    v8086_mode_extensions::enable(v8086_mode_extensions::mask);
    CHECK(v8086_mode_extensions::is_enabled(v8086_mode_extensions::mask));
    v8086_mode_extensions::disable(0x0);
    CHECK(v8086_mode_extensions::is_disabled(0x0));
}

TEST_CASE("cr4_protected_mode_virtual_interrupts")
{
    using namespace cr4;

    protected_mode_virtual_interrupts::enable();
    CHECK(protected_mode_virtual_interrupts::is_enabled());
    protected_mode_virtual_interrupts::disable();
    CHECK(protected_mode_virtual_interrupts::is_disabled());

    protected_mode_virtual_interrupts::enable(protected_mode_virtual_interrupts::mask);
    CHECK(protected_mode_virtual_interrupts::is_enabled(protected_mode_virtual_interrupts::mask));
    protected_mode_virtual_interrupts::disable(0x0);
    CHECK(protected_mode_virtual_interrupts::is_disabled(0x0));
}

TEST_CASE("cr4_time_stamp_disable")
{
    using namespace cr4;

    time_stamp_disable::enable();
    CHECK(time_stamp_disable::is_enabled());
    time_stamp_disable::disable();
    CHECK(time_stamp_disable::is_disabled());

    time_stamp_disable::enable(time_stamp_disable::mask);
    CHECK(time_stamp_disable::is_enabled(time_stamp_disable::mask));
    time_stamp_disable::disable(0x0);
    CHECK(time_stamp_disable::is_disabled(0x0));
}

TEST_CASE("cr4_debugging_extensions")
{
    using namespace cr4;

    debugging_extensions::enable();
    CHECK(debugging_extensions::is_enabled());
    debugging_extensions::disable();
    CHECK(debugging_extensions::is_disabled());

    debugging_extensions::enable(debugging_extensions::mask);
    CHECK(debugging_extensions::is_enabled(debugging_extensions::mask));
    debugging_extensions::disable(0x0);
    CHECK(debugging_extensions::is_disabled(0x0));
}

TEST_CASE("cr4_page_size_extensions")
{
    using namespace cr4;

    page_size_extensions::enable();
    CHECK(page_size_extensions::is_enabled());
    page_size_extensions::disable();
    CHECK(page_size_extensions::is_disabled());

    page_size_extensions::enable(page_size_extensions::mask);
    CHECK(page_size_extensions::is_enabled(page_size_extensions::mask));
    page_size_extensions::disable(0x0);
    CHECK(page_size_extensions::is_disabled(0x0));
}

TEST_CASE("cr4_physical_address_extensions")
{
    using namespace cr4;

    physical_address_extensions::enable();
    CHECK(physical_address_extensions::is_enabled());
    physical_address_extensions::disable();
    CHECK(physical_address_extensions::is_disabled());

    physical_address_extensions::enable(physical_address_extensions::mask);
    CHECK(physical_address_extensions::is_enabled(physical_address_extensions::mask));
    physical_address_extensions::disable(0x0);
    CHECK(physical_address_extensions::is_disabled(0x0));
}

TEST_CASE("cr4_machine_check_enable")
{
    using namespace cr4;

    machine_check_enable::enable();
    CHECK(machine_check_enable::is_enabled());
    machine_check_enable::disable();
    CHECK(machine_check_enable::is_disabled());

    machine_check_enable::enable(machine_check_enable::mask);
    CHECK(machine_check_enable::is_enabled(machine_check_enable::mask));
    machine_check_enable::disable(0x0);
    CHECK(machine_check_enable::is_disabled(0x0));
}

TEST_CASE("cr4_page_global_enable")
{
    using namespace cr4;

    page_global_enable::enable();
    CHECK(page_global_enable::is_enabled());
    page_global_enable::disable();
    CHECK(page_global_enable::is_disabled());

    page_global_enable::enable(page_global_enable::mask);
    CHECK(page_global_enable::is_enabled(page_global_enable::mask));
    page_global_enable::disable(0x0);
    CHECK(page_global_enable::is_disabled(0x0));
}

TEST_CASE("cr4_performance_monitor_counter_enable")
{
    using namespace cr4;

    performance_monitor_counter_enable::enable();
    CHECK(performance_monitor_counter_enable::is_enabled());
    performance_monitor_counter_enable::disable();
    CHECK(performance_monitor_counter_enable::is_disabled());

    performance_monitor_counter_enable::enable(performance_monitor_counter_enable::mask);
    CHECK(performance_monitor_counter_enable::is_enabled(performance_monitor_counter_enable::mask));
    performance_monitor_counter_enable::disable(0x0);
    CHECK(performance_monitor_counter_enable::is_disabled(0x0));
}

TEST_CASE("cr4_osfxsr")
{
    using namespace cr4;

    osfxsr::enable();
    CHECK(osfxsr::is_enabled());
    osfxsr::disable();
    CHECK(osfxsr::is_disabled());

    osfxsr::enable(osfxsr::mask);
    CHECK(osfxsr::is_enabled(osfxsr::mask));
    osfxsr::disable(0x0);
    CHECK(osfxsr::is_disabled(0x0));
}

TEST_CASE("cr4_osxmmexcpt")
{
    using namespace cr4;

    osxmmexcpt::enable();
    CHECK(osxmmexcpt::is_enabled());
    osxmmexcpt::disable();
    CHECK(osxmmexcpt::is_disabled());

    osxmmexcpt::enable(osxmmexcpt::mask);
    CHECK(osxmmexcpt::is_enabled(osxmmexcpt::mask));
    osxmmexcpt::disable(0x0);
    CHECK(osxmmexcpt::is_disabled(0x0));
}

TEST_CASE("cr4_vmx_enable_bit")
{
    using namespace cr4;

    vmx_enable_bit::enable();
    CHECK(vmx_enable_bit::is_enabled());
    vmx_enable_bit::disable();
    CHECK(vmx_enable_bit::is_disabled());

    vmx_enable_bit::enable(vmx_enable_bit::mask);
    CHECK(vmx_enable_bit::is_enabled(vmx_enable_bit::mask));
    vmx_enable_bit::disable(0x0);
    CHECK(vmx_enable_bit::is_disabled(0x0));
}

TEST_CASE("cr4_smx_enable_bit")
{
    using namespace cr4;

    smx_enable_bit::enable();
    CHECK(smx_enable_bit::is_enabled());
    smx_enable_bit::disable();
    CHECK(smx_enable_bit::is_disabled());

    smx_enable_bit::enable(smx_enable_bit::mask);
    CHECK(smx_enable_bit::is_enabled(smx_enable_bit::mask));
    smx_enable_bit::disable(0x0);
    CHECK(smx_enable_bit::is_disabled(0x0));
}

TEST_CASE("cr4_fsgsbase_enable_bit")
{
    using namespace cr4;

    fsgsbase_enable_bit::enable();
    CHECK(fsgsbase_enable_bit::is_enabled());
    fsgsbase_enable_bit::disable();
    CHECK(fsgsbase_enable_bit::is_disabled());

    fsgsbase_enable_bit::enable(fsgsbase_enable_bit::mask);
    CHECK(fsgsbase_enable_bit::is_enabled(fsgsbase_enable_bit::mask));
    fsgsbase_enable_bit::disable(0x0);
    CHECK(fsgsbase_enable_bit::is_disabled(0x0));
}

TEST_CASE("cr4_pcid_enable_bit")
{
    using namespace cr4;

    pcid_enable_bit::enable();
    CHECK(pcid_enable_bit::is_enabled());
    pcid_enable_bit::disable();
    CHECK(pcid_enable_bit::is_disabled());

    pcid_enable_bit::enable(pcid_enable_bit::mask);
    CHECK(pcid_enable_bit::is_enabled(pcid_enable_bit::mask));
    pcid_enable_bit::disable(0x0);
    CHECK(pcid_enable_bit::is_disabled(0x0));
}

TEST_CASE("cr4_osxsave")
{
    using namespace cr4;

    osxsave::enable();
    CHECK(osxsave::is_enabled());
    osxsave::disable();
    CHECK(osxsave::is_disabled());

    osxsave::enable(osxsave::mask);
    CHECK(osxsave::is_enabled(osxsave::mask));
    osxsave::disable(0x0);
    CHECK(osxsave::is_disabled(0x0));
}

TEST_CASE("cr4_smep_enable_bit")
{
    using namespace cr4;

    smep_enable_bit::enable();
    CHECK(smep_enable_bit::is_enabled());
    smep_enable_bit::disable();
    CHECK(smep_enable_bit::is_disabled());

    smep_enable_bit::enable(smep_enable_bit::mask);
    CHECK(smep_enable_bit::is_enabled(smep_enable_bit::mask));
    smep_enable_bit::disable(0x0);
    CHECK(smep_enable_bit::is_disabled(0x0));
}

TEST_CASE("cr4_smap_enable_bit")
{
    using namespace cr4;

    smap_enable_bit::enable();
    CHECK(smap_enable_bit::is_enabled());
    smap_enable_bit::disable();
    CHECK(smap_enable_bit::is_disabled());

    smap_enable_bit::enable(smap_enable_bit::mask);
    CHECK(smap_enable_bit::is_enabled(smap_enable_bit::mask));
    smap_enable_bit::disable(0x0);
    CHECK(smap_enable_bit::is_disabled(0x0));
}

TEST_CASE("cr4_protection_key_enable_bit")
{
    using namespace cr4;

    protection_key_enable_bit::enable();
    CHECK(protection_key_enable_bit::is_enabled());
    protection_key_enable_bit::disable();
    CHECK(protection_key_enable_bit::is_disabled());

    protection_key_enable_bit::enable(protection_key_enable_bit::mask);
    CHECK(protection_key_enable_bit::is_enabled(protection_key_enable_bit::mask));
    protection_key_enable_bit::disable(0x0);
    CHECK(protection_key_enable_bit::is_disabled(0x0));
}

TEST_CASE("cr8")
{
    using namespace cr8;

    set(0xFFFFFFFFU);
    CHECK(get() == 0xFFFFFFFFU);
    dump(0);
}
