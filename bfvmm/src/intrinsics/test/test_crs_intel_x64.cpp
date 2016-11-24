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
#include <intrinsics/crs_intel_x64.h>

using namespace intel_x64;

cr0::value_type g_cr0 = 0;
cr3::value_type g_cr3 = 0;
cr4::value_type g_cr4 = 0;

extern "C" uint64_t
__read_cr0(void) noexcept
{ return g_cr0; }

extern "C" void
__write_cr0(uint64_t val) noexcept
{ g_cr0 = val; }

extern "C" uint64_t
__read_cr3(void) noexcept
{ return g_cr3; }

extern "C" void
__write_cr3(uint64_t val) noexcept
{ g_cr3 = val; }

extern "C" uint64_t
__read_cr4(void) noexcept
{ return g_cr4; }

extern "C" void
__write_cr4(uint64_t val) noexcept
{ g_cr4 = val; }

void
intrinsics_ut::test_cr0_intel_x64()
{
    cr0::set(0xFFFFFFFFU);
    this->expect_true(cr0::get() == 0xFFFFFFFFU);

    cr0::dump();

    cr0::set(0x0U);
    this->expect_true(cr0::get() == 0x0U);
}

void
intrinsics_ut::test_cr0_intel_x64_protection_enable()
{
    cr0::protection_enable::set(true);
    this->expect_true(cr0::protection_enable::get());

    cr0::protection_enable::set(false);
    this->expect_false(cr0::protection_enable::get());

    this->expect_true(cr0::get() == 0x0);
}

void
intrinsics_ut::test_cr0_intel_x64_monitor_coprocessor()
{
    cr0::monitor_coprocessor::set(true);
    this->expect_true(cr0::monitor_coprocessor::get());

    cr0::monitor_coprocessor::set(false);
    this->expect_false(cr0::monitor_coprocessor::get());

    this->expect_true(cr0::get() == 0x0);
}

void
intrinsics_ut::test_cr0_intel_x64_emulation()
{
    cr0::emulation::set(true);
    this->expect_true(cr0::emulation::get());

    cr0::emulation::set(false);
    this->expect_false(cr0::emulation::get());

    this->expect_true(cr0::get() == 0x0);
}

void
intrinsics_ut::test_cr0_intel_x64_task_switched()
{
    cr0::task_switched::set(true);
    this->expect_true(cr0::task_switched::get());

    cr0::task_switched::set(false);
    this->expect_false(cr0::task_switched::get());

    this->expect_true(cr0::get() == 0x0);
}

void
intrinsics_ut::test_cr0_intel_x64_extension_type()
{
    cr0::extension_type::set(true);
    this->expect_true(cr0::extension_type::get());

    cr0::extension_type::set(false);
    this->expect_false(cr0::extension_type::get());

    this->expect_true(cr0::get() == 0x0);
}

void
intrinsics_ut::test_cr0_intel_x64_numeric_error()
{
    cr0::numeric_error::set(true);
    this->expect_true(cr0::numeric_error::get());

    cr0::numeric_error::set(false);
    this->expect_false(cr0::numeric_error::get());

    this->expect_true(cr0::get() == 0x0);
}

void
intrinsics_ut::test_cr0_intel_x64_write_protect()
{
    cr0::write_protect::set(true);
    this->expect_true(cr0::write_protect::get());

    cr0::write_protect::set(false);
    this->expect_false(cr0::write_protect::get());

    this->expect_true(cr0::get() == 0x0);
}

void
intrinsics_ut::test_cr0_intel_x64_alignment_mask()
{
    cr0::alignment_mask::set(true);
    this->expect_true(cr0::alignment_mask::get());

    cr0::alignment_mask::set(false);
    this->expect_false(cr0::alignment_mask::get());

    this->expect_true(cr0::get() == 0x0);
}

void
intrinsics_ut::test_cr0_intel_x64_not_write_through()
{
    cr0::not_write_through::set(true);
    this->expect_true(cr0::not_write_through::get());

    cr0::not_write_through::set(false);
    this->expect_false(cr0::not_write_through::get());

    this->expect_true(cr0::get() == 0x0);
}

void
intrinsics_ut::test_cr0_intel_x64_cache_disable()
{
    cr0::cache_disable::set(true);
    this->expect_true(cr0::cache_disable::get());

    cr0::cache_disable::set(false);
    this->expect_false(cr0::cache_disable::get());

    this->expect_true(cr0::get() == 0x0);
}

void
intrinsics_ut::test_cr0_intel_x64_paging()
{
    cr0::paging::set(true);
    this->expect_true(cr0::paging::get());

    cr0::paging::set(false);
    this->expect_false(cr0::paging::get());

    this->expect_true(cr0::get() == 0x0);
}

void
intrinsics_ut::test_cr3_intel_x64()
{
    cr3::set(0x100U);
    this->expect_true(cr3::get() == 0x100U);
}

void
intrinsics_ut::test_cr4_intel_x64()
{
    cr4::set(0xFFFFFFFFU);
    this->expect_true(cr4::get() == 0xFFFFFFFFU);

    cr4::dump();

    cr4::set(0x0U);
    this->expect_true(cr4::get() == 0x0U);
}

void
intrinsics_ut::test_cr4_intel_x64_v8086_mode_extensions()
{
    cr4::v8086_mode_extensions::set(true);
    this->expect_true(cr4::v8086_mode_extensions::get());

    cr4::v8086_mode_extensions::set(false);
    this->expect_false(cr4::v8086_mode_extensions::get());

    this->expect_true(cr4::get() == 0x0);
}

void
intrinsics_ut::test_cr4_intel_x64_protected_mode_virtual_interrupts()
{
    cr4::protected_mode_virtual_interrupts::set(true);
    this->expect_true(cr4::protected_mode_virtual_interrupts::get());

    cr4::protected_mode_virtual_interrupts::set(false);
    this->expect_false(cr4::protected_mode_virtual_interrupts::get());

    this->expect_true(cr4::get() == 0x0);
}

void
intrinsics_ut::test_cr4_intel_x64_time_stamp_disable()
{
    cr4::time_stamp_disable::set(true);
    this->expect_true(cr4::time_stamp_disable::get());

    cr4::time_stamp_disable::set(false);
    this->expect_false(cr4::time_stamp_disable::get());

    this->expect_true(cr4::get() == 0x0);
}

void
intrinsics_ut::test_cr4_intel_x64_debugging_extensions()
{
    cr4::debugging_extensions::set(true);
    this->expect_true(cr4::debugging_extensions::get());

    cr4::debugging_extensions::set(false);
    this->expect_false(cr4::debugging_extensions::get());

    this->expect_true(cr4::get() == 0x0);
}

void
intrinsics_ut::test_cr4_intel_x64_page_size_extensions()
{
    cr4::page_size_extensions::set(true);
    this->expect_true(cr4::page_size_extensions::get());

    cr4::page_size_extensions::set(false);
    this->expect_false(cr4::page_size_extensions::get());

    this->expect_true(cr4::get() == 0x0);
}

void
intrinsics_ut::test_cr4_intel_x64_physical_address_extensions()
{
    cr4::physical_address_extensions::set(true);
    this->expect_true(cr4::physical_address_extensions::get());

    cr4::physical_address_extensions::set(false);
    this->expect_false(cr4::physical_address_extensions::get());

    this->expect_true(cr4::get() == 0x0);
}

void
intrinsics_ut::test_cr4_intel_x64_machine_check_enable()
{
    cr4::machine_check_enable::set(true);
    this->expect_true(cr4::machine_check_enable::get());

    cr4::machine_check_enable::set(false);
    this->expect_false(cr4::machine_check_enable::get());

    this->expect_true(cr4::get() == 0x0);
}

void
intrinsics_ut::test_cr4_intel_x64_page_global_enable()
{
    cr4::page_global_enable::set(true);
    this->expect_true(cr4::page_global_enable::get());

    cr4::page_global_enable::set(false);
    this->expect_false(cr4::page_global_enable::get());

    this->expect_true(cr4::get() == 0x0);
}

void
intrinsics_ut::test_cr4_intel_x64_performance_monitor_counter_enable()
{
    cr4::performance_monitor_counter_enable::set(true);
    this->expect_true(cr4::performance_monitor_counter_enable::get());

    cr4::performance_monitor_counter_enable::set(false);
    this->expect_false(cr4::performance_monitor_counter_enable::get());

    this->expect_true(cr4::get() == 0x0);
}

void
intrinsics_ut::test_cr4_intel_x64_osfxsr()
{
    cr4::osfxsr::set(true);
    this->expect_true(cr4::osfxsr::get());

    cr4::osfxsr::set(false);
    this->expect_false(cr4::osfxsr::get());

    this->expect_true(cr4::get() == 0x0);
}

void
intrinsics_ut::test_cr4_intel_x64_osxmmexcpt()
{
    cr4::osxmmexcpt::set(true);
    this->expect_true(cr4::osxmmexcpt::get());

    cr4::osxmmexcpt::set(false);
    this->expect_false(cr4::osxmmexcpt::get());

    this->expect_true(cr4::get() == 0x0);
}

void
intrinsics_ut::test_cr4_intel_x64_vmx_enable_bit()
{
    cr4::vmx_enable_bit::set(true);
    this->expect_true(cr4::vmx_enable_bit::get());

    cr4::vmx_enable_bit::set(false);
    this->expect_false(cr4::vmx_enable_bit::get());

    this->expect_true(cr4::get() == 0x0);
}

void
intrinsics_ut::test_cr4_intel_x64_smx_enable_bit()
{
    cr4::smx_enable_bit::set(true);
    this->expect_true(cr4::smx_enable_bit::get());

    cr4::smx_enable_bit::set(false);
    this->expect_false(cr4::smx_enable_bit::get());

    this->expect_true(cr4::get() == 0x0);
}

void
intrinsics_ut::test_cr4_intel_x64_fsgsbase_enable_bit()
{
    cr4::fsgsbase_enable_bit::set(true);
    this->expect_true(cr4::fsgsbase_enable_bit::get());

    cr4::fsgsbase_enable_bit::set(false);
    this->expect_false(cr4::fsgsbase_enable_bit::get());

    this->expect_true(cr4::get() == 0x0);
}

void
intrinsics_ut::test_cr4_intel_x64_pcid_enable_bit()
{
    cr4::pcid_enable_bit::set(true);
    this->expect_true(cr4::pcid_enable_bit::get());

    cr4::pcid_enable_bit::set(false);
    this->expect_false(cr4::pcid_enable_bit::get());

    this->expect_true(cr4::get() == 0x0);
}

void
intrinsics_ut::test_cr4_intel_x64_osxsave()
{
    cr4::osxsave::set(true);
    this->expect_true(cr4::osxsave::get());

    cr4::osxsave::set(false);
    this->expect_false(cr4::osxsave::get());

    this->expect_true(cr4::get() == 0x0);
}

void
intrinsics_ut::test_cr4_intel_x64_smep_enable_bit()
{
    cr4::smep_enable_bit::set(true);
    this->expect_true(cr4::smep_enable_bit::get());

    cr4::smep_enable_bit::set(false);
    this->expect_false(cr4::smep_enable_bit::get());

    this->expect_true(cr4::get() == 0x0);
}

void
intrinsics_ut::test_cr4_intel_x64_smap_enable_bit()
{
    cr4::smap_enable_bit::set(true);
    this->expect_true(cr4::smap_enable_bit::get());

    cr4::smap_enable_bit::set(false);
    this->expect_false(cr4::smap_enable_bit::get());

    this->expect_true(cr4::get() == 0x0);
}

void
intrinsics_ut::test_cr4_intel_x64_protection_key_enable_bit()
{
    cr4::protection_key_enable_bit::set(true);
    this->expect_true(cr4::protection_key_enable_bit::get());

    cr4::protection_key_enable_bit::set(false);
    this->expect_false(cr4::protection_key_enable_bit::get());

    this->expect_true(cr4::get() == 0x0);
}
