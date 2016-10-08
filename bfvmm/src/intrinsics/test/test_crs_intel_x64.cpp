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

uint64_t g_cr0 = 0;
uint64_t g_cr3 = 0;
uint64_t g_cr4 = 0;

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
intrinsics_ut::test_cr0()
{
    cr0::set(100UL);
    this->expect_true(cr0::get() == 100UL);
}

void
intrinsics_ut::test_cr0_protection_enable()
{
    cr0::protection_enable::set(1UL);
    this->expect_true(cr0::protection_enable::get() == 1UL);
}

void
intrinsics_ut::test_cr0_monitor_coprocessor()
{
    cr0::monitor_coprocessor::set(1UL);
    this->expect_true(cr0::monitor_coprocessor::get() == 1UL);
}

void
intrinsics_ut::test_cr0_emulation()
{
    cr0::emulation::set(1UL);
    this->expect_true(cr0::emulation::get() == 1UL);
}

void
intrinsics_ut::test_cr0_task_switched()
{
    cr0::task_switched::set(1UL);
    this->expect_true(cr0::task_switched::get() == 1UL);
}

void
intrinsics_ut::test_cr0_extension_type()
{
    cr0::extension_type::set(1UL);
    this->expect_true(cr0::extension_type::get() == 1UL);
}

void
intrinsics_ut::test_cr0_numeric_error()
{
    cr0::numeric_error::set(1UL);
    this->expect_true(cr0::numeric_error::get() == 1UL);
}

void
intrinsics_ut::test_cr0_write_protect()
{
    cr0::write_protect::set(1UL);
    this->expect_true(cr0::write_protect::get() == 1UL);
}

void
intrinsics_ut::test_cr0_alignment_mask()
{
    cr0::alignment_mask::set(1UL);
    this->expect_true(cr0::alignment_mask::get() == 1UL);
}

void
intrinsics_ut::test_cr0_not_write_through()
{
    cr0::not_write_through::set(1UL);
    this->expect_true(cr0::not_write_through::get() == 1UL);
}

void
intrinsics_ut::test_cr0_cache_disable()
{
    cr0::cache_disable::set(1UL);
    this->expect_true(cr0::cache_disable::get() == 1UL);
}

void
intrinsics_ut::test_cr0_paging()
{
    cr0::paging::set(1UL);
    this->expect_true(cr0::paging::get() == 1UL);
}

void
intrinsics_ut::test_cr3()
{
    cr3::set(100UL);
    this->expect_true(cr3::get() == 100UL);
}

void
intrinsics_ut::test_cr4()
{
    cr4::set(100UL);
    this->expect_true(cr4::get() == 100UL);
}

void
intrinsics_ut::test_cr4_v8086_mode_extensions()
{
    cr4::v8086_mode_extensions::set(1UL);
    this->expect_true(cr4::v8086_mode_extensions::get() == 1UL);
}

void
intrinsics_ut::test_cr4_protected_mode_virtual_interrupts()
{
    cr4::protected_mode_virtual_interrupts::set(1UL);
    this->expect_true(cr4::protected_mode_virtual_interrupts::get() == 1UL);
}

void
intrinsics_ut::test_cr4_time_stamp_disable()
{
    cr4::time_stamp_disable::set(1UL);
    this->expect_true(cr4::time_stamp_disable::get() == 1UL);
}

void
intrinsics_ut::test_cr4_debugging_extensions()
{
    cr4::debugging_extensions::set(1UL);
    this->expect_true(cr4::debugging_extensions::get() == 1UL);
}

void
intrinsics_ut::test_cr4_page_size_extensions()
{
    cr4::page_size_extensions::set(1UL);
    this->expect_true(cr4::page_size_extensions::get() == 1UL);
}

void
intrinsics_ut::test_cr4_physical_address_extensions()
{
    cr4::physical_address_extensions::set(1UL);
    this->expect_true(cr4::physical_address_extensions::get() == 1UL);
}

void
intrinsics_ut::test_cr4_machine_check_enable()
{
    cr4::machine_check_enable::set(1UL);
    this->expect_true(cr4::machine_check_enable::get() == 1UL);
}

void
intrinsics_ut::test_cr4_page_global_enable()
{
    cr4::page_global_enable::set(1UL);
    this->expect_true(cr4::page_global_enable::get() == 1UL);
}

void
intrinsics_ut::test_cr4_performance_monitor_counter_enable()
{
    cr4::performance_monitor_counter_enable::set(1UL);
    this->expect_true(cr4::performance_monitor_counter_enable::get() == 1UL);
}

void
intrinsics_ut::test_cr4_osfxsr()
{
    cr4::osfxsr::set(1UL);
    this->expect_true(cr4::osfxsr::get() == 1UL);
}

void
intrinsics_ut::test_cr4_osxmmexcpt()
{
    cr4::osxmmexcpt::set(1UL);
    this->expect_true(cr4::osxmmexcpt::get() == 1UL);
}

void
intrinsics_ut::test_cr4_vmx_enable_bit()
{
    cr4::vmx_enable_bit::set(1UL);
    this->expect_true(cr4::vmx_enable_bit::get() == 1UL);
}

void
intrinsics_ut::test_cr4_smx_enable_bit()
{
    cr4::smx_enable_bit::set(1UL);
    this->expect_true(cr4::smx_enable_bit::get() == 1UL);
}

void
intrinsics_ut::test_cr4_fsgsbase_enable_bit()
{
    cr4::fsgsbase_enable_bit::set(1UL);
    this->expect_true(cr4::fsgsbase_enable_bit::get() == 1UL);
}

void
intrinsics_ut::test_cr4_pcid_enable_bit()
{
    cr4::pcid_enable_bit::set(1UL);
    this->expect_true(cr4::pcid_enable_bit::get() == 1UL);
}

void
intrinsics_ut::test_cr4_osxsave()
{
    cr4::osxsave::set(1UL);
    this->expect_true(cr4::osxsave::get() == 1UL);
}

void
intrinsics_ut::test_cr4_smep_enable_bit()
{
    cr4::smep_enable_bit::set(1UL);
    this->expect_true(cr4::smep_enable_bit::get() == 1UL);
}

void
intrinsics_ut::test_cr4_smap_enable_bit()
{
    cr4::smap_enable_bit::set(1UL);
    this->expect_true(cr4::smap_enable_bit::get() == 1UL);
}

void
intrinsics_ut::test_cr4_protection_key_enable_bit()
{
    cr4::protection_key_enable_bit::set(1UL);
    this->expect_true(cr4::protection_key_enable_bit::get() == 1UL);
}
