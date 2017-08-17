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
#include <hippomocks.h>
#include <intrinsics/x86/intel_x64.h>

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

using namespace intel_x64;

cr0::value_type g_cr0 = 0;
cr2::value_type g_cr2 = 0;
cr3::value_type g_cr3 = 0;
cr4::value_type g_cr4 = 0;
cr8::value_type g_cr8 = 0;

uint64_t
test_read_cr0() noexcept
{ return g_cr0; }

void
test_write_cr0(uint64_t val) noexcept
{ g_cr0 = val; }

uint64_t
test_read_cr2() noexcept
{ return g_cr2; }

void
test_write_cr2(uint64_t val) noexcept
{ g_cr2 = val; }

uint64_t
test_read_cr3() noexcept
{ return g_cr3; }

void
test_write_cr3(uint64_t val) noexcept
{ g_cr3 = val; }

uint64_t
test_read_cr4() noexcept
{ return g_cr4; }

void
test_write_cr4(uint64_t val) noexcept
{ g_cr4 = val; }

uint64_t
test_read_cr8() noexcept
{ return g_cr8; }

void
test_write_cr8(uint64_t val) noexcept
{ g_cr8 = val; }

void
setup_intrinsics(MockRepository &mocks)
{
    mocks.OnCallFunc(_read_cr0).Do(test_read_cr0);
    mocks.OnCallFunc(_write_cr0).Do(test_write_cr0);
    mocks.OnCallFunc(_read_cr2).Do(test_read_cr2);
    mocks.OnCallFunc(_write_cr2).Do(test_write_cr2);
    mocks.OnCallFunc(_read_cr3).Do(test_read_cr3);
    mocks.OnCallFunc(_write_cr3).Do(test_write_cr3);
    mocks.OnCallFunc(_read_cr4).Do(test_read_cr4);
    mocks.OnCallFunc(_write_cr4).Do(test_write_cr4);
    mocks.OnCallFunc(_read_cr8).Do(test_read_cr8);
    mocks.OnCallFunc(_write_cr8).Do(test_write_cr8);
}

TEST_CASE("cr0_intel_x64")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    cr0::set(0xFFFFFFFFU);
    CHECK(cr0::get() == 0xFFFFFFFFU);

    cr0::dump();

    cr0::set(0x0U);
    CHECK(cr0::get() == 0x0U);
}

TEST_CASE("cr0_intel_x64_protection_enable")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    cr0::protection_enable::set(true);
    CHECK(cr0::protection_enable::get());

    cr0::protection_enable::set(false);
    CHECK_FALSE(cr0::protection_enable::get());

    CHECK(cr0::get() == 0x0);
}

TEST_CASE("cr0_intel_x64_monitor_coprocessor")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    cr0::monitor_coprocessor::set(true);
    CHECK(cr0::monitor_coprocessor::get());

    cr0::monitor_coprocessor::set(false);
    CHECK_FALSE(cr0::monitor_coprocessor::get());

    CHECK(cr0::get() == 0x0);
}

TEST_CASE("cr0_intel_x64_emulation")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    cr0::emulation::set(true);
    CHECK(cr0::emulation::get());

    cr0::emulation::set(false);
    CHECK_FALSE(cr0::emulation::get());

    CHECK(cr0::get() == 0x0);
}

TEST_CASE("cr0_intel_x64_task_switched")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    cr0::task_switched::set(true);
    CHECK(cr0::task_switched::get());

    cr0::task_switched::set(false);
    CHECK_FALSE(cr0::task_switched::get());

    CHECK(cr0::get() == 0x0);
}

TEST_CASE("cr0_intel_x64_extension_type")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    cr0::extension_type::set(true);
    CHECK(cr0::extension_type::get());

    cr0::extension_type::set(false);
    CHECK_FALSE(cr0::extension_type::get());

    CHECK(cr0::get() == 0x0);
}

TEST_CASE("cr0_intel_x64_numeric_error")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    cr0::numeric_error::set(true);
    CHECK(cr0::numeric_error::get());

    cr0::numeric_error::set(false);
    CHECK_FALSE(cr0::numeric_error::get());

    CHECK(cr0::get() == 0x0);
}

TEST_CASE("cr0_intel_x64_write_protect")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    cr0::write_protect::set(true);
    CHECK(cr0::write_protect::get());

    cr0::write_protect::set(false);
    CHECK_FALSE(cr0::write_protect::get());

    CHECK(cr0::get() == 0x0);
}

TEST_CASE("cr0_intel_x64_alignment_mask")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    cr0::alignment_mask::set(true);
    CHECK(cr0::alignment_mask::get());

    cr0::alignment_mask::set(false);
    CHECK_FALSE(cr0::alignment_mask::get());

    CHECK(cr0::get() == 0x0);
}

TEST_CASE("cr0_intel_x64_not_write_through")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    cr0::not_write_through::set(true);
    CHECK(cr0::not_write_through::get());

    cr0::not_write_through::set(false);
    CHECK_FALSE(cr0::not_write_through::get());

    CHECK(cr0::get() == 0x0);
}

TEST_CASE("cr0_intel_x64_cache_disable")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    cr0::cache_disable::set(true);
    CHECK(cr0::cache_disable::get());

    cr0::cache_disable::set(false);
    CHECK_FALSE(cr0::cache_disable::get());

    CHECK(cr0::get() == 0x0);
}

TEST_CASE("cr0_intel_x64_paging")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    cr0::paging::set(true);
    CHECK(cr0::paging::get());

    cr0::paging::set(false);
    CHECK_FALSE(cr0::paging::get());

    CHECK(cr0::get() == 0x0);
}

TEST_CASE("cr2_intel_x64")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    cr2::set(0x100U);
    CHECK(cr2::get() == 0x100U);
}

TEST_CASE("cr3_intel_x64")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    cr3::set(0x100U);
    CHECK(cr3::get() == 0x100U);
}

TEST_CASE("cr4_intel_x64")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    cr4::set(0xFFFFFFFFU);
    CHECK(cr4::get() == 0xFFFFFFFFU);

    cr4::dump();

    cr4::set(0x0U);
    CHECK(cr4::get() == 0x0U);
}

TEST_CASE("cr4_intel_x64_v8086_mode_extensions")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    cr4::v8086_mode_extensions::set(true);
    CHECK(cr4::v8086_mode_extensions::get());

    cr4::v8086_mode_extensions::set(false);
    CHECK_FALSE(cr4::v8086_mode_extensions::get());

    CHECK(cr4::get() == 0x0);
}

TEST_CASE("cr4_intel_x64_protected_mode_virtual_interrupts")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    cr4::protected_mode_virtual_interrupts::set(true);
    CHECK(cr4::protected_mode_virtual_interrupts::get());

    cr4::protected_mode_virtual_interrupts::set(false);
    CHECK_FALSE(cr4::protected_mode_virtual_interrupts::get());

    CHECK(cr4::get() == 0x0);
}

TEST_CASE("cr4_intel_x64_time_stamp_disable")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    cr4::time_stamp_disable::set(true);
    CHECK(cr4::time_stamp_disable::get());

    cr4::time_stamp_disable::set(false);
    CHECK_FALSE(cr4::time_stamp_disable::get());

    CHECK(cr4::get() == 0x0);
}

TEST_CASE("cr4_intel_x64_debugging_extensions")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    cr4::debugging_extensions::set(true);
    CHECK(cr4::debugging_extensions::get());

    cr4::debugging_extensions::set(false);
    CHECK_FALSE(cr4::debugging_extensions::get());

    CHECK(cr4::get() == 0x0);
}

TEST_CASE("cr4_intel_x64_page_size_extensions")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    cr4::page_size_extensions::set(true);
    CHECK(cr4::page_size_extensions::get());

    cr4::page_size_extensions::set(false);
    CHECK_FALSE(cr4::page_size_extensions::get());

    CHECK(cr4::get() == 0x0);
}

TEST_CASE("cr4_intel_x64_physical_address_extensions")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    cr4::physical_address_extensions::set(true);
    CHECK(cr4::physical_address_extensions::get());

    cr4::physical_address_extensions::set(false);
    CHECK_FALSE(cr4::physical_address_extensions::get());

    CHECK(cr4::get() == 0x0);
}

TEST_CASE("cr4_intel_x64_machine_check_enable")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    cr4::machine_check_enable::set(true);
    CHECK(cr4::machine_check_enable::get());

    cr4::machine_check_enable::set(false);
    CHECK_FALSE(cr4::machine_check_enable::get());

    CHECK(cr4::get() == 0x0);
}

TEST_CASE("cr4_intel_x64_page_global_enable")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    cr4::page_global_enable::set(true);
    CHECK(cr4::page_global_enable::get());

    cr4::page_global_enable::set(false);
    CHECK_FALSE(cr4::page_global_enable::get());

    CHECK(cr4::get() == 0x0);
}

TEST_CASE("cr4_intel_x64_performance_monitor_counter_enable")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    cr4::performance_monitor_counter_enable::set(true);
    CHECK(cr4::performance_monitor_counter_enable::get());

    cr4::performance_monitor_counter_enable::set(false);
    CHECK_FALSE(cr4::performance_monitor_counter_enable::get());

    CHECK(cr4::get() == 0x0);
}

TEST_CASE("cr4_intel_x64_osfxsr")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    cr4::osfxsr::set(true);
    CHECK(cr4::osfxsr::get());

    cr4::osfxsr::set(false);
    CHECK_FALSE(cr4::osfxsr::get());

    CHECK(cr4::get() == 0x0);
}

TEST_CASE("cr4_intel_x64_osxmmexcpt")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    cr4::osxmmexcpt::set(true);
    CHECK(cr4::osxmmexcpt::get());

    cr4::osxmmexcpt::set(false);
    CHECK_FALSE(cr4::osxmmexcpt::get());

    CHECK(cr4::get() == 0x0);
}

TEST_CASE("cr4_intel_x64_vmx_enable_bit")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    cr4::vmx_enable_bit::set(true);
    CHECK(cr4::vmx_enable_bit::get());

    cr4::vmx_enable_bit::set(false);
    CHECK_FALSE(cr4::vmx_enable_bit::get());

    CHECK(cr4::get() == 0x0);
}

TEST_CASE("cr4_intel_x64_smx_enable_bit")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    cr4::smx_enable_bit::set(true);
    CHECK(cr4::smx_enable_bit::get());

    cr4::smx_enable_bit::set(false);
    CHECK_FALSE(cr4::smx_enable_bit::get());

    CHECK(cr4::get() == 0x0);
}

TEST_CASE("cr4_intel_x64_fsgsbase_enable_bit")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    cr4::fsgsbase_enable_bit::set(true);
    CHECK(cr4::fsgsbase_enable_bit::get());

    cr4::fsgsbase_enable_bit::set(false);
    CHECK_FALSE(cr4::fsgsbase_enable_bit::get());

    CHECK(cr4::get() == 0x0);
}

TEST_CASE("cr4_intel_x64_pcid_enable_bit")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    cr4::pcid_enable_bit::set(true);
    CHECK(cr4::pcid_enable_bit::get());

    cr4::pcid_enable_bit::set(false);
    CHECK_FALSE(cr4::pcid_enable_bit::get());

    CHECK(cr4::get() == 0x0);
}

TEST_CASE("cr4_intel_x64_osxsave")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    cr4::osxsave::set(true);
    CHECK(cr4::osxsave::get());

    cr4::osxsave::set(false);
    CHECK_FALSE(cr4::osxsave::get());

    CHECK(cr4::get() == 0x0);
}

TEST_CASE("cr4_intel_x64_smep_enable_bit")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    cr4::smep_enable_bit::set(true);
    CHECK(cr4::smep_enable_bit::get());

    cr4::smep_enable_bit::set(false);
    CHECK_FALSE(cr4::smep_enable_bit::get());

    CHECK(cr4::get() == 0x0);
}

TEST_CASE("cr4_intel_x64_smap_enable_bit")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    cr4::smap_enable_bit::set(true);
    CHECK(cr4::smap_enable_bit::get());

    cr4::smap_enable_bit::set(false);
    CHECK_FALSE(cr4::smap_enable_bit::get());

    CHECK(cr4::get() == 0x0);
}

TEST_CASE("cr4_intel_x64_protection_key_enable_bit")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    cr4::protection_key_enable_bit::set(true);
    CHECK(cr4::protection_key_enable_bit::get());

    cr4::protection_key_enable_bit::set(false);
    CHECK_FALSE(cr4::protection_key_enable_bit::get());

    CHECK(cr4::get() == 0x0);
}

TEST_CASE("cr8_intel_x64")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    cr8::set(0x100U);
    CHECK(cr8::get() == 0x100U);
}

#endif
