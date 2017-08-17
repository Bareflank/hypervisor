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

    CHECK(vmcs::guest_cr0::exists());

    vmcs::guest_cr0::set_if_exists(0x0U);
    CHECK(vmcs::guest_cr0::get_if_exists() == 0U);

    vmcs::guest_cr0::set(0xFFFFFFFFU);
    CHECK(vmcs::guest_cr0::get() == 0xFFFFFFFFU);

    vmcs::guest_cr0::dump();
}

TEST_CASE("vmcs_guest_cr0_protection_enable")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_cr0::protection_enable::enable();
    CHECK(vmcs::guest_cr0::protection_enable::is_enabled());

    vmcs::guest_cr0::protection_enable::disable();
    CHECK(vmcs::guest_cr0::protection_enable::is_disabled());

    vmcs::guest_cr0::protection_enable::enable_if_exists();
    CHECK(vmcs::guest_cr0::protection_enable::is_enabled_if_exists());

    vmcs::guest_cr0::protection_enable::disable_if_exists();
    CHECK(vmcs::guest_cr0::protection_enable::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_cr0_monitor_coprocessor")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_cr0::monitor_coprocessor::enable();
    CHECK(vmcs::guest_cr0::monitor_coprocessor::is_enabled());

    vmcs::guest_cr0::monitor_coprocessor::disable();
    CHECK(vmcs::guest_cr0::monitor_coprocessor::is_disabled());

    vmcs::guest_cr0::monitor_coprocessor::enable_if_exists();
    CHECK(vmcs::guest_cr0::monitor_coprocessor::is_enabled_if_exists());

    vmcs::guest_cr0::monitor_coprocessor::disable_if_exists();
    CHECK(vmcs::guest_cr0::monitor_coprocessor::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_cr0_emulation")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_cr0::emulation::enable();
    CHECK(vmcs::guest_cr0::emulation::is_enabled());

    vmcs::guest_cr0::emulation::disable();
    CHECK(vmcs::guest_cr0::emulation::is_disabled());

    vmcs::guest_cr0::emulation::enable_if_exists();
    CHECK(vmcs::guest_cr0::emulation::is_enabled_if_exists());

    vmcs::guest_cr0::emulation::disable_if_exists();
    CHECK(vmcs::guest_cr0::emulation::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_cr0_task_switched")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_cr0::task_switched::enable();
    CHECK(vmcs::guest_cr0::task_switched::is_enabled());

    vmcs::guest_cr0::task_switched::disable();
    CHECK(vmcs::guest_cr0::task_switched::is_disabled());

    vmcs::guest_cr0::task_switched::enable_if_exists();
    CHECK(vmcs::guest_cr0::task_switched::is_enabled_if_exists());

    vmcs::guest_cr0::task_switched::disable_if_exists();
    CHECK(vmcs::guest_cr0::task_switched::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_cr0_extension_type")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_cr0::extension_type::enable();
    CHECK(vmcs::guest_cr0::extension_type::is_enabled());

    vmcs::guest_cr0::extension_type::disable();
    CHECK(vmcs::guest_cr0::extension_type::is_disabled());

    vmcs::guest_cr0::extension_type::enable_if_exists();
    CHECK(vmcs::guest_cr0::extension_type::is_enabled_if_exists());

    vmcs::guest_cr0::extension_type::disable_if_exists();
    CHECK(vmcs::guest_cr0::extension_type::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_cr0_numeric_error")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_cr0::numeric_error::enable();
    CHECK(vmcs::guest_cr0::numeric_error::is_enabled());

    vmcs::guest_cr0::numeric_error::disable();
    CHECK(vmcs::guest_cr0::numeric_error::is_disabled());

    vmcs::guest_cr0::numeric_error::enable_if_exists();
    CHECK(vmcs::guest_cr0::numeric_error::is_enabled_if_exists());

    vmcs::guest_cr0::numeric_error::disable_if_exists();
    CHECK(vmcs::guest_cr0::numeric_error::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_cr0_write_protect")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_cr0::write_protect::enable();
    CHECK(vmcs::guest_cr0::write_protect::is_enabled());

    vmcs::guest_cr0::write_protect::disable();
    CHECK(vmcs::guest_cr0::write_protect::is_disabled());

    vmcs::guest_cr0::write_protect::enable_if_exists();
    CHECK(vmcs::guest_cr0::write_protect::is_enabled_if_exists());

    vmcs::guest_cr0::write_protect::disable_if_exists();
    CHECK(vmcs::guest_cr0::write_protect::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_cr0_alignment_mask")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_cr0::alignment_mask::enable();
    CHECK(vmcs::guest_cr0::alignment_mask::is_enabled());

    vmcs::guest_cr0::alignment_mask::disable();
    CHECK(vmcs::guest_cr0::alignment_mask::is_disabled());

    vmcs::guest_cr0::alignment_mask::enable_if_exists();
    CHECK(vmcs::guest_cr0::alignment_mask::is_enabled_if_exists());

    vmcs::guest_cr0::alignment_mask::disable_if_exists();
    CHECK(vmcs::guest_cr0::alignment_mask::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_cr0_not_write_through")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_cr0::not_write_through::enable();
    CHECK(vmcs::guest_cr0::not_write_through::is_enabled());

    vmcs::guest_cr0::not_write_through::disable();
    CHECK(vmcs::guest_cr0::not_write_through::is_disabled());

    vmcs::guest_cr0::not_write_through::enable_if_exists();
    CHECK(vmcs::guest_cr0::not_write_through::is_enabled_if_exists());

    vmcs::guest_cr0::not_write_through::disable_if_exists();
    CHECK(vmcs::guest_cr0::not_write_through::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_cr0_cache_disable")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_cr0::cache_disable::enable();
    CHECK(vmcs::guest_cr0::cache_disable::is_enabled());

    vmcs::guest_cr0::cache_disable::disable();
    CHECK(vmcs::guest_cr0::cache_disable::is_disabled());

    vmcs::guest_cr0::cache_disable::enable_if_exists();
    CHECK(vmcs::guest_cr0::cache_disable::is_enabled_if_exists());

    vmcs::guest_cr0::cache_disable::disable_if_exists();
    CHECK(vmcs::guest_cr0::cache_disable::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_cr0_paging")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_cr0::paging::enable();
    CHECK(vmcs::guest_cr0::paging::is_enabled());

    vmcs::guest_cr0::paging::disable();
    CHECK(vmcs::guest_cr0::paging::is_disabled());

    vmcs::guest_cr0::paging::enable_if_exists();
    CHECK(vmcs::guest_cr0::paging::is_enabled_if_exists());

    vmcs::guest_cr0::paging::disable_if_exists();
    CHECK(vmcs::guest_cr0::paging::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_cr3")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::guest_cr3::exists());

    vmcs::guest_cr3::set(100UL);
    CHECK(vmcs::guest_cr3::get() == 100UL);

    vmcs::guest_cr3::set_if_exists(200UL);
    CHECK(vmcs::guest_cr3::get_if_exists() == 200UL);
}

TEST_CASE("vmcs_guest_cr4")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::guest_cr4::exists());

    vmcs::guest_cr4::set_if_exists(0x1U);
    CHECK(vmcs::guest_cr4::get_if_exists() == 0x1U);

    vmcs::guest_cr4::set(0xFFFFFFFFU);
    CHECK(vmcs::guest_cr4::get() == 0xFFFFFFFFU);

    vmcs::guest_cr4::dump();
}

TEST_CASE("vmcs_guest_cr4_v8086_mode_extensions")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_cr4::v8086_mode_extensions::enable();
    CHECK(vmcs::guest_cr4::v8086_mode_extensions::is_enabled());

    vmcs::guest_cr4::v8086_mode_extensions::disable();
    CHECK(vmcs::guest_cr4::v8086_mode_extensions::is_disabled());

    vmcs::guest_cr4::v8086_mode_extensions::enable_if_exists();
    CHECK(vmcs::guest_cr4::v8086_mode_extensions::is_enabled_if_exists());

    vmcs::guest_cr4::v8086_mode_extensions::disable_if_exists();
    CHECK(vmcs::guest_cr4::v8086_mode_extensions::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_cr4_protected_mode_virtual_interrupts")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_cr4::protected_mode_virtual_interrupts::enable();
    CHECK(vmcs::guest_cr4::protected_mode_virtual_interrupts::is_enabled());

    vmcs::guest_cr4::protected_mode_virtual_interrupts::disable();
    CHECK(vmcs::guest_cr4::protected_mode_virtual_interrupts::is_disabled());

    vmcs::guest_cr4::protected_mode_virtual_interrupts::enable_if_exists();
    CHECK(vmcs::guest_cr4::protected_mode_virtual_interrupts::is_enabled_if_exists());

    vmcs::guest_cr4::protected_mode_virtual_interrupts::disable_if_exists();
    CHECK(vmcs::guest_cr4::protected_mode_virtual_interrupts::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_cr4_time_stamp_disable")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_cr4::time_stamp_disable::enable();
    CHECK(vmcs::guest_cr4::time_stamp_disable::is_enabled());

    vmcs::guest_cr4::time_stamp_disable::disable();
    CHECK(vmcs::guest_cr4::time_stamp_disable::is_disabled());

    vmcs::guest_cr4::time_stamp_disable::enable_if_exists();
    CHECK(vmcs::guest_cr4::time_stamp_disable::is_enabled_if_exists());

    vmcs::guest_cr4::time_stamp_disable::disable_if_exists();
    CHECK(vmcs::guest_cr4::time_stamp_disable::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_cr4_debugging_extensions")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_cr4::debugging_extensions::enable();
    CHECK(vmcs::guest_cr4::debugging_extensions::is_enabled());

    vmcs::guest_cr4::debugging_extensions::disable();
    CHECK(vmcs::guest_cr4::debugging_extensions::is_disabled());

    vmcs::guest_cr4::debugging_extensions::enable_if_exists();
    CHECK(vmcs::guest_cr4::debugging_extensions::is_enabled_if_exists());

    vmcs::guest_cr4::debugging_extensions::disable_if_exists();
    CHECK(vmcs::guest_cr4::debugging_extensions::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_cr4_page_size_extensions")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_cr4::page_size_extensions::enable();
    CHECK(vmcs::guest_cr4::page_size_extensions::is_enabled());

    vmcs::guest_cr4::page_size_extensions::disable();
    CHECK(vmcs::guest_cr4::page_size_extensions::is_disabled());

    vmcs::guest_cr4::page_size_extensions::enable_if_exists();
    CHECK(vmcs::guest_cr4::page_size_extensions::is_enabled_if_exists());

    vmcs::guest_cr4::page_size_extensions::disable_if_exists();
    CHECK(vmcs::guest_cr4::page_size_extensions::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_cr4_physical_address_extensions")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_cr4::physical_address_extensions::enable();
    CHECK(vmcs::guest_cr4::physical_address_extensions::is_enabled());

    vmcs::guest_cr4::physical_address_extensions::disable();
    CHECK(vmcs::guest_cr4::physical_address_extensions::is_disabled());

    vmcs::guest_cr4::physical_address_extensions::enable_if_exists();
    CHECK(vmcs::guest_cr4::physical_address_extensions::is_enabled_if_exists());

    vmcs::guest_cr4::physical_address_extensions::disable_if_exists();
    CHECK(vmcs::guest_cr4::physical_address_extensions::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_cr4_machine_check_enable")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_cr4::machine_check_enable::enable();
    CHECK(vmcs::guest_cr4::machine_check_enable::is_enabled());

    vmcs::guest_cr4::machine_check_enable::disable();
    CHECK(vmcs::guest_cr4::machine_check_enable::is_disabled());

    vmcs::guest_cr4::machine_check_enable::enable_if_exists();
    CHECK(vmcs::guest_cr4::machine_check_enable::is_enabled_if_exists());

    vmcs::guest_cr4::machine_check_enable::disable_if_exists();
    CHECK(vmcs::guest_cr4::machine_check_enable::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_cr4_page_global_enable")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_cr4::page_global_enable::enable();
    CHECK(vmcs::guest_cr4::page_global_enable::is_enabled());

    vmcs::guest_cr4::page_global_enable::disable();
    CHECK(vmcs::guest_cr4::page_global_enable::is_disabled());

    vmcs::guest_cr4::page_global_enable::enable_if_exists();
    CHECK(vmcs::guest_cr4::page_global_enable::is_enabled_if_exists());

    vmcs::guest_cr4::page_global_enable::disable_if_exists();
    CHECK(vmcs::guest_cr4::page_global_enable::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_cr4_performance_monitor_counter_enable")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_cr4::performance_monitor_counter_enable::enable();
    CHECK(vmcs::guest_cr4::performance_monitor_counter_enable::is_enabled());

    vmcs::guest_cr4::performance_monitor_counter_enable::disable();
    CHECK(vmcs::guest_cr4::performance_monitor_counter_enable::is_disabled());

    vmcs::guest_cr4::performance_monitor_counter_enable::enable_if_exists();
    CHECK(vmcs::guest_cr4::performance_monitor_counter_enable::is_enabled_if_exists());

    vmcs::guest_cr4::performance_monitor_counter_enable::disable_if_exists();
    CHECK(vmcs::guest_cr4::performance_monitor_counter_enable::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_cr4_osfxsr")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_cr4::osfxsr::enable();
    CHECK(vmcs::guest_cr4::osfxsr::is_enabled());

    vmcs::guest_cr4::osfxsr::disable();
    CHECK(vmcs::guest_cr4::osfxsr::is_disabled());

    vmcs::guest_cr4::osfxsr::enable_if_exists();
    CHECK(vmcs::guest_cr4::osfxsr::is_enabled_if_exists());

    vmcs::guest_cr4::osfxsr::disable_if_exists();
    CHECK(vmcs::guest_cr4::osfxsr::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_cr4_osxmmexcpt")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_cr4::osxmmexcpt::enable();
    CHECK(vmcs::guest_cr4::osxmmexcpt::is_enabled());

    vmcs::guest_cr4::osxmmexcpt::disable();
    CHECK(vmcs::guest_cr4::osxmmexcpt::is_disabled());

    vmcs::guest_cr4::osxmmexcpt::enable_if_exists();
    CHECK(vmcs::guest_cr4::osxmmexcpt::is_enabled_if_exists());

    vmcs::guest_cr4::osxmmexcpt::disable_if_exists();
    CHECK(vmcs::guest_cr4::osxmmexcpt::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_cr4_vmx_enable_bit")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_cr4::vmx_enable_bit::enable();
    CHECK(vmcs::guest_cr4::vmx_enable_bit::is_enabled());

    vmcs::guest_cr4::vmx_enable_bit::disable();
    CHECK(vmcs::guest_cr4::vmx_enable_bit::is_disabled());

    vmcs::guest_cr4::vmx_enable_bit::enable_if_exists();
    CHECK(vmcs::guest_cr4::vmx_enable_bit::is_enabled_if_exists());

    vmcs::guest_cr4::vmx_enable_bit::disable_if_exists();
    CHECK(vmcs::guest_cr4::vmx_enable_bit::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_cr4_smx_enable_bit")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_cr4::smx_enable_bit::enable();
    CHECK(vmcs::guest_cr4::smx_enable_bit::is_enabled());

    vmcs::guest_cr4::smx_enable_bit::disable();
    CHECK(vmcs::guest_cr4::smx_enable_bit::is_disabled());

    vmcs::guest_cr4::smx_enable_bit::enable_if_exists();
    CHECK(vmcs::guest_cr4::smx_enable_bit::is_enabled_if_exists());

    vmcs::guest_cr4::smx_enable_bit::disable_if_exists();
    CHECK(vmcs::guest_cr4::smx_enable_bit::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_cr4_fsgsbase_enable_bit")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_cr4::fsgsbase_enable_bit::enable();
    CHECK(vmcs::guest_cr4::fsgsbase_enable_bit::is_enabled());

    vmcs::guest_cr4::fsgsbase_enable_bit::disable();
    CHECK(vmcs::guest_cr4::fsgsbase_enable_bit::is_disabled());

    vmcs::guest_cr4::fsgsbase_enable_bit::enable_if_exists();
    CHECK(vmcs::guest_cr4::fsgsbase_enable_bit::is_enabled_if_exists());

    vmcs::guest_cr4::fsgsbase_enable_bit::disable_if_exists();
    CHECK(vmcs::guest_cr4::fsgsbase_enable_bit::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_cr4_pcid_enable_bit")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_cr4::pcid_enable_bit::enable();
    CHECK(vmcs::guest_cr4::pcid_enable_bit::is_enabled());

    vmcs::guest_cr4::pcid_enable_bit::disable();
    CHECK(vmcs::guest_cr4::pcid_enable_bit::is_disabled());

    vmcs::guest_cr4::pcid_enable_bit::enable_if_exists();
    CHECK(vmcs::guest_cr4::pcid_enable_bit::is_enabled_if_exists());

    vmcs::guest_cr4::pcid_enable_bit::disable_if_exists();
    CHECK(vmcs::guest_cr4::pcid_enable_bit::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_cr4_osxsave")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_cr4::osxsave::enable();
    CHECK(vmcs::guest_cr4::osxsave::is_enabled());

    vmcs::guest_cr4::osxsave::disable();
    CHECK(vmcs::guest_cr4::osxsave::is_disabled());

    vmcs::guest_cr4::osxsave::enable_if_exists();
    CHECK(vmcs::guest_cr4::osxsave::is_enabled_if_exists());

    vmcs::guest_cr4::osxsave::disable_if_exists();
    CHECK(vmcs::guest_cr4::osxsave::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_cr4_smep_enable_bit")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_cr4::smep_enable_bit::enable();
    CHECK(vmcs::guest_cr4::smep_enable_bit::is_enabled());

    vmcs::guest_cr4::smep_enable_bit::disable();
    CHECK(vmcs::guest_cr4::smep_enable_bit::is_disabled());

    vmcs::guest_cr4::smep_enable_bit::enable_if_exists();
    CHECK(vmcs::guest_cr4::smep_enable_bit::is_enabled_if_exists());

    vmcs::guest_cr4::smep_enable_bit::disable_if_exists();
    CHECK(vmcs::guest_cr4::smep_enable_bit::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_cr4_smap_enable_bit")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_cr4::smap_enable_bit::enable();
    CHECK(vmcs::guest_cr4::smap_enable_bit::is_enabled());

    vmcs::guest_cr4::smap_enable_bit::disable();
    CHECK(vmcs::guest_cr4::smap_enable_bit::is_disabled());

    vmcs::guest_cr4::smap_enable_bit::enable_if_exists();
    CHECK(vmcs::guest_cr4::smap_enable_bit::is_enabled_if_exists());

    vmcs::guest_cr4::smap_enable_bit::disable_if_exists();
    CHECK(vmcs::guest_cr4::smap_enable_bit::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_cr4_protection_key_enable_bit")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_cr4::protection_key_enable_bit::enable();
    CHECK(vmcs::guest_cr4::protection_key_enable_bit::is_enabled());

    vmcs::guest_cr4::protection_key_enable_bit::disable();
    CHECK(vmcs::guest_cr4::protection_key_enable_bit::is_disabled());

    vmcs::guest_cr4::protection_key_enable_bit::enable_if_exists();
    CHECK(vmcs::guest_cr4::protection_key_enable_bit::is_enabled_if_exists());

    vmcs::guest_cr4::protection_key_enable_bit::disable_if_exists();
    CHECK(vmcs::guest_cr4::protection_key_enable_bit::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_es_base")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::guest_es_base::exists());

    vmcs::guest_es_base::set(1UL);
    CHECK(vmcs::guest_es_base::get() == 1UL);

    vmcs::guest_es_base::set_if_exists(0UL);
    CHECK(vmcs::guest_es_base::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_cs_base")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::guest_cs_base::exists());

    vmcs::guest_cs_base::set(1UL);
    CHECK(vmcs::guest_cs_base::get() == 1UL);

    vmcs::guest_cs_base::set_if_exists(0UL);
    CHECK(vmcs::guest_cs_base::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_ss_base")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::guest_ss_base::exists());

    vmcs::guest_ss_base::set(1UL);
    CHECK(vmcs::guest_ss_base::get() == 1UL);

    vmcs::guest_ss_base::set_if_exists(0UL);
    CHECK(vmcs::guest_ss_base::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_ds_base")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::guest_ds_base::exists());

    vmcs::guest_ds_base::set(1UL);
    CHECK(vmcs::guest_ds_base::get() == 1UL);

    vmcs::guest_ds_base::set_if_exists(0UL);
    CHECK(vmcs::guest_ds_base::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_fs_base")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::guest_fs_base::exists());

    vmcs::guest_fs_base::set(1UL);
    CHECK(vmcs::guest_fs_base::get() == 1UL);

    vmcs::guest_fs_base::set_if_exists(0UL);
    CHECK(vmcs::guest_fs_base::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_gs_base")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::guest_gs_base::exists());

    vmcs::guest_gs_base::set(1UL);
    CHECK(vmcs::guest_gs_base::get() == 1UL);

    vmcs::guest_gs_base::set_if_exists(0UL);
    CHECK(vmcs::guest_gs_base::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_ldtr_base")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::guest_ldtr_base::exists());

    vmcs::guest_ldtr_base::set(1UL);
    CHECK(vmcs::guest_ldtr_base::get() == 1UL);

    vmcs::guest_ldtr_base::set_if_exists(0UL);
    CHECK(vmcs::guest_ldtr_base::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_tr_base")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::guest_tr_base::exists());

    vmcs::guest_tr_base::set(1UL);
    CHECK(vmcs::guest_tr_base::get() == 1UL);

    vmcs::guest_tr_base::set_if_exists(0UL);
    CHECK(vmcs::guest_tr_base::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_gdtr_base")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::guest_gdtr_base::exists());

    vmcs::guest_gdtr_base::set(1UL);
    CHECK(vmcs::guest_gdtr_base::get() == 1UL);

    vmcs::guest_gdtr_base::set_if_exists(0UL);
    CHECK(vmcs::guest_gdtr_base::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_idtr_base")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::guest_idtr_base::exists());

    vmcs::guest_idtr_base::set(1UL);
    CHECK(vmcs::guest_idtr_base::get() == 1UL);

    vmcs::guest_idtr_base::set_if_exists(0UL);
    CHECK(vmcs::guest_idtr_base::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_dr7")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::guest_dr7::exists());

    vmcs::guest_dr7::set(1UL);
    CHECK(vmcs::guest_dr7::get() == 1UL);

    vmcs::guest_dr7::set_if_exists(0UL);
    CHECK(vmcs::guest_dr7::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_rsp")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::guest_rsp::exists());

    vmcs::guest_rsp::set(1UL);
    CHECK(vmcs::guest_rsp::get() == 1UL);

    vmcs::guest_rsp::set_if_exists(0UL);
    CHECK(vmcs::guest_rsp::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_rip")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::guest_rip::exists());

    vmcs::guest_rip::set(1UL);
    CHECK(vmcs::guest_rip::get() == 1UL);

    vmcs::guest_rip::set_if_exists(0UL);
    CHECK(vmcs::guest_rip::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_rflags")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::guest_rflags::exists());

    vmcs::guest_rflags::set(100UL);
    CHECK(vmcs::guest_rflags::get() == 100UL);

    vmcs::guest_rflags::set_if_exists(0UL);
    CHECK(vmcs::guest_rflags::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_rflags_carry_flag")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_rflags::carry_flag::enable();
    CHECK(vmcs::guest_rflags::carry_flag::is_enabled());

    vmcs::guest_rflags::carry_flag::disable();
    CHECK(vmcs::guest_rflags::carry_flag::is_disabled());

    vmcs::guest_rflags::carry_flag::enable_if_exists();
    CHECK(vmcs::guest_rflags::carry_flag::is_enabled_if_exists());

    vmcs::guest_rflags::carry_flag::disable_if_exists();
    CHECK(vmcs::guest_rflags::carry_flag::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_rflags_parity_flag")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_rflags::parity_flag::enable();
    CHECK(vmcs::guest_rflags::parity_flag::is_enabled());

    vmcs::guest_rflags::parity_flag::disable();
    CHECK(vmcs::guest_rflags::parity_flag::is_disabled());

    vmcs::guest_rflags::parity_flag::enable_if_exists();
    CHECK(vmcs::guest_rflags::parity_flag::is_enabled_if_exists());

    vmcs::guest_rflags::parity_flag::disable_if_exists();
    CHECK(vmcs::guest_rflags::parity_flag::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_rflags_auxiliary_carry_flag")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_rflags::auxiliary_carry_flag::enable();
    CHECK(vmcs::guest_rflags::auxiliary_carry_flag::is_enabled());

    vmcs::guest_rflags::auxiliary_carry_flag::disable();
    CHECK(vmcs::guest_rflags::auxiliary_carry_flag::is_disabled());

    vmcs::guest_rflags::auxiliary_carry_flag::enable_if_exists();
    CHECK(vmcs::guest_rflags::auxiliary_carry_flag::is_enabled_if_exists());

    vmcs::guest_rflags::auxiliary_carry_flag::disable_if_exists();
    CHECK(vmcs::guest_rflags::auxiliary_carry_flag::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_rflags_zero_flag")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_rflags::zero_flag::enable();
    CHECK(vmcs::guest_rflags::zero_flag::is_enabled());

    vmcs::guest_rflags::zero_flag::disable();
    CHECK(vmcs::guest_rflags::zero_flag::is_disabled());

    vmcs::guest_rflags::zero_flag::enable_if_exists();
    CHECK(vmcs::guest_rflags::zero_flag::is_enabled_if_exists());

    vmcs::guest_rflags::zero_flag::disable_if_exists();
    CHECK(vmcs::guest_rflags::zero_flag::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_rflags_sign_flag")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_rflags::sign_flag::enable();
    CHECK(vmcs::guest_rflags::sign_flag::is_enabled());

    vmcs::guest_rflags::sign_flag::disable();
    CHECK(vmcs::guest_rflags::sign_flag::is_disabled());

    vmcs::guest_rflags::sign_flag::enable_if_exists();
    CHECK(vmcs::guest_rflags::sign_flag::is_enabled_if_exists());

    vmcs::guest_rflags::sign_flag::disable_if_exists();
    CHECK(vmcs::guest_rflags::sign_flag::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_rflags_trap_flag")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_rflags::trap_flag::enable();
    CHECK(vmcs::guest_rflags::trap_flag::is_enabled());

    vmcs::guest_rflags::trap_flag::disable();
    CHECK(vmcs::guest_rflags::trap_flag::is_disabled());

    vmcs::guest_rflags::trap_flag::enable_if_exists();
    CHECK(vmcs::guest_rflags::trap_flag::is_enabled_if_exists());

    vmcs::guest_rflags::trap_flag::disable_if_exists();
    CHECK(vmcs::guest_rflags::trap_flag::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_rflags_interrupt_enable_flag")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_rflags::interrupt_enable_flag::enable();
    CHECK(vmcs::guest_rflags::interrupt_enable_flag::is_enabled());

    vmcs::guest_rflags::interrupt_enable_flag::disable();
    CHECK(vmcs::guest_rflags::interrupt_enable_flag::is_disabled());

    vmcs::guest_rflags::interrupt_enable_flag::enable_if_exists();
    CHECK(vmcs::guest_rflags::interrupt_enable_flag::is_enabled_if_exists());

    vmcs::guest_rflags::interrupt_enable_flag::disable_if_exists();
    CHECK(vmcs::guest_rflags::interrupt_enable_flag::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_rflags_direction_flag")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_rflags::direction_flag::enable();
    CHECK(vmcs::guest_rflags::direction_flag::is_enabled());

    vmcs::guest_rflags::direction_flag::disable();
    CHECK(vmcs::guest_rflags::direction_flag::is_disabled());

    vmcs::guest_rflags::direction_flag::enable_if_exists();
    CHECK(vmcs::guest_rflags::direction_flag::is_enabled_if_exists());

    vmcs::guest_rflags::direction_flag::disable_if_exists();
    CHECK(vmcs::guest_rflags::direction_flag::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_rflags_overflow_flag")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_rflags::overflow_flag::enable();
    CHECK(vmcs::guest_rflags::overflow_flag::is_enabled());

    vmcs::guest_rflags::overflow_flag::disable();
    CHECK(vmcs::guest_rflags::overflow_flag::is_disabled());

    vmcs::guest_rflags::overflow_flag::enable_if_exists();
    CHECK(vmcs::guest_rflags::overflow_flag::is_enabled_if_exists());

    vmcs::guest_rflags::overflow_flag::disable_if_exists();
    CHECK(vmcs::guest_rflags::overflow_flag::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_rflags_privilege_level")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_rflags::privilege_level::set(1UL);
    CHECK(vmcs::guest_rflags::privilege_level::get() == 1UL);

    vmcs::guest_rflags::privilege_level::set(2UL);
    CHECK(vmcs::guest_rflags::privilege_level::get() == 2UL);

    vmcs::guest_rflags::privilege_level::set_if_exists(3UL);
    CHECK(vmcs::guest_rflags::privilege_level::get_if_exists() == 3UL);

    vmcs::guest_rflags::privilege_level::set_if_exists(0UL);
    CHECK(vmcs::guest_rflags::privilege_level::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_rflags_nested_task")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_rflags::nested_task::enable();
    CHECK(vmcs::guest_rflags::nested_task::is_enabled());

    vmcs::guest_rflags::nested_task::disable();
    CHECK(vmcs::guest_rflags::nested_task::is_disabled());

    vmcs::guest_rflags::nested_task::enable_if_exists();
    CHECK(vmcs::guest_rflags::nested_task::is_enabled_if_exists());

    vmcs::guest_rflags::nested_task::disable_if_exists();
    CHECK(vmcs::guest_rflags::nested_task::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_rflags_resume_flag")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_rflags::resume_flag::enable();
    CHECK(vmcs::guest_rflags::resume_flag::is_enabled());

    vmcs::guest_rflags::resume_flag::disable();
    CHECK(vmcs::guest_rflags::resume_flag::is_disabled());

    vmcs::guest_rflags::resume_flag::enable_if_exists();
    CHECK(vmcs::guest_rflags::resume_flag::is_enabled_if_exists());

    vmcs::guest_rflags::resume_flag::disable_if_exists();
    CHECK(vmcs::guest_rflags::resume_flag::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_rflags_virtual_8086_mode")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_rflags::virtual_8086_mode::enable();
    CHECK(vmcs::guest_rflags::virtual_8086_mode::is_enabled());

    vmcs::guest_rflags::virtual_8086_mode::disable();
    CHECK(vmcs::guest_rflags::virtual_8086_mode::is_disabled());

    vmcs::guest_rflags::virtual_8086_mode::enable_if_exists();
    CHECK(vmcs::guest_rflags::virtual_8086_mode::is_enabled_if_exists());

    vmcs::guest_rflags::virtual_8086_mode::disable_if_exists();
    CHECK(vmcs::guest_rflags::virtual_8086_mode::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_rflags_alignment_check_access_control")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_rflags::alignment_check_access_control::enable();
    CHECK(vmcs::guest_rflags::alignment_check_access_control::is_enabled());

    vmcs::guest_rflags::alignment_check_access_control::disable();
    CHECK(vmcs::guest_rflags::alignment_check_access_control::is_disabled());

    vmcs::guest_rflags::alignment_check_access_control::enable_if_exists();
    CHECK(vmcs::guest_rflags::alignment_check_access_control::is_enabled_if_exists());

    vmcs::guest_rflags::alignment_check_access_control::disable_if_exists();
    CHECK(vmcs::guest_rflags::alignment_check_access_control::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_rflags_virtual_interupt_flag")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_rflags::virtual_interrupt_flag::enable();
    CHECK(vmcs::guest_rflags::virtual_interrupt_flag::is_enabled());

    vmcs::guest_rflags::virtual_interrupt_flag::disable();
    CHECK(vmcs::guest_rflags::virtual_interrupt_flag::is_disabled());

    vmcs::guest_rflags::virtual_interrupt_flag::enable_if_exists();
    CHECK(vmcs::guest_rflags::virtual_interrupt_flag::is_enabled_if_exists());

    vmcs::guest_rflags::virtual_interrupt_flag::disable_if_exists();
    CHECK(vmcs::guest_rflags::virtual_interrupt_flag::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_rflags_virtual_interupt_pending")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_rflags::virtual_interrupt_pending::enable();
    CHECK(vmcs::guest_rflags::virtual_interrupt_pending::is_enabled());

    vmcs::guest_rflags::virtual_interrupt_pending::disable();
    CHECK(vmcs::guest_rflags::virtual_interrupt_pending::is_disabled());

    vmcs::guest_rflags::virtual_interrupt_pending::enable_if_exists();
    CHECK(vmcs::guest_rflags::virtual_interrupt_pending::is_enabled_if_exists());

    vmcs::guest_rflags::virtual_interrupt_pending::disable_if_exists();
    CHECK(vmcs::guest_rflags::virtual_interrupt_pending::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_rflags_id_flag")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_rflags::id_flag::enable();
    CHECK(vmcs::guest_rflags::id_flag::is_enabled());

    vmcs::guest_rflags::id_flag::disable();
    CHECK(vmcs::guest_rflags::id_flag::is_disabled());

    vmcs::guest_rflags::id_flag::enable_if_exists();
    CHECK(vmcs::guest_rflags::id_flag::is_enabled_if_exists());

    vmcs::guest_rflags::id_flag::disable_if_exists();
    CHECK(vmcs::guest_rflags::id_flag::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_rflags_reserved")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_rflags::reserved::set(0x100000000UL);
    CHECK(vmcs::guest_rflags::reserved::get() == 0x100000000UL);

    vmcs::guest_rflags::reserved::set_if_exists(0UL);
    CHECK(vmcs::guest_rflags::reserved::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_rflags_always_disabled")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_rflags::always_disabled::set(0x100000000UL);
    CHECK(vmcs::guest_rflags::always_disabled::get() == 0x100000000UL);

    vmcs::guest_rflags::always_disabled::set_if_exists(0UL);
    CHECK(vmcs::guest_rflags::always_disabled::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_rflags_always_enabled")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_rflags::always_enabled::set(2UL);
    CHECK(vmcs::guest_rflags::always_enabled::get() == 2UL);

    vmcs::guest_rflags::always_enabled::set_if_exists(0UL);
    CHECK(vmcs::guest_rflags::always_enabled::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_pending_debug_exceptions")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::guest_pending_debug_exceptions::exists());

    vmcs::guest_pending_debug_exceptions::set(1UL);
    CHECK(vmcs::guest_pending_debug_exceptions::get() == 1UL);

    vmcs::guest_pending_debug_exceptions::set_if_exists(0UL);
    CHECK(vmcs::guest_pending_debug_exceptions::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_pending_debug_exceptions_b0")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_pending_debug_exceptions::b0::enable();
    CHECK(vmcs::guest_pending_debug_exceptions::b0::is_enabled());

    vmcs::guest_pending_debug_exceptions::b0::disable();
    CHECK(vmcs::guest_pending_debug_exceptions::b0::is_disabled());

    vmcs::guest_pending_debug_exceptions::b0::enable_if_exists();
    CHECK(vmcs::guest_pending_debug_exceptions::b0::is_enabled_if_exists());

    vmcs::guest_pending_debug_exceptions::b0::disable_if_exists();
    CHECK(vmcs::guest_pending_debug_exceptions::b0::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_pending_debug_exceptions_b1")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_pending_debug_exceptions::b1::enable();
    CHECK(vmcs::guest_pending_debug_exceptions::b1::is_enabled());

    vmcs::guest_pending_debug_exceptions::b1::disable();
    CHECK(vmcs::guest_pending_debug_exceptions::b1::is_disabled());

    vmcs::guest_pending_debug_exceptions::b1::enable_if_exists();
    CHECK(vmcs::guest_pending_debug_exceptions::b1::is_enabled_if_exists());

    vmcs::guest_pending_debug_exceptions::b1::disable_if_exists();
    CHECK(vmcs::guest_pending_debug_exceptions::b1::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_pending_debug_exceptions_b2")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_pending_debug_exceptions::b2::enable();
    CHECK(vmcs::guest_pending_debug_exceptions::b2::is_enabled());

    vmcs::guest_pending_debug_exceptions::b2::disable();
    CHECK(vmcs::guest_pending_debug_exceptions::b2::is_disabled());

    vmcs::guest_pending_debug_exceptions::b2::enable_if_exists();
    CHECK(vmcs::guest_pending_debug_exceptions::b2::is_enabled_if_exists());

    vmcs::guest_pending_debug_exceptions::b2::disable_if_exists();
    CHECK(vmcs::guest_pending_debug_exceptions::b2::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_pending_debug_exceptions_b3")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_pending_debug_exceptions::b3::enable();
    CHECK(vmcs::guest_pending_debug_exceptions::b3::is_enabled());

    vmcs::guest_pending_debug_exceptions::b3::disable();
    CHECK(vmcs::guest_pending_debug_exceptions::b3::is_disabled());

    vmcs::guest_pending_debug_exceptions::b3::enable_if_exists();
    CHECK(vmcs::guest_pending_debug_exceptions::b3::is_enabled_if_exists());

    vmcs::guest_pending_debug_exceptions::b3::disable_if_exists();
    CHECK(vmcs::guest_pending_debug_exceptions::b3::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_pending_debug_exceptions_reserved")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_pending_debug_exceptions::reserved::set(0x10UL);
    CHECK(vmcs::guest_pending_debug_exceptions::reserved::get() == 0x10UL);

    vmcs::guest_pending_debug_exceptions::reserved::set_if_exists(0x0UL);
    CHECK(vmcs::guest_pending_debug_exceptions::reserved::get_if_exists() == 0x0UL);
}

TEST_CASE("vmcs_guest_pending_debug_exceptions_enabled_breakpoint")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_pending_debug_exceptions::enabled_breakpoint::enable();
    CHECK(vmcs::guest_pending_debug_exceptions::enabled_breakpoint::is_enabled());

    vmcs::guest_pending_debug_exceptions::enabled_breakpoint::disable();
    CHECK(vmcs::guest_pending_debug_exceptions::enabled_breakpoint::is_disabled());

    vmcs::guest_pending_debug_exceptions::enabled_breakpoint::enable_if_exists();
    CHECK(vmcs::guest_pending_debug_exceptions::enabled_breakpoint::is_enabled_if_exists());

    vmcs::guest_pending_debug_exceptions::enabled_breakpoint::disable_if_exists();
    CHECK(
        vmcs::guest_pending_debug_exceptions::enabled_breakpoint::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_pending_debug_exceptions_bs")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_pending_debug_exceptions::bs::enable();
    CHECK(vmcs::guest_pending_debug_exceptions::bs::is_enabled());

    vmcs::guest_pending_debug_exceptions::bs::disable();
    CHECK(vmcs::guest_pending_debug_exceptions::bs::is_disabled());

    vmcs::guest_pending_debug_exceptions::bs::enable_if_exists();
    CHECK(vmcs::guest_pending_debug_exceptions::bs::is_enabled_if_exists());

    vmcs::guest_pending_debug_exceptions::bs::disable_if_exists();
    CHECK(vmcs::guest_pending_debug_exceptions::bs::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_pending_debug_exceptions_rtm")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_pending_debug_exceptions::rtm::enable();
    CHECK(vmcs::guest_pending_debug_exceptions::rtm::is_enabled());

    vmcs::guest_pending_debug_exceptions::rtm::disable();
    CHECK(vmcs::guest_pending_debug_exceptions::rtm::is_disabled());

    vmcs::guest_pending_debug_exceptions::rtm::enable_if_exists();
    CHECK(vmcs::guest_pending_debug_exceptions::rtm::is_enabled_if_exists());

    vmcs::guest_pending_debug_exceptions::rtm::disable_if_exists();
    CHECK(vmcs::guest_pending_debug_exceptions::rtm::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_ia32_sysenter_esp")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::guest_ia32_sysenter_esp::exists());

    vmcs::guest_ia32_sysenter_esp::set_if_exists(0x0UL);
    CHECK(vmcs::guest_ia32_sysenter_esp::get_if_exists() == 0UL);

    vmcs::guest_ia32_sysenter_esp::set(0xFFFFFFFFUL);
    CHECK(vmcs::guest_ia32_sysenter_esp::get() == 0xFFFFFFFFUL);
}

TEST_CASE("vmcs_guest_ia32_sysenter_eip")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::guest_ia32_sysenter_eip::exists());

    vmcs::guest_ia32_sysenter_eip::set_if_exists(0x0UL);
    CHECK(vmcs::guest_ia32_sysenter_eip::get_if_exists() == 0UL);

    vmcs::guest_ia32_sysenter_eip::set(0xFFFFFFFFUL);
    CHECK(vmcs::guest_ia32_sysenter_eip::get() == 0xFFFFFFFFUL);
}

#endif
