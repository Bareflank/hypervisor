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

TEST_CASE("vmcs_host_cr0")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::host_cr0::exists());

    vmcs::host_cr0::set_if_exists(0x2UL);
    CHECK(vmcs::host_cr0::get_if_exists() == 0x2UL);

    vmcs::host_cr0::set(0xFFFFFFFFUL);
    CHECK(vmcs::host_cr0::get() == 0xFFFFFFFFUL);

    vmcs::host_cr0::dump();
}

TEST_CASE("vmcs_host_cr0_protection_enable")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::host_cr0::protection_enable::enable();
    CHECK(vmcs::host_cr0::protection_enable::is_enabled());

    vmcs::host_cr0::protection_enable::disable();
    CHECK(vmcs::host_cr0::protection_enable::is_disabled());

    vmcs::host_cr0::protection_enable::enable_if_exists();
    CHECK(vmcs::host_cr0::protection_enable::is_enabled_if_exists());

    vmcs::host_cr0::protection_enable::disable_if_exists();
    CHECK(vmcs::host_cr0::protection_enable::is_disabled_if_exists());
}

TEST_CASE("vmcs_host_cr0_monitor_coprocessor")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::host_cr0::monitor_coprocessor::enable();
    CHECK(vmcs::host_cr0::monitor_coprocessor::is_enabled());

    vmcs::host_cr0::monitor_coprocessor::disable();
    CHECK(vmcs::host_cr0::monitor_coprocessor::is_disabled());

    vmcs::host_cr0::monitor_coprocessor::enable_if_exists();
    CHECK(vmcs::host_cr0::monitor_coprocessor::is_enabled_if_exists());

    vmcs::host_cr0::monitor_coprocessor::disable_if_exists();
    CHECK(vmcs::host_cr0::monitor_coprocessor::is_disabled_if_exists());
}

TEST_CASE("vmcs_host_cr0_emulation")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::host_cr0::emulation::enable();
    CHECK(vmcs::host_cr0::emulation::is_enabled());

    vmcs::host_cr0::emulation::disable();
    CHECK(vmcs::host_cr0::emulation::is_disabled());

    vmcs::host_cr0::emulation::enable_if_exists();
    CHECK(vmcs::host_cr0::emulation::is_enabled_if_exists());

    vmcs::host_cr0::emulation::disable_if_exists();
    CHECK(vmcs::host_cr0::emulation::is_disabled_if_exists());
}

TEST_CASE("vmcs_host_cr0_task_switched")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::host_cr0::task_switched::enable();
    CHECK(vmcs::host_cr0::task_switched::is_enabled());

    vmcs::host_cr0::task_switched::disable();
    CHECK(vmcs::host_cr0::task_switched::is_disabled());

    vmcs::host_cr0::task_switched::enable_if_exists();
    CHECK(vmcs::host_cr0::task_switched::is_enabled_if_exists());

    vmcs::host_cr0::task_switched::disable_if_exists();
    CHECK(vmcs::host_cr0::task_switched::is_disabled_if_exists());
}

TEST_CASE("vmcs_host_cr0_extension_type")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::host_cr0::extension_type::enable();
    CHECK(vmcs::host_cr0::extension_type::is_enabled());

    vmcs::host_cr0::extension_type::disable();
    CHECK(vmcs::host_cr0::extension_type::is_disabled());

    vmcs::host_cr0::extension_type::enable_if_exists();
    CHECK(vmcs::host_cr0::extension_type::is_enabled_if_exists());

    vmcs::host_cr0::extension_type::disable_if_exists();
    CHECK(vmcs::host_cr0::extension_type::is_disabled_if_exists());
}

TEST_CASE("vmcs_host_cr0_numeric_error")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::host_cr0::numeric_error::enable();
    CHECK(vmcs::host_cr0::numeric_error::is_enabled());

    vmcs::host_cr0::numeric_error::disable();
    CHECK(vmcs::host_cr0::numeric_error::is_disabled());

    vmcs::host_cr0::numeric_error::enable_if_exists();
    CHECK(vmcs::host_cr0::numeric_error::is_enabled_if_exists());

    vmcs::host_cr0::numeric_error::disable_if_exists();
    CHECK(vmcs::host_cr0::numeric_error::is_disabled_if_exists());
}

TEST_CASE("vmcs_host_cr0_write_protect")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::host_cr0::write_protect::enable();
    CHECK(vmcs::host_cr0::write_protect::is_enabled());

    vmcs::host_cr0::write_protect::disable();
    CHECK(vmcs::host_cr0::write_protect::is_disabled());

    vmcs::host_cr0::write_protect::enable_if_exists();
    CHECK(vmcs::host_cr0::write_protect::is_enabled_if_exists());

    vmcs::host_cr0::write_protect::disable_if_exists();
    CHECK(vmcs::host_cr0::write_protect::is_disabled_if_exists());
}

TEST_CASE("vmcs_host_cr0_alignment_mask")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::host_cr0::alignment_mask::enable();
    CHECK(vmcs::host_cr0::alignment_mask::is_enabled());

    vmcs::host_cr0::alignment_mask::disable();
    CHECK(vmcs::host_cr0::alignment_mask::is_disabled());

    vmcs::host_cr0::alignment_mask::enable_if_exists();
    CHECK(vmcs::host_cr0::alignment_mask::is_enabled_if_exists());

    vmcs::host_cr0::alignment_mask::disable_if_exists();
    CHECK(vmcs::host_cr0::alignment_mask::is_disabled_if_exists());
}

TEST_CASE("vmcs_host_cr0_not_write_through")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::host_cr0::not_write_through::enable();
    CHECK(vmcs::host_cr0::not_write_through::is_enabled());

    vmcs::host_cr0::not_write_through::disable();
    CHECK(vmcs::host_cr0::not_write_through::is_disabled());

    vmcs::host_cr0::not_write_through::enable_if_exists();
    CHECK(vmcs::host_cr0::not_write_through::is_enabled_if_exists());

    vmcs::host_cr0::not_write_through::disable_if_exists();
    CHECK(vmcs::host_cr0::not_write_through::is_disabled_if_exists());
}

TEST_CASE("vmcs_host_cr0_cache_disable")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::host_cr0::cache_disable::enable();
    CHECK(vmcs::host_cr0::cache_disable::is_enabled());

    vmcs::host_cr0::cache_disable::disable();
    CHECK(vmcs::host_cr0::cache_disable::is_disabled());

    vmcs::host_cr0::cache_disable::enable_if_exists();
    CHECK(vmcs::host_cr0::cache_disable::is_enabled_if_exists());

    vmcs::host_cr0::cache_disable::disable_if_exists();
    CHECK(vmcs::host_cr0::cache_disable::is_disabled_if_exists());
}

TEST_CASE("vmcs_host_cr0_paging")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::host_cr0::paging::enable();
    CHECK(vmcs::host_cr0::paging::is_enabled());

    vmcs::host_cr0::paging::disable();
    CHECK(vmcs::host_cr0::paging::is_disabled());

    vmcs::host_cr0::paging::enable_if_exists();
    CHECK(vmcs::host_cr0::paging::is_enabled_if_exists());

    vmcs::host_cr0::paging::disable_if_exists();
    CHECK(vmcs::host_cr0::paging::is_disabled_if_exists());
}

TEST_CASE("vmcs_host_cr3")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::host_cr3::exists());

    vmcs::host_cr3::set_if_exists(0x2UL);
    CHECK(vmcs::host_cr3::get_if_exists() == 0x2UL);

    vmcs::host_cr3::set(0xFFFFFFFFUL);
    CHECK(vmcs::host_cr3::get() == 0xFFFFFFFFUL);
}

TEST_CASE("vmcs_host_cr4")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::host_cr4::exists());

    vmcs::host_cr4::set_if_exists(0x2UL);
    CHECK(vmcs::host_cr4::get_if_exists() == 0x2UL);

    vmcs::host_cr4::set(0xFFFFFFFFUL);
    CHECK(vmcs::host_cr4::get() == 0xFFFFFFFFUL);

    vmcs::host_cr4::dump();
}

TEST_CASE("vmcs_host_cr4_v8086_mode_extensions")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::host_cr4::v8086_mode_extensions::enable();
    CHECK(vmcs::host_cr4::v8086_mode_extensions::is_enabled());

    vmcs::host_cr4::v8086_mode_extensions::disable();
    CHECK(vmcs::host_cr4::v8086_mode_extensions::is_disabled());

    vmcs::host_cr4::v8086_mode_extensions::enable_if_exists();
    CHECK(vmcs::host_cr4::v8086_mode_extensions::is_enabled_if_exists());

    vmcs::host_cr4::v8086_mode_extensions::disable_if_exists();
    CHECK(vmcs::host_cr4::v8086_mode_extensions::is_disabled_if_exists());
}

TEST_CASE("vmcs_host_cr4_protected_mode_virtual_interrupts")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::host_cr4::protected_mode_virtual_interrupts::enable();
    CHECK(vmcs::host_cr4::protected_mode_virtual_interrupts::is_enabled());

    vmcs::host_cr4::protected_mode_virtual_interrupts::disable();
    CHECK(vmcs::host_cr4::protected_mode_virtual_interrupts::is_disabled());

    vmcs::host_cr4::protected_mode_virtual_interrupts::enable_if_exists();
    CHECK(vmcs::host_cr4::protected_mode_virtual_interrupts::is_enabled_if_exists());

    vmcs::host_cr4::protected_mode_virtual_interrupts::disable_if_exists();
    CHECK(vmcs::host_cr4::protected_mode_virtual_interrupts::is_disabled_if_exists());
}

TEST_CASE("vmcs_host_cr4_time_stamp_disable")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::host_cr4::time_stamp_disable::enable();
    CHECK(vmcs::host_cr4::time_stamp_disable::is_enabled());

    vmcs::host_cr4::time_stamp_disable::disable();
    CHECK(vmcs::host_cr4::time_stamp_disable::is_disabled());

    vmcs::host_cr4::time_stamp_disable::enable_if_exists();
    CHECK(vmcs::host_cr4::time_stamp_disable::is_enabled_if_exists());

    vmcs::host_cr4::time_stamp_disable::disable_if_exists();
    CHECK(vmcs::host_cr4::time_stamp_disable::is_disabled_if_exists());
}

TEST_CASE("vmcs_host_cr4_debugging_extensions")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::host_cr4::debugging_extensions::enable();
    CHECK(vmcs::host_cr4::debugging_extensions::is_enabled());

    vmcs::host_cr4::debugging_extensions::disable();
    CHECK(vmcs::host_cr4::debugging_extensions::is_disabled());

    vmcs::host_cr4::debugging_extensions::enable_if_exists();
    CHECK(vmcs::host_cr4::debugging_extensions::is_enabled_if_exists());

    vmcs::host_cr4::debugging_extensions::disable_if_exists();
    CHECK(vmcs::host_cr4::debugging_extensions::is_disabled_if_exists());
}

TEST_CASE("vmcs_host_cr4_page_size_extensions")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::host_cr4::page_size_extensions::enable();
    CHECK(vmcs::host_cr4::page_size_extensions::is_enabled());

    vmcs::host_cr4::page_size_extensions::disable();
    CHECK(vmcs::host_cr4::page_size_extensions::is_disabled());

    vmcs::host_cr4::page_size_extensions::enable_if_exists();
    CHECK(vmcs::host_cr4::page_size_extensions::is_enabled_if_exists());

    vmcs::host_cr4::page_size_extensions::disable_if_exists();
    CHECK(vmcs::host_cr4::page_size_extensions::is_disabled_if_exists());
}

TEST_CASE("vmcs_host_cr4_physical_address_extensions")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::host_cr4::physical_address_extensions::enable();
    CHECK(vmcs::host_cr4::physical_address_extensions::is_enabled());

    vmcs::host_cr4::physical_address_extensions::disable();
    CHECK(vmcs::host_cr4::physical_address_extensions::is_disabled());

    vmcs::host_cr4::physical_address_extensions::enable_if_exists();
    CHECK(vmcs::host_cr4::physical_address_extensions::is_enabled_if_exists());

    vmcs::host_cr4::physical_address_extensions::disable_if_exists();
    CHECK(vmcs::host_cr4::physical_address_extensions::is_disabled_if_exists());
}

TEST_CASE("vmcs_host_cr4_machine_check_enable")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::host_cr4::machine_check_enable::enable();
    CHECK(vmcs::host_cr4::machine_check_enable::is_enabled());

    vmcs::host_cr4::machine_check_enable::disable();
    CHECK(vmcs::host_cr4::machine_check_enable::is_disabled());

    vmcs::host_cr4::machine_check_enable::enable_if_exists();
    CHECK(vmcs::host_cr4::machine_check_enable::is_enabled_if_exists());

    vmcs::host_cr4::machine_check_enable::disable_if_exists();
    CHECK(vmcs::host_cr4::machine_check_enable::is_disabled_if_exists());
}

TEST_CASE("vmcs_host_cr4_page_global_enable")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::host_cr4::page_global_enable::enable();
    CHECK(vmcs::host_cr4::page_global_enable::is_enabled());

    vmcs::host_cr4::page_global_enable::disable();
    CHECK(vmcs::host_cr4::page_global_enable::is_disabled());

    vmcs::host_cr4::page_global_enable::enable_if_exists();
    CHECK(vmcs::host_cr4::page_global_enable::is_enabled_if_exists());

    vmcs::host_cr4::page_global_enable::disable_if_exists();
    CHECK(vmcs::host_cr4::page_global_enable::is_disabled_if_exists());
}

TEST_CASE("vmcs_host_cr4_performance_monitor_counter_enable")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::host_cr4::performance_monitor_counter_enable::enable();
    CHECK(vmcs::host_cr4::performance_monitor_counter_enable::is_enabled());

    vmcs::host_cr4::performance_monitor_counter_enable::disable();
    CHECK(vmcs::host_cr4::performance_monitor_counter_enable::is_disabled());

    vmcs::host_cr4::performance_monitor_counter_enable::enable_if_exists();
    CHECK(vmcs::host_cr4::performance_monitor_counter_enable::is_enabled_if_exists());

    vmcs::host_cr4::performance_monitor_counter_enable::disable_if_exists();
    CHECK(vmcs::host_cr4::performance_monitor_counter_enable::is_disabled_if_exists());
}

TEST_CASE("vmcs_host_cr4_osfxsr")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::host_cr4::osfxsr::enable();
    CHECK(vmcs::host_cr4::osfxsr::is_enabled());

    vmcs::host_cr4::osfxsr::disable();
    CHECK(vmcs::host_cr4::osfxsr::is_disabled());

    vmcs::host_cr4::osfxsr::enable_if_exists();
    CHECK(vmcs::host_cr4::osfxsr::is_enabled_if_exists());

    vmcs::host_cr4::osfxsr::disable_if_exists();
    CHECK(vmcs::host_cr4::osfxsr::is_disabled_if_exists());
}

TEST_CASE("vmcs_host_cr4_osxmmexcpt")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::host_cr4::osxmmexcpt::enable();
    CHECK(vmcs::host_cr4::osxmmexcpt::is_enabled());

    vmcs::host_cr4::osxmmexcpt::disable();
    CHECK(vmcs::host_cr4::osxmmexcpt::is_disabled());

    vmcs::host_cr4::osxmmexcpt::enable_if_exists();
    CHECK(vmcs::host_cr4::osxmmexcpt::is_enabled_if_exists());

    vmcs::host_cr4::osxmmexcpt::disable_if_exists();
    CHECK(vmcs::host_cr4::osxmmexcpt::is_disabled_if_exists());
}

TEST_CASE("vmcs_host_cr4_vmx_enable_bit")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::host_cr4::vmx_enable_bit::enable();
    CHECK(vmcs::host_cr4::vmx_enable_bit::is_enabled());

    vmcs::host_cr4::vmx_enable_bit::disable();
    CHECK(vmcs::host_cr4::vmx_enable_bit::is_disabled());

    vmcs::host_cr4::vmx_enable_bit::enable_if_exists();
    CHECK(vmcs::host_cr4::vmx_enable_bit::is_enabled_if_exists());

    vmcs::host_cr4::vmx_enable_bit::disable_if_exists();
    CHECK(vmcs::host_cr4::vmx_enable_bit::is_disabled_if_exists());
}

TEST_CASE("vmcs_host_cr4_smx_enable_bit")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::host_cr4::smx_enable_bit::enable();
    CHECK(vmcs::host_cr4::smx_enable_bit::is_enabled());

    vmcs::host_cr4::smx_enable_bit::disable();
    CHECK(vmcs::host_cr4::smx_enable_bit::is_disabled());

    vmcs::host_cr4::smx_enable_bit::enable_if_exists();
    CHECK(vmcs::host_cr4::smx_enable_bit::is_enabled_if_exists());

    vmcs::host_cr4::smx_enable_bit::disable_if_exists();
    CHECK(vmcs::host_cr4::smx_enable_bit::is_disabled_if_exists());
}

TEST_CASE("vmcs_host_cr4_fsgsbase_enable_bit")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::host_cr4::fsgsbase_enable_bit::enable();
    CHECK(vmcs::host_cr4::fsgsbase_enable_bit::is_enabled());

    vmcs::host_cr4::fsgsbase_enable_bit::disable();
    CHECK(vmcs::host_cr4::fsgsbase_enable_bit::is_disabled());

    vmcs::host_cr4::fsgsbase_enable_bit::enable_if_exists();
    CHECK(vmcs::host_cr4::fsgsbase_enable_bit::is_enabled_if_exists());

    vmcs::host_cr4::fsgsbase_enable_bit::disable_if_exists();
    CHECK(vmcs::host_cr4::fsgsbase_enable_bit::is_disabled_if_exists());
}

TEST_CASE("vmcs_host_cr4_pcid_enable_bit")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::host_cr4::pcid_enable_bit::enable();
    CHECK(vmcs::host_cr4::pcid_enable_bit::is_enabled());

    vmcs::host_cr4::pcid_enable_bit::disable();
    CHECK(vmcs::host_cr4::pcid_enable_bit::is_disabled());

    vmcs::host_cr4::pcid_enable_bit::enable_if_exists();
    CHECK(vmcs::host_cr4::pcid_enable_bit::is_enabled_if_exists());

    vmcs::host_cr4::pcid_enable_bit::disable_if_exists();
    CHECK(vmcs::host_cr4::pcid_enable_bit::is_disabled_if_exists());
}

TEST_CASE("vmcs_host_cr4_osxsave")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::host_cr4::osxsave::enable();
    CHECK(vmcs::host_cr4::osxsave::is_enabled());

    vmcs::host_cr4::osxsave::disable();
    CHECK(vmcs::host_cr4::osxsave::is_disabled());

    vmcs::host_cr4::osxsave::enable_if_exists();
    CHECK(vmcs::host_cr4::osxsave::is_enabled_if_exists());

    vmcs::host_cr4::osxsave::disable_if_exists();
    CHECK(vmcs::host_cr4::osxsave::is_disabled_if_exists());
}

TEST_CASE("vmcs_host_cr4_smep_enable_bit")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::host_cr4::smep_enable_bit::enable();
    CHECK(vmcs::host_cr4::smep_enable_bit::is_enabled());

    vmcs::host_cr4::smep_enable_bit::disable();
    CHECK(vmcs::host_cr4::smep_enable_bit::is_disabled());

    vmcs::host_cr4::smep_enable_bit::enable_if_exists();
    CHECK(vmcs::host_cr4::smep_enable_bit::is_enabled_if_exists());

    vmcs::host_cr4::smep_enable_bit::disable_if_exists();
    CHECK(vmcs::host_cr4::smep_enable_bit::is_disabled_if_exists());
}

TEST_CASE("vmcs_host_cr4_smap_enable_bit")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::host_cr4::smap_enable_bit::enable();
    CHECK(vmcs::host_cr4::smap_enable_bit::is_enabled());

    vmcs::host_cr4::smap_enable_bit::disable();
    CHECK(vmcs::host_cr4::smap_enable_bit::is_disabled());

    vmcs::host_cr4::smap_enable_bit::enable_if_exists();
    CHECK(vmcs::host_cr4::smap_enable_bit::is_enabled_if_exists());

    vmcs::host_cr4::smap_enable_bit::disable_if_exists();
    CHECK(vmcs::host_cr4::smap_enable_bit::is_disabled_if_exists());
}

TEST_CASE("vmcs_host_cr4_protection_key_enable_bit")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::host_cr4::protection_key_enable_bit::enable();
    CHECK(vmcs::host_cr4::protection_key_enable_bit::is_enabled());

    vmcs::host_cr4::protection_key_enable_bit::disable();
    CHECK(vmcs::host_cr4::protection_key_enable_bit::is_disabled());

    vmcs::host_cr4::protection_key_enable_bit::enable_if_exists();
    CHECK(vmcs::host_cr4::protection_key_enable_bit::is_enabled_if_exists());

    vmcs::host_cr4::protection_key_enable_bit::disable_if_exists();
    CHECK(vmcs::host_cr4::protection_key_enable_bit::is_disabled_if_exists());
}

TEST_CASE("vmcs_host_fs_base")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::host_fs_base::exists());

    vmcs::host_fs_base::set(1UL);
    CHECK(vmcs::host_fs_base::get() == 1UL);

    vmcs::host_fs_base::set_if_exists(0UL);
    CHECK(vmcs::host_fs_base::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_host_gs_base")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::host_gs_base::exists());

    vmcs::host_gs_base::set(1UL);
    CHECK(vmcs::host_gs_base::get() == 1UL);

    vmcs::host_gs_base::set_if_exists(0UL);
    CHECK(vmcs::host_gs_base::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_host_tr_base")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::host_tr_base::exists());

    vmcs::host_tr_base::set(1UL);
    CHECK(vmcs::host_tr_base::get() == 1UL);

    vmcs::host_tr_base::set_if_exists(0UL);
    CHECK(vmcs::host_tr_base::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_host_gdtr_base")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::host_gdtr_base::exists());

    vmcs::host_gdtr_base::set(1UL);
    CHECK(vmcs::host_gdtr_base::get() == 1UL);

    vmcs::host_gdtr_base::set_if_exists(0UL);
    CHECK(vmcs::host_gdtr_base::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_host_idtr_base")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::host_idtr_base::exists());

    vmcs::host_idtr_base::set(1UL);
    CHECK(vmcs::host_idtr_base::get() == 1UL);

    vmcs::host_idtr_base::set_if_exists(0UL);
    CHECK(vmcs::host_idtr_base::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_host_ia32_sysenter_esp")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::host_ia32_sysenter_esp::exists());

    vmcs::host_ia32_sysenter_esp::set(1UL);
    CHECK(vmcs::host_ia32_sysenter_esp::get() == 1UL);

    vmcs::host_ia32_sysenter_esp::set_if_exists(0UL);
    CHECK(vmcs::host_ia32_sysenter_esp::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_host_ia32_sysenter_eip")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::host_ia32_sysenter_eip::exists());

    vmcs::host_ia32_sysenter_eip::set(1UL);
    CHECK(vmcs::host_ia32_sysenter_eip::get() == 1UL);

    vmcs::host_ia32_sysenter_eip::set_if_exists(0UL);
    CHECK(vmcs::host_ia32_sysenter_eip::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_host_rsp")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::host_rsp::exists());

    vmcs::host_rsp::set(1UL);
    CHECK(vmcs::host_rsp::get() == 1UL);

    vmcs::host_rsp::set_if_exists(0UL);
    CHECK(vmcs::host_rsp::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_host_rip")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::host_rip::exists());

    vmcs::host_rip::set(1UL);
    CHECK(vmcs::host_rip::get() == 1UL);

    vmcs::host_rip::set_if_exists(0UL);
    CHECK(vmcs::host_rip::get_if_exists() == 0UL);
}

#endif
