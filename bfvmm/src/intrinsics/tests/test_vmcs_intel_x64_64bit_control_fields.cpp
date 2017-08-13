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

TEST_CASE("set_vm_function_control")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    constexpr const auto name = "control";
    auto mask = 0x0000000000000040UL;
    auto ctls_addr = 0UL;
    auto msr_addr = 0U;

    CHECK_THROWS(set_vm_function_control(true, msr_addr, ctls_addr, name, mask, false));
    CHECK_NOTHROW(set_vm_function_control(false, msr_addr, ctls_addr, name, mask, true));

    g_msrs[msr_addr] = mask;
    CHECK_NOTHROW(set_vm_function_control(true, msr_addr, ctls_addr, name, mask, true));

    g_msrs[msr_addr] = ~mask;
    CHECK_THROWS(set_vm_function_control(true, msr_addr, ctls_addr, name, mask, true));
}

TEST_CASE("set_vm_function_control_if_allowed")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    constexpr const auto name = "control";
    auto mask = 0x0000000000000040UL;
    auto ctls_addr = 0UL;
    auto msr_addr = 0U;

    CHECK_NOTHROW(set_vm_function_control_if_allowed(true, msr_addr, ctls_addr, name, mask, true, false));
    CHECK_NOTHROW(set_vm_function_control_if_allowed(false, msr_addr, ctls_addr, name, mask, true, true));

    g_msrs[msr_addr] = mask;
    CHECK_NOTHROW(set_vm_function_control_if_allowed(true, msr_addr, ctls_addr, name, mask, true, true));

    g_msrs[msr_addr] = ~mask;
    CHECK_NOTHROW(set_vm_function_control_if_allowed(true, msr_addr, ctls_addr, name, mask, true, true));
}

TEST_CASE("vmcs_address_of_io_bitmap_a")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::address_of_io_bitmap_a::exists());

    vmcs::address_of_io_bitmap_a::set(1UL);
    CHECK(vmcs::address_of_io_bitmap_a::get() == 1UL);

    vmcs::address_of_io_bitmap_a::set_if_exists(0UL);
    CHECK(vmcs::address_of_io_bitmap_a::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_address_of_io_bitmap_b")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::address_of_io_bitmap_b::exists());

    vmcs::address_of_io_bitmap_b::set(1UL);
    CHECK(vmcs::address_of_io_bitmap_b::get() == 1UL);

    vmcs::address_of_io_bitmap_b::set_if_exists(0UL);
    CHECK(vmcs::address_of_io_bitmap_b::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_address_of_msr_bitmap")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    proc_ctl_allow1(msrs::ia32_vmx_true_procbased_ctls::use_msr_bitmap::mask);
    CHECK(vmcs::address_of_msr_bitmap::exists());

    vmcs::address_of_msr_bitmap::set(1UL);
    CHECK(vmcs::address_of_msr_bitmap::get() == 1UL);

    vmcs::address_of_msr_bitmap::set_if_exists(0UL);
    CHECK(vmcs::address_of_msr_bitmap::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_vm_exit_msr_store_address")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::vm_exit_msr_store_address::exists());

    vmcs::vm_exit_msr_store_address::set(1UL);
    CHECK(vmcs::vm_exit_msr_store_address::get() == 1UL);

    vmcs::vm_exit_msr_store_address::set_if_exists(0UL);
    CHECK(vmcs::vm_exit_msr_store_address::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_vm_exit_msr_load_address")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::vm_exit_msr_load_address::exists());

    vmcs::vm_exit_msr_load_address::set(1UL);
    CHECK(vmcs::vm_exit_msr_load_address::get() == 1UL);

    vmcs::vm_exit_msr_load_address::set_if_exists(0UL);
    CHECK(vmcs::vm_exit_msr_load_address::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_vm_entry_msr_load_address")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::vm_entry_msr_load_address::exists());

    vmcs::vm_entry_msr_load_address::set(1UL);
    CHECK(vmcs::vm_entry_msr_load_address::get() == 1UL);

    vmcs::vm_entry_msr_load_address::set_if_exists(0UL);
    CHECK(vmcs::vm_entry_msr_load_address::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_executive_vmcs_pointer")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::executive_vmcs_pointer::exists());

    vmcs::executive_vmcs_pointer::set(1UL);
    CHECK(vmcs::executive_vmcs_pointer::get() == 1UL);

    vmcs::executive_vmcs_pointer::set_if_exists(0UL);
    CHECK(vmcs::executive_vmcs_pointer::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_pml_address")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    proc_ctl_allow1(msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
    proc_ctl2_allow1(msrs::ia32_vmx_procbased_ctls2::enable_pml::mask);
    CHECK(vmcs::pml_address::exists());

    vmcs::pml_address::set(1UL);
    CHECK(vmcs::pml_address::get() == 1UL);

    vmcs::pml_address::set_if_exists(0UL);
    CHECK(vmcs::pml_address::get_if_exists() == 0UL);

    proc_ctl2_disallow1(msrs::ia32_vmx_procbased_ctls2::enable_pml::mask);
    CHECK_FALSE(vmcs::pml_address::exists());

    CHECK_THROWS(vmcs::pml_address::set(42U));
    CHECK_THROWS(vmcs::pml_address::get());

    CHECK_NOTHROW(vmcs::pml_address::set_if_exists(42U));
    CHECK_NOTHROW(vmcs::pml_address::get_if_exists());
    CHECK(g_vmcs_fields[vmcs::pml_address::addr] == 0UL);
}

TEST_CASE("vmcs_tsc_offset")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::tsc_offset::exists());

    vmcs::tsc_offset::set(1UL);
    CHECK(vmcs::tsc_offset::get() == 1UL);

    vmcs::tsc_offset::set_if_exists(0UL);
    CHECK(vmcs::tsc_offset::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_virtual_apic_address")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    proc_ctl_allow1(msrs::ia32_vmx_true_procbased_ctls::use_tpr_shadow::mask);
    CHECK(vmcs::virtual_apic_address::exists());

    vmcs::virtual_apic_address::set(1UL);
    CHECK(vmcs::virtual_apic_address::get() == 1UL);

    vmcs::virtual_apic_address::set_if_exists(0UL);
    CHECK(vmcs::virtual_apic_address::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_apic_access_address")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    proc_ctl_allow1(msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
    proc_ctl2_allow1(msrs::ia32_vmx_procbased_ctls2::virtualize_apic_accesses::mask);
    CHECK(vmcs::apic_access_address::exists());

    vmcs::apic_access_address::set(1UL);
    CHECK(vmcs::apic_access_address::get() == 1UL);

    vmcs::apic_access_address::set_if_exists(0UL);
    CHECK(vmcs::apic_access_address::get_if_exists() == 0UL);

    proc_ctl2_disallow1(msrs::ia32_vmx_procbased_ctls2::virtualize_apic_accesses::mask);
    CHECK_FALSE(vmcs::apic_access_address::exists());

    CHECK_THROWS(vmcs::apic_access_address::set(42U));
    CHECK_THROWS(vmcs::apic_access_address::get());

    CHECK_NOTHROW(vmcs::apic_access_address::set_if_exists(42U));
    CHECK_NOTHROW(vmcs::apic_access_address::get_if_exists());
    CHECK(g_vmcs_fields[vmcs::apic_access_address::addr] == 0UL);
}

TEST_CASE("vmcs_posted_interrupt_descriptor_address")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    pin_ctl_allow1(msrs::ia32_vmx_true_pinbased_ctls::process_posted_interrupts::mask);
    CHECK(vmcs::posted_interrupt_descriptor_address::exists());

    vmcs::posted_interrupt_descriptor_address::set(1UL);
    CHECK(vmcs::posted_interrupt_descriptor_address::get() == 1UL);

    vmcs::posted_interrupt_descriptor_address::set_if_exists(0UL);
    CHECK(vmcs::posted_interrupt_descriptor_address::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_vm_function_controls")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    proc_ctl_allow1(msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
    proc_ctl2_allow1(msrs::ia32_vmx_procbased_ctls2::enable_vm_functions::mask);
    CHECK(vmcs::vm_function_controls::exists());

    vmcs::vm_function_controls::set(1UL);
    CHECK(vmcs::vm_function_controls::get() == 1UL);

    vmcs::vm_function_controls::set_if_exists(0UL);
    CHECK(vmcs::vm_function_controls::get_if_exists() == 0UL);

    proc_ctl2_disallow1(msrs::ia32_vmx_procbased_ctls2::enable_vm_functions::mask);
    CHECK_FALSE(vmcs::vm_function_controls::exists());

    CHECK_THROWS(vmcs::vm_function_controls::set(42U));
    CHECK_THROWS(vmcs::vm_function_controls::get());

    CHECK_NOTHROW(vmcs::vm_function_controls::set_if_exists(42U));
    CHECK_NOTHROW(vmcs::vm_function_controls::get_if_exists());
    CHECK(g_vmcs_fields[vmcs::vm_function_controls::addr] == 0UL);
}

TEST_CASE("vmcs_vm_function_controls_eptp_switching")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    proc_ctl_allow1(msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
    proc_ctl2_allow1(msrs::ia32_vmx_procbased_ctls2::enable_vm_functions::mask);
    vmfunc_ctl_allow1(msrs::ia32_vmx_vmfunc::eptp_switching::mask);

    vmcs::vm_function_controls::eptp_switching::enable();
    CHECK(vmcs::vm_function_controls::eptp_switching::is_enabled());

    vmcs::vm_function_controls::eptp_switching::disable();
    CHECK(vmcs::vm_function_controls::eptp_switching::is_disabled());

    vmcs::vm_function_controls::eptp_switching::enable_if_allowed();
    CHECK(vmcs::vm_function_controls::eptp_switching::is_enabled_if_exists());

    vmcs::vm_function_controls::eptp_switching::disable_if_allowed();
    CHECK(vmcs::vm_function_controls::eptp_switching::is_disabled_if_exists());
}

TEST_CASE("vmcs_vm_function_controls_reserved")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    proc_ctl_allow1(msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
    proc_ctl2_allow1(msrs::ia32_vmx_procbased_ctls2::enable_vm_functions::mask);

    vmcs::vm_function_controls::reserved::set(0xEU);
    CHECK(vmcs::vm_function_controls::reserved::get() == 0xEU);

    vmcs::vm_function_controls::reserved::set_if_exists(0x0U);
    CHECK(vmcs::vm_function_controls::reserved::get_if_exists() == 0x0U);
}

TEST_CASE("vmcs_ept_pointer")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    proc_ctl_allow1(msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
    proc_ctl2_allow1(msrs::ia32_vmx_procbased_ctls2::enable_ept::mask);
    CHECK(vmcs::ept_pointer::exists());

    vmcs::ept_pointer::set(1UL);
    CHECK(vmcs::ept_pointer::get() == 1UL);

    vmcs::ept_pointer::set_if_exists(0UL);
    CHECK(vmcs::ept_pointer::get_if_exists() == 0UL);

    proc_ctl2_disallow1(msrs::ia32_vmx_procbased_ctls2::enable_ept::mask);
    CHECK_FALSE(vmcs::ept_pointer::exists());

    CHECK_THROWS(vmcs::ept_pointer::set(42U));
    CHECK_THROWS(vmcs::ept_pointer::get());

    CHECK_NOTHROW(vmcs::ept_pointer::set_if_exists(42U));
    CHECK_NOTHROW(vmcs::ept_pointer::get_if_exists());
    CHECK(g_vmcs_fields[vmcs::ept_pointer::addr] == 0UL);
}

TEST_CASE("vmcs_ept_pointer_memory_type")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    proc_ctl_allow1(msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
    proc_ctl2_allow1(msrs::ia32_vmx_procbased_ctls2::enable_ept::mask);

    vmcs::ept_pointer::memory_type::set(0UL);
    CHECK(vmcs::ept_pointer::memory_type::get() ==
          vmcs::ept_pointer::memory_type::uncacheable);

    vmcs::ept_pointer::memory_type::set_if_exists(6UL);
    CHECK(vmcs::ept_pointer::memory_type::get_if_exists() ==
          vmcs::ept_pointer::memory_type::write_back);

    proc_ctl2_disallow1(msrs::ia32_vmx_procbased_ctls2::enable_ept::mask);
    CHECK_THROWS(vmcs::ept_pointer::memory_type::set(42U));
    CHECK_THROWS(vmcs::ept_pointer::memory_type::get());

    CHECK_NOTHROW(vmcs::ept_pointer::memory_type::set_if_exists(42U));
    CHECK_NOTHROW(vmcs::ept_pointer::memory_type::get_if_exists());
}

TEST_CASE("vmcs_ept_pointer_page_walk_length_minus_one")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    proc_ctl_allow1(msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
    proc_ctl2_allow1(msrs::ia32_vmx_procbased_ctls2::enable_ept::mask);

    vmcs::ept_pointer::page_walk_length_minus_one::set(2UL);
    CHECK(vmcs::ept_pointer::page_walk_length_minus_one::get() == 2UL);

    vmcs::ept_pointer::page_walk_length_minus_one::set_if_exists(1UL);
    CHECK(vmcs::ept_pointer::page_walk_length_minus_one::get_if_exists() == 1UL);

    proc_ctl2_disallow1(msrs::ia32_vmx_procbased_ctls2::enable_ept::mask);
    CHECK_THROWS(vmcs::ept_pointer::page_walk_length_minus_one::set(42U));
    CHECK_THROWS(vmcs::ept_pointer::page_walk_length_minus_one::get());

    CHECK_NOTHROW(vmcs::ept_pointer::page_walk_length_minus_one::set_if_exists(42U));
    CHECK_NOTHROW(vmcs::ept_pointer::page_walk_length_minus_one::get_if_exists());
}

TEST_CASE("vmcs_ept_pointer_accessed_and_dirty_flags")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    proc_ctl_allow1(msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
    proc_ctl2_allow1(msrs::ia32_vmx_procbased_ctls2::enable_ept::mask);

    vmcs::ept_pointer::accessed_and_dirty_flags::enable();
    CHECK(vmcs::ept_pointer::accessed_and_dirty_flags::is_enabled());

    vmcs::ept_pointer::accessed_and_dirty_flags::disable();
    CHECK(vmcs::ept_pointer::accessed_and_dirty_flags::is_disabled());

    vmcs::ept_pointer::accessed_and_dirty_flags::enable_if_exists();
    CHECK(vmcs::ept_pointer::accessed_and_dirty_flags::is_enabled_if_exists());

    vmcs::ept_pointer::accessed_and_dirty_flags::disable_if_exists();
    CHECK(vmcs::ept_pointer::accessed_and_dirty_flags::is_disabled_if_exists());
}

TEST_CASE("vmcs_ept_pointer_phys_addr")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    proc_ctl_allow1(msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
    proc_ctl2_allow1(msrs::ia32_vmx_procbased_ctls2::enable_ept::mask);

    vmcs::ept_pointer::phys_addr::set(0x0000ABCDEF123000UL);
    CHECK(vmcs::ept_pointer::phys_addr::get() == 0x0000ABCDEF123000UL);

    vmcs::ept_pointer::phys_addr::set_if_exists(0x0U);
    CHECK(vmcs::ept_pointer::phys_addr::get_if_exists() == 0x0U);
}

TEST_CASE("vmcs_ept_pointer_reserved")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    proc_ctl_allow1(msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
    proc_ctl2_allow1(msrs::ia32_vmx_procbased_ctls2::enable_ept::mask);

    vmcs::ept_pointer::reserved::set(0x80U);
    CHECK(vmcs::ept_pointer::reserved::get() == 0x80U);

    vmcs::ept_pointer::reserved::set_if_exists(0x0U);
    CHECK(vmcs::ept_pointer::reserved::get_if_exists() == 0x0U);
}

TEST_CASE("vmcs_eoi_exit_bitmap_0")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    proc_ctl_allow1(msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
    proc_ctl2_allow1(msrs::ia32_vmx_procbased_ctls2::virtual_interrupt_delivery::mask);
    CHECK(vmcs::eoi_exit_bitmap_0::exists());

    vmcs::eoi_exit_bitmap_0::set(1UL);
    CHECK(vmcs::eoi_exit_bitmap_0::get() == 1UL);

    vmcs::eoi_exit_bitmap_0::set_if_exists(0UL);
    CHECK(vmcs::eoi_exit_bitmap_0::get_if_exists() == 0UL);

    proc_ctl2_disallow1(msrs::ia32_vmx_procbased_ctls2::virtual_interrupt_delivery::mask);
    CHECK_FALSE(vmcs::eoi_exit_bitmap_0::exists());

    CHECK_THROWS(vmcs::eoi_exit_bitmap_0::set(42U));
    CHECK_THROWS(vmcs::eoi_exit_bitmap_0::get());

    CHECK_NOTHROW(vmcs::eoi_exit_bitmap_0::set_if_exists(42U));
    CHECK_NOTHROW(vmcs::eoi_exit_bitmap_0::get_if_exists());
    CHECK(g_vmcs_fields[vmcs::eoi_exit_bitmap_0::addr] == 0UL);
}

TEST_CASE("vmcs_eoi_exit_bitmap_1")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    proc_ctl_allow1(msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
    proc_ctl2_allow1(msrs::ia32_vmx_procbased_ctls2::virtual_interrupt_delivery::mask);
    CHECK(vmcs::eoi_exit_bitmap_1::exists());

    vmcs::eoi_exit_bitmap_1::set(1UL);
    CHECK(vmcs::eoi_exit_bitmap_1::get() == 1UL);

    vmcs::eoi_exit_bitmap_1::set_if_exists(0UL);
    CHECK(vmcs::eoi_exit_bitmap_1::get_if_exists() == 0UL);

    proc_ctl2_disallow1(msrs::ia32_vmx_procbased_ctls2::virtual_interrupt_delivery::mask);
    CHECK_FALSE(vmcs::eoi_exit_bitmap_1::exists());

    CHECK_THROWS(vmcs::eoi_exit_bitmap_1::set(42U));
    CHECK_THROWS(vmcs::eoi_exit_bitmap_1::get());

    CHECK_NOTHROW(vmcs::eoi_exit_bitmap_1::set_if_exists(42U));
    CHECK_NOTHROW(vmcs::eoi_exit_bitmap_1::get_if_exists());
    CHECK(g_vmcs_fields[vmcs::eoi_exit_bitmap_1::addr] == 0UL);
}

TEST_CASE("vmcs_eoi_exit_bitmap_2")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    proc_ctl_allow1(msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
    proc_ctl2_allow1(msrs::ia32_vmx_procbased_ctls2::virtual_interrupt_delivery::mask);
    CHECK(vmcs::eoi_exit_bitmap_2::exists());

    vmcs::eoi_exit_bitmap_2::set(1UL);
    CHECK(vmcs::eoi_exit_bitmap_2::get() == 1UL);

    vmcs::eoi_exit_bitmap_2::set_if_exists(0UL);
    CHECK(vmcs::eoi_exit_bitmap_2::get_if_exists() == 0UL);

    proc_ctl2_disallow1(msrs::ia32_vmx_procbased_ctls2::virtual_interrupt_delivery::mask);
    CHECK_FALSE(vmcs::eoi_exit_bitmap_2::exists());

    CHECK_THROWS(vmcs::eoi_exit_bitmap_2::set(42U));
    CHECK_THROWS(vmcs::eoi_exit_bitmap_2::get());

    CHECK_NOTHROW(vmcs::eoi_exit_bitmap_2::set_if_exists(42U));
    CHECK_NOTHROW(vmcs::eoi_exit_bitmap_2::get_if_exists());
    CHECK(g_vmcs_fields[vmcs::eoi_exit_bitmap_2::addr] == 0UL);
}

TEST_CASE("vmcs_eoi_exit_bitmap_3")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    proc_ctl_allow1(msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
    proc_ctl2_allow1(msrs::ia32_vmx_procbased_ctls2::virtual_interrupt_delivery::mask);
    CHECK(vmcs::eoi_exit_bitmap_3::exists());

    vmcs::eoi_exit_bitmap_3::set(1UL);
    CHECK(vmcs::eoi_exit_bitmap_3::get() == 1UL);

    vmcs::eoi_exit_bitmap_3::set_if_exists(0UL);
    CHECK(vmcs::eoi_exit_bitmap_3::get_if_exists() == 0UL);

    proc_ctl2_disallow1(msrs::ia32_vmx_procbased_ctls2::virtual_interrupt_delivery::mask);
    CHECK_FALSE(vmcs::eoi_exit_bitmap_3::exists());

    CHECK_THROWS(vmcs::eoi_exit_bitmap_3::set(42U));
    CHECK_THROWS(vmcs::eoi_exit_bitmap_3::get());

    CHECK_NOTHROW(vmcs::eoi_exit_bitmap_3::set_if_exists(42U));
    CHECK_NOTHROW(vmcs::eoi_exit_bitmap_3::get_if_exists());
    CHECK(g_vmcs_fields[vmcs::eoi_exit_bitmap_3::addr] == 0UL);
}

TEST_CASE("vmcs_eptp_list_address")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    proc_ctl_allow1(msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
    proc_ctl2_allow1(msrs::ia32_vmx_procbased_ctls2::enable_vm_functions::mask);
    vmfunc_ctl_allow1(msrs::ia32_vmx_vmfunc::eptp_switching::mask);
    CHECK(vmcs::eptp_list_address::exists());

    vmcs::eptp_list_address::set(1UL);
    CHECK(vmcs::eptp_list_address::get() == 1UL);

    vmcs::eptp_list_address::set_if_exists(0UL);
    CHECK(vmcs::eptp_list_address::get_if_exists() == 0UL);

    proc_ctl2_disallow1(msrs::ia32_vmx_procbased_ctls2::enable_vm_functions::mask);
    CHECK_FALSE(vmcs::eptp_list_address::exists());

    CHECK_THROWS(vmcs::eptp_list_address::set(42U));
    CHECK_THROWS(vmcs::eptp_list_address::get());

    CHECK_NOTHROW(vmcs::eptp_list_address::set_if_exists(42U));
    CHECK_NOTHROW(vmcs::eptp_list_address::get_if_exists());
    CHECK(g_vmcs_fields[vmcs::eptp_list_address::addr] == 0UL);
}

TEST_CASE("vmcs_vmread_bitmap_address")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    proc_ctl_allow1(msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
    proc_ctl2_allow1(msrs::ia32_vmx_procbased_ctls2::vmcs_shadowing::mask);
    CHECK(vmcs::vmread_bitmap_address::exists());

    vmcs::vmread_bitmap_address::set(1UL);
    CHECK(vmcs::vmread_bitmap_address::get() == 1UL);

    vmcs::vmread_bitmap_address::set_if_exists(0UL);
    CHECK(vmcs::vmread_bitmap_address::get_if_exists() == 0UL);

    proc_ctl2_disallow1(msrs::ia32_vmx_procbased_ctls2::vmcs_shadowing::mask);
    CHECK_FALSE(vmcs::vmread_bitmap_address::exists());

    CHECK_THROWS(vmcs::vmread_bitmap_address::set(42U));
    CHECK_THROWS(vmcs::vmread_bitmap_address::get());

    CHECK_NOTHROW(vmcs::vmread_bitmap_address::set_if_exists(42U));
    CHECK_NOTHROW(vmcs::vmread_bitmap_address::get_if_exists());
    CHECK(g_vmcs_fields[vmcs::vmread_bitmap_address::addr] == 0UL);
}

TEST_CASE("vmcs_vmwrite_bitmap_address")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    proc_ctl_allow1(msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
    proc_ctl2_allow1(msrs::ia32_vmx_procbased_ctls2::vmcs_shadowing::mask);
    CHECK(vmcs::vmwrite_bitmap_address::exists());

    vmcs::vmwrite_bitmap_address::set(1UL);
    CHECK(vmcs::vmwrite_bitmap_address::get() == 1UL);

    vmcs::vmwrite_bitmap_address::set_if_exists(0UL);
    CHECK(vmcs::vmwrite_bitmap_address::get_if_exists() == 0UL);

    proc_ctl2_disallow1(msrs::ia32_vmx_procbased_ctls2::vmcs_shadowing::mask);
    CHECK_FALSE(vmcs::vmwrite_bitmap_address::exists());

    CHECK_THROWS(vmcs::vmwrite_bitmap_address::set(42U));
    CHECK_THROWS(vmcs::vmwrite_bitmap_address::get());

    CHECK_NOTHROW(vmcs::vmwrite_bitmap_address::set_if_exists(42U));
    CHECK_NOTHROW(vmcs::vmwrite_bitmap_address::get_if_exists());
    CHECK(g_vmcs_fields[vmcs::vmwrite_bitmap_address::addr] == 0UL);
}

TEST_CASE("vmcs_virtualization_exception_information_address")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    proc_ctl_allow1(msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
    proc_ctl2_allow1(msrs::ia32_vmx_procbased_ctls2::ept_violation_ve::mask);
    CHECK(vmcs::virtualization_exception_information_address::exists());

    vmcs::virtualization_exception_information_address::set(1UL);
    CHECK(vmcs::virtualization_exception_information_address::get() == 1UL);

    vmcs::virtualization_exception_information_address::set_if_exists(0UL);
    CHECK(vmcs::virtualization_exception_information_address::get_if_exists() == 0UL);

    proc_ctl2_disallow1(msrs::ia32_vmx_procbased_ctls2::ept_violation_ve::mask);
    CHECK_FALSE(vmcs::virtualization_exception_information_address::exists());

    CHECK_THROWS(vmcs::virtualization_exception_information_address::set(42U));
    CHECK_THROWS(vmcs::virtualization_exception_information_address::get());

    CHECK_NOTHROW(vmcs::virtualization_exception_information_address::set_if_exists(42U));
    CHECK_NOTHROW(vmcs::virtualization_exception_information_address::get_if_exists());
    CHECK(g_vmcs_fields[vmcs::virtualization_exception_information_address::addr] == 0UL);
}

TEST_CASE("vmcs_xss_exiting_bitmap")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    proc_ctl_allow1(msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
    proc_ctl2_allow1(msrs::ia32_vmx_procbased_ctls2::enable_xsaves_xrstors::mask);
    CHECK(vmcs::xss_exiting_bitmap::exists());

    vmcs::xss_exiting_bitmap::set(1UL);
    CHECK(vmcs::xss_exiting_bitmap::get() == 1UL);

    vmcs::xss_exiting_bitmap::set_if_exists(0UL);
    CHECK(vmcs::xss_exiting_bitmap::get_if_exists() == 0UL);

    proc_ctl2_disallow1(msrs::ia32_vmx_procbased_ctls2::enable_xsaves_xrstors::mask);
    CHECK_FALSE(vmcs::xss_exiting_bitmap::exists());

    CHECK_THROWS(vmcs::xss_exiting_bitmap::set(42U));
    CHECK_THROWS(vmcs::xss_exiting_bitmap::get());

    CHECK_NOTHROW(vmcs::xss_exiting_bitmap::set_if_exists(42U));
    CHECK_NOTHROW(vmcs::xss_exiting_bitmap::get_if_exists());
    CHECK(g_vmcs_fields[vmcs::xss_exiting_bitmap::addr] == 0UL);
}

TEST_CASE("vmcs_encls_exiting_bitmap")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    proc_ctl_allow1(msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
    proc_ctl2_allow1(msrs::ia32_vmx_procbased_ctls2::enable_encls_exiting::mask);
    CHECK(vmcs::encls_exiting_bitmap::exists());

    vmcs::encls_exiting_bitmap::set(1UL);
    CHECK(vmcs::encls_exiting_bitmap::get() == 1UL);

    vmcs::encls_exiting_bitmap::set_if_exists(0UL);
    CHECK(vmcs::encls_exiting_bitmap::get_if_exists() == 0UL);

    proc_ctl2_disallow1(msrs::ia32_vmx_procbased_ctls2::enable_encls_exiting::mask);
    CHECK_FALSE(vmcs::encls_exiting_bitmap::exists());

    CHECK_THROWS(vmcs::encls_exiting_bitmap::set(42U));
    CHECK_THROWS(vmcs::encls_exiting_bitmap::get());

    CHECK_NOTHROW(vmcs::encls_exiting_bitmap::set_if_exists(42U));
    CHECK_NOTHROW(vmcs::encls_exiting_bitmap::get_if_exists());
    CHECK(g_vmcs_fields[vmcs::encls_exiting_bitmap::addr] == 0UL);
}

TEST_CASE("vmcs_tsc_multiplier")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    proc_ctl_allow1(msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
    proc_ctl2_allow1(msrs::ia32_vmx_procbased_ctls2::use_tsc_scaling::mask);
    CHECK(vmcs::tsc_multiplier::exists());

    vmcs::tsc_multiplier::set(1UL);
    CHECK(vmcs::tsc_multiplier::get() == 1UL);

    vmcs::tsc_multiplier::set_if_exists(0UL);
    CHECK(vmcs::tsc_multiplier::get_if_exists() == 0UL);

    proc_ctl2_disallow1(msrs::ia32_vmx_procbased_ctls2::use_tsc_scaling::mask);
    CHECK_FALSE(vmcs::tsc_multiplier::exists());

    CHECK_THROWS(vmcs::tsc_multiplier::set(42U));
    CHECK_THROWS(vmcs::tsc_multiplier::get());

    CHECK_NOTHROW(vmcs::tsc_multiplier::set_if_exists(42U));
    CHECK_NOTHROW(vmcs::tsc_multiplier::get_if_exists());
    CHECK(g_vmcs_fields[vmcs::tsc_multiplier::addr] == 0UL);
}

#endif
