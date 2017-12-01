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

TEST_CASE("vmcs_address_of_io_bitmap_a")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::address_of_io_bitmap_a;

    CHECK(exists());
    set(100UL);
    CHECK(get() == 100UL);
    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    dump(0);
}

TEST_CASE("vmcs_address_of_io_bitmap_b")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::address_of_io_bitmap_b;

    CHECK(exists());
    set(100UL);
    CHECK(get() == 100UL);
    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    dump(0);
}

TEST_CASE("vmcs_address_of_msr_bitmap")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    proc_ctl_allow1(msrs::ia32_vmx_true_procbased_ctls::use_msr_bitmap::mask);

    using namespace vmcs::address_of_msr_bitmap;

    CHECK(exists());
    set(100UL);
    CHECK(get() == 100UL);
    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    dump(0);
}

TEST_CASE("vmcs_vm_exit_msr_store_address")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_msr_store_address;

    CHECK(exists());
    set(100UL);
    CHECK(get() == 100UL);
    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    dump(0);
}

TEST_CASE("vmcs_vm_exit_msr_load_address")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_msr_load_address;

    CHECK(exists());
    set(100UL);
    CHECK(get() == 100UL);
    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    dump(0);
}

TEST_CASE("vmcs_vm_entry_msr_load_address")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_entry_msr_load_address;

    CHECK(exists());
    set(100UL);
    CHECK(get() == 100UL);
    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    dump(0);
}

TEST_CASE("vmcs_executive_vmcs_pointer")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::executive_vmcs_pointer;

    CHECK(exists());
    set(100UL);
    CHECK(get() == 100UL);
    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    dump(0);
}

TEST_CASE("vmcs_pml_address")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::pml_address;

    proc_ctl_allow1(msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
    proc_ctl2_allow1(msrs::ia32_vmx_procbased_ctls2::enable_pml::mask);

    CHECK(exists());
    set(100UL);
    CHECK(get() == 100UL);
    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    proc_ctl2_disallow1(msrs::ia32_vmx_procbased_ctls2::enable_pml::mask);
    CHECK_FALSE(exists());

    CHECK_THROWS(set(42U));
    CHECK_THROWS(get());

    CHECK_NOTHROW(set_if_exists(42U));
    CHECK_NOTHROW(get_if_exists());

    dump(0);
}

TEST_CASE("vmcs_tsc_offset")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::tsc_offset;

    CHECK(exists());
    set(100UL);
    CHECK(get() == 100UL);
    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    dump(0);
}

TEST_CASE("vmcs_virtual_apic_address")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::virtual_apic_address;

    proc_ctl_allow1(msrs::ia32_vmx_true_procbased_ctls::use_tpr_shadow::mask);

    CHECK(exists());
    set(100UL);
    CHECK(get() == 100UL);
    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    dump(0);
}

TEST_CASE("vmcs_apic_access_address")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::apic_access_address;

    proc_ctl_allow1(msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
    proc_ctl2_allow1(msrs::ia32_vmx_procbased_ctls2::virtualize_apic_accesses::mask);

    CHECK(exists());
    set(100UL);
    CHECK(get() == 100UL);
    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    proc_ctl2_disallow1(msrs::ia32_vmx_procbased_ctls2::virtualize_apic_accesses::mask);

    CHECK_FALSE(exists());
    CHECK_THROWS(set(42U));
    CHECK_THROWS(get());
    CHECK_NOTHROW(set_if_exists(42U));
    CHECK_NOTHROW(get_if_exists());

    dump(0);
}

TEST_CASE("vmcs_posted_interrupt_descriptor_address")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::posted_interrupt_descriptor_address;

    pin_ctl_allow1(msrs::ia32_vmx_true_pinbased_ctls::process_posted_interrupts::mask);

    CHECK(exists());
    set(100UL);
    CHECK(get() == 100UL);
    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    dump(0);
}

TEST_CASE("vmcs_vm_function_controls")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_function_controls;

    proc_ctl_allow1(msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
    proc_ctl2_allow1(msrs::ia32_vmx_procbased_ctls2::enable_vm_functions::mask);

    CHECK(exists());
    set(100UL);
    CHECK(get() == 100UL);
    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    proc_ctl2_disallow1(msrs::ia32_vmx_procbased_ctls2::enable_vm_functions::mask);

    CHECK_FALSE(exists());
    CHECK_THROWS(set(42U));
    CHECK_THROWS(get());
    CHECK_NOTHROW(set_if_exists(42U));
    CHECK_NOTHROW(get_if_exists());

    dump(0);
}

TEST_CASE("vmcs_vm_function_controls_eptp_switching")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_function_controls;

    proc_ctl_allow1(msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
    proc_ctl2_allow1(msrs::ia32_vmx_procbased_ctls2::enable_vm_functions::mask);
    vmfunc_ctl_allow1(msrs::ia32_vmx_vmfunc::eptp_switching::mask);

    eptp_switching::set(true);
    CHECK(eptp_switching::is_enabled());
    eptp_switching::set(false);
    CHECK(eptp_switching::is_disabled());

    eptp_switching::set(eptp_switching::mask, true);
    CHECK(eptp_switching::is_enabled(eptp_switching::mask));
    eptp_switching::set(0x0, false);
    CHECK(eptp_switching::is_disabled(0x0));

    eptp_switching::set_if_exists(true);
    CHECK(eptp_switching::is_enabled_if_exists());
    eptp_switching::set_if_exists(false);
    CHECK(eptp_switching::is_disabled_if_exists());
}

TEST_CASE("vmcs_vm_function_controls_reserved")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_function_controls;

    proc_ctl_allow1(msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
    proc_ctl2_allow1(msrs::ia32_vmx_procbased_ctls2::enable_vm_functions::mask);

    reserved::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(reserved::get() == (reserved::mask >> reserved::from));

    reserved::set(reserved::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(reserved::get(reserved::mask) == (reserved::mask >> reserved::from));

    reserved::set_if_exists(0xFFFFFFFFFFFFFFFFULL);
    CHECK(reserved::get_if_exists() == (reserved::mask >> reserved::from));
}

TEST_CASE("vmcs_ept_pointer")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::ept_pointer;

    proc_ctl_allow1(msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
    proc_ctl2_allow1(msrs::ia32_vmx_procbased_ctls2::enable_ept::mask);

    CHECK(exists());
    set(100UL);
    CHECK(get() == 100UL);
    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    proc_ctl2_disallow1(msrs::ia32_vmx_procbased_ctls2::enable_ept::mask);

    CHECK_FALSE(exists());
    CHECK_THROWS(set(42U));
    CHECK_THROWS(get());
    CHECK_NOTHROW(set_if_exists(42U));
    CHECK_NOTHROW(get_if_exists());

    dump(0);
}

TEST_CASE("vmcs_ept_pointer_memory_type")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::ept_pointer;

    proc_ctl_allow1(msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
    proc_ctl2_allow1(msrs::ia32_vmx_procbased_ctls2::enable_ept::mask);

    memory_type::set(0UL);
    CHECK(memory_type::get() == memory_type::uncacheable);
    memory_type::set(memory_type::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(memory_type::get(memory_type::mask) == (memory_type::mask >> memory_type::from));
    memory_type::set_if_exists(6UL);
    CHECK(memory_type::get_if_exists() == memory_type::write_back);

    proc_ctl2_disallow1(msrs::ia32_vmx_procbased_ctls2::enable_ept::mask);

    CHECK_THROWS(memory_type::set(42U));
    CHECK_THROWS(memory_type::get());
    CHECK_NOTHROW(memory_type::set_if_exists(42U));
    CHECK_NOTHROW(memory_type::get_if_exists());
}

TEST_CASE("vmcs_ept_pointer_page_walk_length_minus_one")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::ept_pointer;

    proc_ctl_allow1(msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
    proc_ctl2_allow1(msrs::ia32_vmx_procbased_ctls2::enable_ept::mask);

    page_walk_length_minus_one::set(2UL);
    CHECK(page_walk_length_minus_one::get() == 2UL);
    memory_type::set(memory_type::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(memory_type::get(memory_type::mask) == (memory_type::mask >> memory_type::from));
    page_walk_length_minus_one::set_if_exists(1UL);
    CHECK(page_walk_length_minus_one::get_if_exists() == 1UL);

    proc_ctl2_disallow1(msrs::ia32_vmx_procbased_ctls2::enable_ept::mask);

    CHECK_THROWS(page_walk_length_minus_one::set(42U));
    CHECK_THROWS(page_walk_length_minus_one::get());
    CHECK_NOTHROW(page_walk_length_minus_one::set_if_exists(42U));
    CHECK_NOTHROW(page_walk_length_minus_one::get_if_exists());
}

TEST_CASE("vmcs_ept_pointer_accessed_and_dirty_flags")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::ept_pointer;

    proc_ctl_allow1(msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
    proc_ctl2_allow1(msrs::ia32_vmx_procbased_ctls2::enable_ept::mask);

    accessed_and_dirty_flags::set(true);
    CHECK(accessed_and_dirty_flags::is_enabled());
    accessed_and_dirty_flags::set(false);
    CHECK(accessed_and_dirty_flags::is_disabled());

    accessed_and_dirty_flags::set(accessed_and_dirty_flags::mask, true);
    CHECK(accessed_and_dirty_flags::is_enabled(accessed_and_dirty_flags::mask));
    accessed_and_dirty_flags::set(0x0, false);
    CHECK(accessed_and_dirty_flags::is_disabled(0x0));

    accessed_and_dirty_flags::set_if_exists(true);
    CHECK(accessed_and_dirty_flags::is_enabled_if_exists());
    accessed_and_dirty_flags::set_if_exists(false);
    CHECK(accessed_and_dirty_flags::is_disabled_if_exists());
}

TEST_CASE("vmcs_ept_pointer_phys_addr")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::ept_pointer;

    proc_ctl_allow1(msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
    proc_ctl2_allow1(msrs::ia32_vmx_procbased_ctls2::enable_ept::mask);

    phys_addr::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(phys_addr::get() == (phys_addr::mask >> phys_addr::from));

    phys_addr::set(phys_addr::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(phys_addr::get(phys_addr::mask) == (phys_addr::mask >> phys_addr::from));

    phys_addr::set_if_exists(0xFFFFFFFFFFFFFFFFULL);
    CHECK(phys_addr::get_if_exists() == (phys_addr::mask >> phys_addr::from));
}

TEST_CASE("vmcs_ept_pointer_reserved")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::ept_pointer;

    proc_ctl_allow1(msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
    proc_ctl2_allow1(msrs::ia32_vmx_procbased_ctls2::enable_ept::mask);

    reserved::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(reserved::get() == (reserved::mask >> reserved::from));

    reserved::set(reserved::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(reserved::get(reserved::mask) == (reserved::mask >> reserved::from));

    reserved::set_if_exists(0xFFFFFFFFFFFFFFFFULL);
    CHECK(reserved::get_if_exists() == (reserved::mask >> reserved::from));
}

TEST_CASE("vmcs_eoi_exit_bitmap_0")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::eoi_exit_bitmap_0;

    proc_ctl_allow1(msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
    proc_ctl2_allow1(msrs::ia32_vmx_procbased_ctls2::virtual_interrupt_delivery::mask);

    CHECK(exists());
    set(100UL);
    CHECK(get() == 100UL);
    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    proc_ctl2_disallow1(msrs::ia32_vmx_procbased_ctls2::virtual_interrupt_delivery::mask);

    CHECK_FALSE(exists());
    CHECK_THROWS(set(42U));
    CHECK_THROWS(get());
    CHECK_NOTHROW(set_if_exists(42U));
    CHECK_NOTHROW(get_if_exists());

    dump(0);
}

TEST_CASE("vmcs_eoi_exit_bitmap_1")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::eoi_exit_bitmap_1;

    proc_ctl_allow1(msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
    proc_ctl2_allow1(msrs::ia32_vmx_procbased_ctls2::virtual_interrupt_delivery::mask);

    CHECK(exists());
    set(100UL);
    CHECK(get() == 100UL);
    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    proc_ctl2_disallow1(msrs::ia32_vmx_procbased_ctls2::virtual_interrupt_delivery::mask);

    CHECK_FALSE(exists());
    CHECK_THROWS(set(42U));
    CHECK_THROWS(get());
    CHECK_NOTHROW(set_if_exists(42U));
    CHECK_NOTHROW(get_if_exists());

    dump(0);
}

TEST_CASE("vmcs_eoi_exit_bitmap_2")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::eoi_exit_bitmap_2;

    proc_ctl_allow1(msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
    proc_ctl2_allow1(msrs::ia32_vmx_procbased_ctls2::virtual_interrupt_delivery::mask);

    CHECK(exists());
    set(100UL);
    CHECK(get() == 100UL);
    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    proc_ctl2_disallow1(msrs::ia32_vmx_procbased_ctls2::virtual_interrupt_delivery::mask);

    CHECK_FALSE(exists());
    CHECK_THROWS(set(42U));
    CHECK_THROWS(get());
    CHECK_NOTHROW(set_if_exists(42U));
    CHECK_NOTHROW(get_if_exists());

    dump(0);
}

TEST_CASE("vmcs_eoi_exit_bitmap_3")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::eoi_exit_bitmap_3;

    proc_ctl_allow1(msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
    proc_ctl2_allow1(msrs::ia32_vmx_procbased_ctls2::virtual_interrupt_delivery::mask);

    CHECK(exists());
    set(100UL);
    CHECK(get() == 100UL);
    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    proc_ctl2_disallow1(msrs::ia32_vmx_procbased_ctls2::virtual_interrupt_delivery::mask);

    CHECK_FALSE(exists());
    CHECK_THROWS(set(42U));
    CHECK_THROWS(get());
    CHECK_NOTHROW(set_if_exists(42U));
    CHECK_NOTHROW(get_if_exists());

    dump(0);
}

TEST_CASE("vmcs_eptp_list_address")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::eptp_list_address;

    proc_ctl_allow1(msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
    proc_ctl2_allow1(msrs::ia32_vmx_procbased_ctls2::enable_vm_functions::mask);
    vmfunc_ctl_allow1(msrs::ia32_vmx_vmfunc::eptp_switching::mask);

    //    CHECK(exists());
    //    set(100UL);
    //    CHECK(get() == 100UL);
    //    set_if_exists(200UL);
    //    CHECK(get_if_exists() == 200UL);

    proc_ctl2_disallow1(msrs::ia32_vmx_procbased_ctls2::enable_vm_functions::mask);

    CHECK_FALSE(exists());
    CHECK_THROWS(set(42U));
    CHECK_THROWS(get());
    CHECK_NOTHROW(set_if_exists(42U));
    CHECK_NOTHROW(get_if_exists());

    dump(0);
}

TEST_CASE("vmcs_vmread_bitmap_address")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vmread_bitmap_address;

    proc_ctl_allow1(msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
    proc_ctl2_allow1(msrs::ia32_vmx_procbased_ctls2::vmcs_shadowing::mask);

    CHECK(exists());
    set(100UL);
    CHECK(get() == 100UL);
    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    proc_ctl2_disallow1(msrs::ia32_vmx_procbased_ctls2::vmcs_shadowing::mask);

    CHECK_FALSE(exists());
    CHECK_THROWS(set(42U));
    CHECK_THROWS(get());
    CHECK_NOTHROW(set_if_exists(42U));
    CHECK_NOTHROW(get_if_exists());

    dump(0);
}

TEST_CASE("vmcs_vmwrite_bitmap_address")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vmwrite_bitmap_address;

    proc_ctl_allow1(msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
    proc_ctl2_allow1(msrs::ia32_vmx_procbased_ctls2::vmcs_shadowing::mask);

    CHECK(exists());
    set(100UL);
    CHECK(get() == 100UL);
    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    proc_ctl2_disallow1(msrs::ia32_vmx_procbased_ctls2::vmcs_shadowing::mask);

    CHECK_FALSE(exists());
    CHECK_THROWS(set(42U));
    CHECK_THROWS(get());
    CHECK_NOTHROW(set_if_exists(42U));
    CHECK_NOTHROW(get_if_exists());

    dump(0);
}

TEST_CASE("vmcs_virtualization_exception_information_address")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::virtualization_exception_information_address;

    proc_ctl_allow1(msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
    proc_ctl2_allow1(msrs::ia32_vmx_procbased_ctls2::ept_violation_ve::mask);

    CHECK(exists());
    set(100UL);
    CHECK(get() == 100UL);
    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    proc_ctl2_disallow1(msrs::ia32_vmx_procbased_ctls2::ept_violation_ve::mask);

    CHECK_FALSE(exists());
    CHECK_THROWS(set(42U));
    CHECK_THROWS(get());
    CHECK_NOTHROW(set_if_exists(42U));
    CHECK_NOTHROW(get_if_exists());

    dump(0);
}

TEST_CASE("vmcs_xss_exiting_bitmap")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::xss_exiting_bitmap;

    proc_ctl_allow1(msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
    proc_ctl2_allow1(msrs::ia32_vmx_procbased_ctls2::enable_xsaves_xrstors::mask);

    CHECK(exists());
    set(100UL);
    CHECK(get() == 100UL);
    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    proc_ctl2_disallow1(msrs::ia32_vmx_procbased_ctls2::enable_xsaves_xrstors::mask);

    CHECK_FALSE(exists());
    CHECK_THROWS(set(42U));
    CHECK_THROWS(get());
    CHECK_NOTHROW(set_if_exists(42U));
    CHECK_NOTHROW(get_if_exists());

    dump(0);
}

TEST_CASE("vmcs_encls_exiting_bitmap")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::encls_exiting_bitmap;

    proc_ctl_allow1(msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
    proc_ctl2_allow1(msrs::ia32_vmx_procbased_ctls2::enable_encls_exiting::mask);

    CHECK(exists());
    set(100UL);
    CHECK(get() == 100UL);
    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    proc_ctl2_disallow1(msrs::ia32_vmx_procbased_ctls2::enable_encls_exiting::mask);

    CHECK_FALSE(exists());
    CHECK_THROWS(set(42U));
    CHECK_THROWS(get());
    CHECK_NOTHROW(set_if_exists(42U));
    CHECK_NOTHROW(get_if_exists());

    dump(0);
}

TEST_CASE("vmcs_tsc_multiplier")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::tsc_multiplier;

    proc_ctl_allow1(msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
    proc_ctl2_allow1(msrs::ia32_vmx_procbased_ctls2::use_tsc_scaling::mask);

    CHECK(exists());
    set(100UL);
    CHECK(get() == 100UL);
    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    proc_ctl2_disallow1(msrs::ia32_vmx_procbased_ctls2::use_tsc_scaling::mask);

    CHECK_FALSE(exists());
    CHECK_THROWS(set(42U));
    CHECK_THROWS(get());
    CHECK_NOTHROW(set_if_exists(42U));
    CHECK_NOTHROW(get_if_exists());

    dump(0);
}

#endif
