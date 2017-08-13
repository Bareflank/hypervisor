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

static void
setup_intrinsics(MockRepository &mocks)
{
    mocks.OnCallFunc(_vmread).Do(test_vmread);
}

TEST_CASE("test name goes here")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(true);
}

TEST_CASE("vmcs_exit_qualification")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::exit_qualification::exists());

    g_vmcs_fields[vmcs::exit_qualification::addr] = 1UL;
    CHECK(vmcs::exit_qualification::get() == 1UL);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0UL;
    CHECK(vmcs::exit_qualification::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_exit_qualification_debug_exception")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::exit_qualification::debug_exception::get_name() == "debug_exception"_s);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 1UL;
    CHECK(vmcs::exit_qualification::debug_exception::get() == 1UL);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0UL;
    CHECK(vmcs::exit_qualification::debug_exception::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_exit_qualification_debug_exception_b0")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 1UL;
    CHECK(vmcs::exit_qualification::debug_exception::b0::is_enabled());
    CHECK_FALSE(vmcs::exit_qualification::debug_exception::b0::is_disabled());
    CHECK(vmcs::exit_qualification::debug_exception::b0::is_enabled(1UL));
    CHECK_FALSE(vmcs::exit_qualification::debug_exception::b0::is_disabled(1UL));

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0UL;
    CHECK_FALSE(vmcs::exit_qualification::debug_exception::b0::is_enabled_if_exists());
    CHECK(vmcs::exit_qualification::debug_exception::b0::is_disabled_if_exists());
}

TEST_CASE("vmcs_exit_qualification_debug_exception_b1")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 2UL;
    CHECK(vmcs::exit_qualification::debug_exception::b1::is_enabled());
    CHECK_FALSE(vmcs::exit_qualification::debug_exception::b1::is_disabled());
    CHECK(vmcs::exit_qualification::debug_exception::b1::is_enabled(2UL));
    CHECK_FALSE(vmcs::exit_qualification::debug_exception::b1::is_disabled(2UL));

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0UL;
    CHECK_FALSE(vmcs::exit_qualification::debug_exception::b1::is_enabled_if_exists());
    CHECK(vmcs::exit_qualification::debug_exception::b1::is_disabled_if_exists());
}

TEST_CASE("vmcs_exit_qualification_debug_exception_b2")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 4UL;
    CHECK(vmcs::exit_qualification::debug_exception::b2::is_enabled());
    CHECK_FALSE(vmcs::exit_qualification::debug_exception::b2::is_disabled());
    CHECK(vmcs::exit_qualification::debug_exception::b2::is_enabled(4UL));
    CHECK_FALSE(vmcs::exit_qualification::debug_exception::b2::is_disabled(4UL));

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0UL;
    CHECK_FALSE(vmcs::exit_qualification::debug_exception::b2::is_enabled_if_exists());
    CHECK(vmcs::exit_qualification::debug_exception::b2::is_disabled_if_exists());
}

TEST_CASE("vmcs_exit_qualification_debug_exception_b3")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 8UL;
    CHECK(vmcs::exit_qualification::debug_exception::b3::is_enabled());
    CHECK_FALSE(vmcs::exit_qualification::debug_exception::b3::is_disabled());
    CHECK(vmcs::exit_qualification::debug_exception::b3::is_enabled(8UL));
    CHECK_FALSE(vmcs::exit_qualification::debug_exception::b3::is_disabled(8UL));

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0UL;
    CHECK_FALSE(vmcs::exit_qualification::debug_exception::b3::is_enabled_if_exists());
    CHECK(vmcs::exit_qualification::debug_exception::b3::is_disabled_if_exists());
}

TEST_CASE("vmcs_exit_qualification_debug_exception_reserved")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x600UL;
    CHECK(vmcs::exit_qualification::debug_exception::reserved::get() == 0x600U);
    CHECK(vmcs::exit_qualification::debug_exception::reserved::get(0x600UL) == 0x600U);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x602UL;
    CHECK(vmcs::exit_qualification::debug_exception::reserved::get_if_exists() == 0x600U);
}

TEST_CASE("vmcs_exit_qualification_debug_exception_bd")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x2000UL;
    CHECK(vmcs::exit_qualification::debug_exception::bd::is_enabled());
    CHECK_FALSE(vmcs::exit_qualification::debug_exception::bd::is_disabled());
    CHECK(vmcs::exit_qualification::debug_exception::bd::is_enabled(0x2000UL));
    CHECK_FALSE(vmcs::exit_qualification::debug_exception::bd::is_disabled(0x2000UL));

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0UL;
    CHECK_FALSE(vmcs::exit_qualification::debug_exception::bd::is_enabled_if_exists());
    CHECK(vmcs::exit_qualification::debug_exception::bd::is_disabled_if_exists());
}

TEST_CASE("vmcs_exit_qualification_debug_exception_bs")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x4000UL;
    CHECK(vmcs::exit_qualification::debug_exception::bs::is_enabled());
    CHECK_FALSE(vmcs::exit_qualification::debug_exception::bs::is_disabled());
    CHECK(vmcs::exit_qualification::debug_exception::bs::is_enabled(0x4000UL));
    CHECK_FALSE(vmcs::exit_qualification::debug_exception::bs::is_disabled(0x4000UL));

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0UL;
    CHECK_FALSE(vmcs::exit_qualification::debug_exception::bs::is_enabled_if_exists());
    CHECK(vmcs::exit_qualification::debug_exception::bs::is_disabled_if_exists());
}

TEST_CASE("vmcs_exit_qualification_page_fault_exception")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::exit_qualification::page_fault_exception::get_name() ==
          "page_fault_exception"_s);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x4000UL;
    CHECK(vmcs::exit_qualification::page_fault_exception::address() == 0x4000UL);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x10000000UL;
    CHECK(vmcs::exit_qualification::page_fault_exception::address_if_exists() ==
          0x10000000UL);
}

TEST_CASE("vmcs_exit_qualification_sipi")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::exit_qualification::sipi::get_name() == "sipi"_s);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x34UL;
    CHECK(vmcs::exit_qualification::sipi::get() == 0x34UL);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0UL;
    CHECK(vmcs::exit_qualification::sipi::get_if_exists() == 0x0UL);
}

TEST_CASE("vmcs_exit_qualification_sipi_vector")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0xF34UL;
    CHECK(vmcs::exit_qualification::sipi::vector::get() == 0x34UL);
    CHECK(vmcs::exit_qualification::sipi::vector::get(0xF34UL) == 0x34UL);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x3010UL;
    CHECK(vmcs::exit_qualification::sipi::vector::get_if_exists() == 0x10UL);
}

TEST_CASE("vmcs_exit_qualification_task_switch")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::exit_qualification::task_switch::get_name() == "task_switch"_s);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x1UL;
    CHECK(vmcs::exit_qualification::task_switch::get() == 0x1UL);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0UL;
    CHECK(vmcs::exit_qualification::task_switch::get_if_exists() == 0x0UL);
}

TEST_CASE("vmcs_exit_qualification_task_switch_tss_selector")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0xF0003456UL;
    CHECK(vmcs::exit_qualification::task_switch::tss_selector::get() == 0x3456UL);
    CHECK(vmcs::exit_qualification::task_switch::tss_selector::get(
              0xF0003456UL) == 0x3456UL);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0UL;
    CHECK(vmcs::exit_qualification::task_switch::tss_selector::get_if_exists() == 0x0UL);
}

TEST_CASE("vmcs_exit_qualification_task_switch_reserved")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0xFFF0000UL;
    CHECK(vmcs::exit_qualification::task_switch::reserved::get() == 0xFFF0000UL);
    CHECK(vmcs::exit_qualification::task_switch::reserved::get(0xFFF0000UL) == 0xFFF0000UL);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0UL;
    CHECK(vmcs::exit_qualification::task_switch::reserved::get_if_exists() == 0x0UL);
}

TEST_CASE("vmcs_exit_qualification_task_switch_source_of_task_switch_init")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::exit_qualification::task_switch;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0UL;
    CHECK(source_of_task_switch_init::get() ==
          source_of_task_switch_init::call_instruction);
    CHECK(source_of_task_switch_init::get(0x0UL) ==
          source_of_task_switch_init::call_instruction);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x40000000UL;
    CHECK(source_of_task_switch_init::get() ==
          source_of_task_switch_init::iret_instruction);
    CHECK(source_of_task_switch_init::get(0x40000000UL) ==
          source_of_task_switch_init::iret_instruction);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x80000000UL;
    CHECK(source_of_task_switch_init::get_if_exists() ==
          source_of_task_switch_init::jmp_instruction);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0xC0000000UL;
    CHECK(source_of_task_switch_init::get_if_exists() ==
          source_of_task_switch_init::task_gate_in_idt);
}

TEST_CASE("vmcs_exit_qualification_invept")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::exit_qualification::invept::get_name() == "invept"_s);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x1UL;
    CHECK(vmcs::exit_qualification::invept::get() == 0x1UL);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x2UL;
    CHECK(vmcs::exit_qualification::invept::get_if_exists() == 0x2UL);
}

TEST_CASE("vmcs_exit_qualification_invpcid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::exit_qualification::invpcid::get_name() == "invpcid"_s);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x1UL;
    CHECK(vmcs::exit_qualification::invpcid::get() == 0x1UL);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x2UL;
    CHECK(vmcs::exit_qualification::invpcid::get_if_exists() == 0x2UL);
}

TEST_CASE("vmcs_exit_qualification_invvpid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::exit_qualification::invvpid::get_name() == "invvpid"_s);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x1UL;
    CHECK(vmcs::exit_qualification::invvpid::get() == 0x1UL);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x2UL;
    CHECK(vmcs::exit_qualification::invvpid::get_if_exists() == 0x2UL);
}

TEST_CASE("vmcs_exit_qualification_lgdt")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::exit_qualification::lgdt::get_name() == "lgdt"_s);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x1UL;
    CHECK(vmcs::exit_qualification::lgdt::get() == 0x1UL);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x2UL;
    CHECK(vmcs::exit_qualification::lgdt::get_if_exists() == 0x2UL);
}

TEST_CASE("vmcs_exit_qualification_lidt")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::exit_qualification::lidt::get_name() == "lidt"_s);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x1UL;
    CHECK(vmcs::exit_qualification::lidt::get() == 0x1UL);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x2UL;
    CHECK(vmcs::exit_qualification::lidt::get_if_exists() == 0x2UL);
}

TEST_CASE("vmcs_exit_qualification_lldt")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::exit_qualification::lldt::get_name() == "lldt"_s);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x1UL;
    CHECK(vmcs::exit_qualification::lldt::get() == 0x1UL);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x2UL;
    CHECK(vmcs::exit_qualification::lldt::get_if_exists() == 0x2UL);
}

TEST_CASE("vmcs_exit_qualification_ltr")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::exit_qualification::ltr::get_name() == "ltr"_s);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x1UL;
    CHECK(vmcs::exit_qualification::ltr::get() == 0x1UL);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x2UL;
    CHECK(vmcs::exit_qualification::ltr::get_if_exists() == 0x2UL);
}

TEST_CASE("vmcs_exit_qualification_sgdt")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::exit_qualification::sgdt::get_name() == "sgdt"_s);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x1UL;
    CHECK(vmcs::exit_qualification::sgdt::get() == 0x1UL);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x2UL;
    CHECK(vmcs::exit_qualification::sgdt::get_if_exists() == 0x2UL);
}

TEST_CASE("vmcs_exit_qualification_sidt")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::exit_qualification::sidt::get_name() == "sidt"_s);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x1UL;
    CHECK(vmcs::exit_qualification::sidt::get() == 0x1UL);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x2UL;
    CHECK(vmcs::exit_qualification::sidt::get_if_exists() == 0x2UL);
}

TEST_CASE("vmcs_exit_qualification_sldt")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::exit_qualification::sldt::get_name() == "sldt"_s);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x1UL;
    CHECK(vmcs::exit_qualification::sldt::get() == 0x1UL);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x2UL;
    CHECK(vmcs::exit_qualification::sldt::get_if_exists() == 0x2UL);
}

TEST_CASE("vmcs_exit_qualification_str")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::exit_qualification::str::get_name() == "str"_s);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x1UL;
    CHECK(vmcs::exit_qualification::str::get() == 0x1UL);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x2UL;
    CHECK(vmcs::exit_qualification::str::get_if_exists() == 0x2UL);
}

TEST_CASE("vmcs_exit_qualification_vmclear")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::exit_qualification::vmclear::get_name() == "vmclear"_s);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x1UL;
    CHECK(vmcs::exit_qualification::vmclear::get() == 0x1UL);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x2UL;
    CHECK(vmcs::exit_qualification::vmclear::get_if_exists() == 0x2UL);
}

TEST_CASE("vmcs_exit_qualification_vmptrld")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::exit_qualification::vmptrld::get_name() == "vmptrld"_s);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x1UL;
    CHECK(vmcs::exit_qualification::vmptrld::get() == 0x1UL);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x2UL;
    CHECK(vmcs::exit_qualification::vmptrld::get_if_exists() == 0x2UL);
}

TEST_CASE("vmcs_exit_qualification_vmptrst")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::exit_qualification::vmptrst::get_name() == "vmptrst"_s);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x1UL;
    CHECK(vmcs::exit_qualification::vmptrst::get() == 0x1UL);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x2UL;
    CHECK(vmcs::exit_qualification::vmptrst::get_if_exists() == 0x2UL);
}

TEST_CASE("vmcs_exit_qualification_vmread")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::exit_qualification::vmread::get_name() == "vmread"_s);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x1UL;
    CHECK(vmcs::exit_qualification::vmread::get() == 0x1UL);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x2UL;
    CHECK(vmcs::exit_qualification::vmread::get_if_exists() == 0x2UL);
}

TEST_CASE("vmcs_exit_qualification_vmwrite")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::exit_qualification::vmwrite::get_name() == "vmwrite"_s);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x1UL;
    CHECK(vmcs::exit_qualification::vmwrite::get() == 0x1UL);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x2UL;
    CHECK(vmcs::exit_qualification::vmwrite::get_if_exists() == 0x2UL);
}

TEST_CASE("vmcs_exit_qualification_vmxon")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::exit_qualification::vmxon::get_name() == "vmxon"_s);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x1UL;
    CHECK(vmcs::exit_qualification::vmxon::get() == 0x1UL);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x2UL;
    CHECK(vmcs::exit_qualification::vmxon::get_if_exists() == 0x2UL);
}

TEST_CASE("vmcs_exit_qualification_xrstors")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::exit_qualification::xrstors::get_name() == "xrstors"_s);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x1UL;
    CHECK(vmcs::exit_qualification::xrstors::get() == 0x1UL);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x2UL;
    CHECK(vmcs::exit_qualification::xrstors::get_if_exists() == 0x2UL);
}

TEST_CASE("vmcs_exit_qualification_xsaves")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::exit_qualification::xsaves::get_name() == "xsaves"_s);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x1UL;
    CHECK(vmcs::exit_qualification::xsaves::get() == 0x1UL);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x2UL;
    CHECK(vmcs::exit_qualification::xsaves::get_if_exists() == 0x2UL);
}

TEST_CASE("vmcs_exit_qualification_control_register_access")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::exit_qualification::control_register_access::get_name() ==
          "control_register_access"_s);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x34UL;
    CHECK(vmcs::exit_qualification::control_register_access::get() == 0x34UL);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0UL;
    CHECK(vmcs::exit_qualification::control_register_access::get_if_exists() == 0x0UL);
}

TEST_CASE("vmcs_exit_qualification_control_register_access_control_register_number")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x42UL;
    CHECK(vmcs::exit_qualification::control_register_access::control_register_number::get()
          == 0x2UL);
    CHECK(vmcs::exit_qualification::control_register_access::control_register_number::get(
              0x42UL) == 0x2UL);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0UL;
    CHECK(
        vmcs::exit_qualification::control_register_access::control_register_number::get_if_exists() ==
        0x0UL);
}

TEST_CASE("vmcs_exit_qualification_control_register_access_access_type")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::exit_qualification::control_register_access;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x00UL;
    CHECK(access_type::get() == access_type::mov_to_cr);
    CHECK(access_type::get(0x00UL) == access_type::mov_to_cr);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x10UL;
    CHECK(access_type::get() == access_type::mov_from_cr);
    CHECK(access_type::get(0x10UL) == access_type::mov_from_cr);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x20UL;
    CHECK(access_type::get_if_exists() == access_type::clts);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x30UL;
    CHECK(access_type::get_if_exists() == access_type::lmsw);
}

TEST_CASE("vmcs_exit_qualification_control_register_access_lmsw_operand_type")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::exit_qualification::control_register_access;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x00UL;
    CHECK(lmsw_operand_type::get() == lmsw_operand_type::reg);
    CHECK(lmsw_operand_type::get(0x00UL) == lmsw_operand_type::reg);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x40UL;
    CHECK(lmsw_operand_type::get_if_exists() == lmsw_operand_type::mem);
}

TEST_CASE("vmcs_exit_qualification_control_register_access_reserved")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x3080UL;
    CHECK(vmcs::exit_qualification::control_register_access::reserved::get() == 0x3080UL);
    CHECK(vmcs::exit_qualification::control_register_access::reserved::get(
              0x3080UL) == 0x3080UL);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0UL;
    CHECK(vmcs::exit_qualification::control_register_access::reserved::get_if_exists() ==
          0x0UL);
}

TEST_CASE("vmcs_exit_qualification_control_register_access_general_purpose_register")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::exit_qualification::control_register_access;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x100UL;
    CHECK(general_purpose_register::get() == general_purpose_register::rcx);
    CHECK(general_purpose_register::get(0x100UL) == general_purpose_register::rcx);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0xA00UL;
    CHECK(general_purpose_register::get_if_exists() == general_purpose_register::r10);
}

TEST_CASE("vmcs_exit_qualification_control_register_access_source_data")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::exit_qualification::control_register_access;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x30000UL;
    CHECK(source_data::get() == 3UL);
    CHECK(source_data::get(0x30000UL) == 3UL);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x60000UL;
    CHECK(source_data::get_if_exists() == 6UL);
}

TEST_CASE("vmcs_exit_qualification_mov_dr")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::exit_qualification::mov_dr::get_name() == "mov_dr"_s);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x34UL;
    CHECK(vmcs::exit_qualification::mov_dr::get() == 0x34UL);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0UL;
    CHECK(vmcs::exit_qualification::mov_dr::get_if_exists() == 0x0UL);
}

TEST_CASE("vmcs_exit_qualification_mov_dr_debug_register_number")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x42UL;
    CHECK(vmcs::exit_qualification::mov_dr::debug_register_number::get() == 0x2UL);
    CHECK(vmcs::exit_qualification::mov_dr::debug_register_number::get(0x42UL) == 0x2UL);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0UL;
    CHECK(vmcs::exit_qualification::mov_dr::debug_register_number::get_if_exists() ==
          0x0UL);
}

TEST_CASE("vmcs_exit_qualification_mov_dr_reserved")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x88UL;
    CHECK(vmcs::exit_qualification::mov_dr::reserved::get() == 0x88UL);
    CHECK(vmcs::exit_qualification::mov_dr::reserved::get(0x88UL) == 0x88UL);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0UL;
    CHECK(vmcs::exit_qualification::mov_dr::reserved::get_if_exists() == 0x0UL);
}

TEST_CASE("vmcs_exit_qualification_mov_dr_direction_of_access")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::exit_qualification::mov_dr;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x00UL;
    CHECK(direction_of_access::get() == direction_of_access::to_dr);
    CHECK(direction_of_access::get(0x00UL) == direction_of_access::to_dr);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x10UL;
    CHECK(direction_of_access::get_if_exists() == direction_of_access::from_dr);
}

TEST_CASE("vmcs_exit_qualification_mov_dr_general_purpose_register")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::exit_qualification::mov_dr;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x200UL;
    CHECK(general_purpose_register::get() == general_purpose_register::rdx);
    CHECK(general_purpose_register::get(0x200UL) == general_purpose_register::rdx);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0xB00UL;
    CHECK(general_purpose_register::get_if_exists() == general_purpose_register::r11);
}

TEST_CASE("vmcs_exit_qualification_io_instruction")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::exit_qualification::io_instruction::get_name() == "io_instruction"_s);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x34UL;
    CHECK(vmcs::exit_qualification::io_instruction::get() == 0x34UL);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0UL;
    CHECK(vmcs::exit_qualification::io_instruction::get_if_exists() == 0x0UL);
}

TEST_CASE("vmcs_exit_qualification_io_instruction_size_of_access")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::exit_qualification::io_instruction;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0UL;
    CHECK(size_of_access::get() == size_of_access::one_byte);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x1UL;
    CHECK(size_of_access::get() == size_of_access::two_byte);
    CHECK(size_of_access::get(0x1UL) == size_of_access::two_byte);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x3UL;
    CHECK(size_of_access::get_if_exists() == size_of_access::four_byte);
}

TEST_CASE("vmcs_exit_qualification_io_instruction_direction_of_access")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::exit_qualification::io_instruction;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0UL;
    CHECK(direction_of_access::get() == direction_of_access::out);
    CHECK(direction_of_access::get(0x0UL) == direction_of_access::out);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x1UL << direction_of_access::from;
    CHECK(direction_of_access::get_if_exists() == direction_of_access::in);
}

TEST_CASE("vmcs_exit_qualification_io_instruction_string_instruction")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::exit_qualification::io_instruction;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0UL;
    CHECK(string_instruction::get() == string_instruction::not_string);
    CHECK(string_instruction::get(0x0UL) == string_instruction::not_string);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x1UL << string_instruction::from;
    CHECK(string_instruction::get_if_exists() == string_instruction::string);
}

TEST_CASE("vmcs_exit_qualification_io_instruction_rep_prefixed")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::exit_qualification::io_instruction;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0UL;
    CHECK(rep_prefixed::get() == rep_prefixed::not_rep);
    CHECK(rep_prefixed::get(0x0UL) == rep_prefixed::not_rep);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x1UL << rep_prefixed::from;
    CHECK(rep_prefixed::get_if_exists() == rep_prefixed::rep);
}

TEST_CASE("vmcs_exit_qualification_io_instruction_operand_encoding")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::exit_qualification::io_instruction;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0UL;
    CHECK(operand_encoding::get() == operand_encoding::dx);
    CHECK(operand_encoding::get(0x0UL) == operand_encoding::dx);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x1UL << operand_encoding::from;
    CHECK(operand_encoding::get_if_exists() == operand_encoding::immediate);
}

TEST_CASE("vmcs_exit_qualification_io_instruction_reserved")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::exit_qualification::io_instruction;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0UL;
    CHECK(reserved::get() == 0x0UL);
    CHECK(reserved::get(0x0UL) == 0x0UL);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0xF80UL;
    CHECK(reserved::get_if_exists() == 0xF80UL);
}

TEST_CASE("vmcs_exit_qualification_io_instruction_port_number")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::exit_qualification::io_instruction;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0UL;
    CHECK(port_number::get() == 0x0UL);
    CHECK(port_number::get(0x0UL) == 0x0UL);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x1UL << port_number::from;
    CHECK(port_number::get_if_exists() == 0x1UL);
}

TEST_CASE("vmcs_exit_qualification_mwait")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::exit_qualification::mwait;

    CHECK(get_name() == "mwait"_s);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0U;
    CHECK(get() == 0U);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 1U;
    CHECK(get_if_exists() == 1U);
}

TEST_CASE("vmcs_exit_qualification_linear_apic_access")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::exit_qualification::linear_apic_access;

    CHECK(get_name() == "linear_apic_access"_s);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x1UL;
    CHECK(get() == 0x1UL);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0UL;
    CHECK(get_if_exists() == 0x0UL);
}

TEST_CASE("vmcs_exit_qualification_linear_apic_access_offset")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::exit_qualification::linear_apic_access;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x1UL;
    CHECK(offset::get() == 0x1UL);
    CHECK(offset::get(0x1UL) == 0x1UL);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0UL;
    CHECK(offset::get_if_exists() == 0x0UL);
}

TEST_CASE("vmcs_exit_qualification_linear_apic_access_access_type")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::exit_qualification::linear_apic_access;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0UL;
    CHECK(access_type::get() == access_type::read_during_instruction_execution);
    CHECK(access_type::get(0x0UL) == access_type::read_during_instruction_execution);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x1UL << access_type::from;
    CHECK(access_type::get_if_exists() == access_type::write_during_instruction_execution);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x2UL << access_type::from;
    CHECK(access_type::get() == access_type::instruction_fetch);
    CHECK(access_type::get(0x2UL << access_type::from) == access_type::instruction_fetch);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x3UL << access_type::from;
    CHECK(access_type::get_if_exists() == access_type::event_delivery);
}

TEST_CASE("vmcs_exit_qualification_linear_apic_access_reserved")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::exit_qualification::linear_apic_access;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0UL;
    CHECK(reserved::get() == 0U);
    CHECK(reserved::get(0x0UL) == 0U);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0xF0000UL;
    CHECK(reserved::get_if_exists() == 0xF0000U);
}

TEST_CASE("vmcs_exit_qualification_guest_physical_apic_access")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::exit_qualification::guest_physical_apic_access;

    CHECK(get_name() == "guest_physical_apic_access"_s);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x1UL;
    CHECK(get() == 0x1UL);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0UL;
    CHECK(get_if_exists() == 0x0UL);
}

TEST_CASE("vmcs_exit_qualification_guest_physical_apic_access_access_type")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::exit_qualification::guest_physical_apic_access;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0xFUL << access_type::from;
    CHECK(access_type::get() == access_type::instruction_fetch_or_execution);
    CHECK(access_type::get(0xFUL << access_type::from) ==
          access_type::instruction_fetch_or_execution);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0xAUL << access_type::from;
    CHECK(access_type::get_if_exists() == access_type::event_delivery);
}

TEST_CASE("vmcs_exit_qualification_guest_physical_apic_access_reserved")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::exit_qualification::guest_physical_apic_access;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0UL;
    CHECK(reserved::get() == 0U);
    CHECK(reserved::get(0x0UL) == 0U);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0xF0000UL;
    CHECK(reserved::get_if_exists() == 0xF0000U);
}

TEST_CASE("vmcs_exit_qualification_ept_violation")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::exit_qualification::ept_violation::get_name() == "ept_violation"_s);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x1UL;
    CHECK(vmcs::exit_qualification::ept_violation::get() == 1UL);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0UL;
    CHECK(vmcs::exit_qualification::ept_violation::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_exit_qualification_ept_violation_data_read")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::exit_qualification::ept_violation;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x1UL;
    CHECK(data_read::is_enabled());
    CHECK(data_read::is_enabled(0x1UL));
    CHECK(data_read::is_enabled_if_exists());

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0UL;
    CHECK(data_read::is_disabled());
    CHECK(data_read::is_disabled(0x0UL));
    CHECK(data_read::is_disabled_if_exists());
}

TEST_CASE("vmcs_exit_qualification_ept_violation_data_write")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::exit_qualification::ept_violation;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x1UL << data_write::from;
    CHECK(data_write::is_enabled());
    CHECK(data_write::is_enabled(0x1UL << data_write::from));
    CHECK(data_write::is_enabled_if_exists());

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0UL << data_write::from;
    CHECK(data_write::is_disabled());
    CHECK(data_write::is_disabled(0x0UL << data_write::from));
    CHECK(data_write::is_disabled_if_exists());
}

TEST_CASE("vmcs_exit_qualification_ept_violation_instruction_fetch")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::exit_qualification::ept_violation;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x1UL << instruction_fetch::from;
    CHECK(instruction_fetch::is_enabled());
    CHECK(instruction_fetch::is_enabled(0x1UL << instruction_fetch::from));
    CHECK(instruction_fetch::is_enabled_if_exists());

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0UL << instruction_fetch::from;
    CHECK(instruction_fetch::is_disabled());
    CHECK(instruction_fetch::is_disabled(0x0UL << instruction_fetch::from));
    CHECK(instruction_fetch::is_disabled_if_exists());
}

TEST_CASE("vmcs_exit_qualification_ept_violation_readable")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::exit_qualification::ept_violation;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x1UL << readable::from;
    CHECK(readable::is_enabled());
    CHECK(readable::is_enabled(0x1UL << readable::from));
    CHECK(readable::is_enabled_if_exists());

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0UL << readable::from;
    CHECK(readable::is_disabled());
    CHECK(readable::is_disabled(0x0UL << readable::from));
    CHECK(readable::is_disabled_if_exists());
}

TEST_CASE("vmcs_exit_qualification_ept_violation_writeable")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::exit_qualification::ept_violation;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x1UL << writeable::from;
    CHECK(writeable::is_enabled());
    CHECK(writeable::is_enabled(0x1UL << writeable::from));
    CHECK(writeable::is_enabled_if_exists());

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0UL << writeable::from;
    CHECK(writeable::is_disabled());
    CHECK(writeable::is_disabled(0x0UL << writeable::from));
    CHECK(writeable::is_disabled_if_exists());
}

TEST_CASE("vmcs_exit_qualification_ept_violation_executable")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::exit_qualification::ept_violation;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x1UL << executable::from;
    CHECK(executable::is_enabled());
    CHECK(executable::is_enabled(0x1UL << executable::from));
    CHECK(executable::is_enabled_if_exists());

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0UL << executable::from;
    CHECK(executable::is_disabled());
    CHECK(executable::is_disabled(0x0UL << executable::from));
    CHECK(executable::is_disabled_if_exists());
}

TEST_CASE("vmcs_exit_qualification_ept_violation_reserved")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::exit_qualification::ept_violation;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x40UL;
    CHECK(reserved::get() == 0x40UL);
    CHECK(reserved::get(0x40UL) == 0x40UL);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0UL;
    CHECK(reserved::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_exit_qualification_ept_violation_valid_guest_linear_address")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::exit_qualification::ept_violation;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x1UL << valid_guest_linear_address::from;
    CHECK(valid_guest_linear_address::is_enabled());
    CHECK(valid_guest_linear_address::is_enabled(0x1UL <<
            valid_guest_linear_address::from));
    CHECK(valid_guest_linear_address::is_enabled_if_exists());

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0UL << valid_guest_linear_address::from;
    CHECK(valid_guest_linear_address::is_disabled());
    CHECK(valid_guest_linear_address::is_disabled(0x0UL <<
            valid_guest_linear_address::from));
    CHECK(valid_guest_linear_address::is_disabled_if_exists());
}

TEST_CASE("vmcs_exit_qualification_ept_violation_nmi_unblocking_due_to_iret")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::exit_qualification::ept_violation;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x1UL << nmi_unblocking_due_to_iret::from;
    CHECK(nmi_unblocking_due_to_iret::is_enabled());
    CHECK(nmi_unblocking_due_to_iret::is_enabled(0x1UL <<
            nmi_unblocking_due_to_iret::from));
    CHECK(nmi_unblocking_due_to_iret::is_enabled_if_exists());

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0UL << nmi_unblocking_due_to_iret::from;
    CHECK(nmi_unblocking_due_to_iret::is_disabled());
    CHECK(nmi_unblocking_due_to_iret::is_disabled(0x0UL <<
            nmi_unblocking_due_to_iret::from));
    CHECK(nmi_unblocking_due_to_iret::is_disabled_if_exists());
}

TEST_CASE("vmcs_exit_qualification_eoi_virtualization")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::exit_qualification::eoi_virtualization::get_name() ==
          "eoi_virtualization"_s);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x1UL;
    CHECK(vmcs::exit_qualification::eoi_virtualization::get() == 1UL);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0UL;
    CHECK(vmcs::exit_qualification::eoi_virtualization::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_exit_qualification_eoi_virtualization_vector")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::exit_qualification::eoi_virtualization;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x1UL;
    CHECK(vector::get() == 1UL);
    CHECK(vector::get(0x1UL) == 1UL);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0UL;
    CHECK(vector::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_exit_qualification_apic_write")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::exit_qualification::apic_write::get_name() == "apic_write"_s);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x1UL;
    CHECK(vmcs::exit_qualification::apic_write::get() == 1UL);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0UL;
    CHECK(vmcs::exit_qualification::apic_write::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_exit_qualification_apic_write_offset")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::exit_qualification::apic_write;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x1UL;
    CHECK(offset::get() == 1UL);
    CHECK(offset::get(0x1UL) == 1UL);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0UL;
    CHECK(offset::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_io_rcx")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_vmcs_fields[vmcs::io_rcx::addr] = 1U;
    CHECK(vmcs::io_rcx::get() == 1U);

    g_vmcs_fields[vmcs::io_rcx::addr] = 0U;
    CHECK(vmcs::io_rcx::get_if_exists() == 0U);
}

TEST_CASE("vmcs_io_rsi")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_vmcs_fields[vmcs::io_rsi::addr] = 1U;
    CHECK(vmcs::io_rsi::get() == 1U);

    g_vmcs_fields[vmcs::io_rsi::addr] = 0U;
    CHECK(vmcs::io_rsi::get_if_exists() == 0U);
}

TEST_CASE("vmcs_io_rdi")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_vmcs_fields[vmcs::io_rdi::addr] = 1U;
    CHECK(vmcs::io_rdi::get() == 1U);

    g_vmcs_fields[vmcs::io_rdi::addr] = 0U;
    CHECK(vmcs::io_rdi::get_if_exists() == 0U);
}

TEST_CASE("vmcs_io_rip")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_vmcs_fields[vmcs::io_rip::addr] = 1U;
    CHECK(vmcs::io_rip::get() == 1U);

    g_vmcs_fields[vmcs::io_rip::addr] = 0U;
    CHECK(vmcs::io_rip::get_if_exists() == 0U);
}

TEST_CASE("vmcs_guest_linear_address")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_vmcs_fields[vmcs::guest_linear_address::addr] = 1U;
    CHECK(vmcs::guest_linear_address::get() == 1U);

    g_vmcs_fields[vmcs::guest_linear_address::addr] = 0U;
    CHECK(vmcs::guest_linear_address::get_if_exists() == 0U);
}

#endif
