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

    using namespace vmcs::exit_qualification;

    CHECK(exists());
    g_vmcs_fields[vmcs::exit_qualification::addr] = 100UL;
    CHECK(get() == 100UL);
    g_vmcs_fields[vmcs::exit_qualification::addr] = 200UL;
    CHECK(get_if_exists() == 200UL);

    dump(0);
}

TEST_CASE("vmcs_exit_qualification_debug_exception")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::exit_qualification;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 1UL;
    CHECK(debug_exception::get() == 1UL);
    g_vmcs_fields[vmcs::exit_qualification::addr] = 0UL;
    CHECK(debug_exception::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_exit_qualification_debug_exception_b0")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::exit_qualification::debug_exception;

    g_vmcs_fields[vmcs::exit_qualification::addr] = b0::mask;
    CHECK(b0::is_enabled());
    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0U;
    CHECK(b0::is_disabled());

    g_vmcs_fields[vmcs::exit_qualification::addr] = b0::mask;
    CHECK(b0::is_enabled(b0::mask));
    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0U;
    CHECK(b0::is_disabled(0x0));

    g_vmcs_fields[vmcs::exit_qualification::addr] = b0::mask;
    CHECK(b0::is_enabled_if_exists());
    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0U;
    CHECK(b0::is_disabled_if_exists());
}

TEST_CASE("vmcs_exit_qualification_debug_exception_b1")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::exit_qualification::debug_exception;

    g_vmcs_fields[vmcs::exit_qualification::addr] = b1::mask;
    CHECK(b1::is_enabled());
    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0U;
    CHECK(b1::is_disabled());

    g_vmcs_fields[vmcs::exit_qualification::addr] = b1::mask;
    CHECK(b1::is_enabled(b1::mask));
    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0U;
    CHECK(b1::is_disabled(0x0));

    g_vmcs_fields[vmcs::exit_qualification::addr] = b1::mask;
    CHECK(b1::is_enabled_if_exists());
    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0U;
    CHECK(b1::is_disabled_if_exists());
}

TEST_CASE("vmcs_exit_qualification_debug_exception_b2")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::exit_qualification::debug_exception;

    g_vmcs_fields[vmcs::exit_qualification::addr] = b2::mask;
    CHECK(b2::is_enabled());
    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0U;
    CHECK(b2::is_disabled());

    g_vmcs_fields[vmcs::exit_qualification::addr] = b2::mask;
    CHECK(b2::is_enabled(b2::mask));
    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0U;
    CHECK(b2::is_disabled(0x0));

    g_vmcs_fields[vmcs::exit_qualification::addr] = b2::mask;
    CHECK(b2::is_enabled_if_exists());
    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0U;
    CHECK(b2::is_disabled_if_exists());
}

TEST_CASE("vmcs_exit_qualification_debug_exception_b3")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::exit_qualification::debug_exception;

    g_vmcs_fields[vmcs::exit_qualification::addr] = b3::mask;
    CHECK(b3::is_enabled());
    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0U;
    CHECK(b3::is_disabled());

    g_vmcs_fields[vmcs::exit_qualification::addr] = b3::mask;
    CHECK(b3::is_enabled(b3::mask));
    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0U;
    CHECK(b3::is_disabled(0x0));

    g_vmcs_fields[vmcs::exit_qualification::addr] = b3::mask;
    CHECK(b3::is_enabled_if_exists());
    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0U;
    CHECK(b3::is_disabled_if_exists());
}

TEST_CASE("vmcs_exit_qualification_debug_exception_reserved")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::exit_qualification::debug_exception;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(reserved::get() == (reserved::mask >> reserved::from));

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(reserved::get(reserved::mask) == (reserved::mask >> reserved::from));

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(reserved::get_if_exists() == (reserved::mask >> reserved::from));
}

TEST_CASE("vmcs_exit_qualification_debug_exception_bd")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::exit_qualification::debug_exception;

    g_vmcs_fields[vmcs::exit_qualification::addr] = bd::mask;
    CHECK(bd::is_enabled());
    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0U;
    CHECK(bd::is_disabled());

    g_vmcs_fields[vmcs::exit_qualification::addr] = bd::mask;
    CHECK(bd::is_enabled(bd::mask));
    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0U;
    CHECK(bd::is_disabled(0x0));

    g_vmcs_fields[vmcs::exit_qualification::addr] = bd::mask;
    CHECK(bd::is_enabled_if_exists());
    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0U;
    CHECK(bd::is_disabled_if_exists());
}

TEST_CASE("vmcs_exit_qualification_debug_exception_bs")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::exit_qualification::debug_exception;

    g_vmcs_fields[vmcs::exit_qualification::addr] = bs::mask;
    CHECK(bs::is_enabled());
    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0U;
    CHECK(bs::is_disabled());

    g_vmcs_fields[vmcs::exit_qualification::addr] = bs::mask;
    CHECK(bs::is_enabled(bs::mask));
    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0U;
    CHECK(bs::is_disabled(0x0));

    g_vmcs_fields[vmcs::exit_qualification::addr] = bs::mask;
    CHECK(bs::is_enabled_if_exists());
    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0U;
    CHECK(bs::is_disabled_if_exists());
}

TEST_CASE("vmcs_exit_qualification_page_fault_exception")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::exit_qualification;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 1UL;
    CHECK(page_fault_exception::get() == 1UL);
    g_vmcs_fields[vmcs::exit_qualification::addr] = 0UL;
    CHECK(page_fault_exception::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_exit_qualification_sipi")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::exit_qualification;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 1UL;
    CHECK(sipi::get() == 1UL);
    g_vmcs_fields[vmcs::exit_qualification::addr] = 0UL;
    CHECK(sipi::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_exit_qualification_sipi_vector")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::exit_qualification::sipi;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(vector::get() == (vector::mask >> vector::from));

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(vector::get(vector::mask) == (vector::mask >> vector::from));

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(vector::get_if_exists() == (vector::mask >> vector::from));
}

TEST_CASE("vmcs_exit_qualification_task_switch")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::exit_qualification;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 1UL;
    CHECK(task_switch::get() == 1UL);
    g_vmcs_fields[vmcs::exit_qualification::addr] = 0UL;
    CHECK(task_switch::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_exit_qualification_task_switch_tss_selector")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::exit_qualification::task_switch;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(tss_selector::get() == (tss_selector::mask >> tss_selector::from));

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(tss_selector::get(tss_selector::mask) == (tss_selector::mask >> tss_selector::from));

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(tss_selector::get_if_exists() == (tss_selector::mask >> tss_selector::from));
}

TEST_CASE("vmcs_exit_qualification_task_switch_reserved")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::exit_qualification::task_switch;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(reserved::get() == (reserved::mask >> reserved::from));

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(reserved::get(reserved::mask) == (reserved::mask >> reserved::from));

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(reserved::get_if_exists() == (reserved::mask >> reserved::from));
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

    using namespace vmcs::exit_qualification;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 1UL;
    CHECK(invept::get() == 1UL);
    g_vmcs_fields[vmcs::exit_qualification::addr] = 0UL;
    CHECK(invept::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_exit_qualification_invpcid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::exit_qualification;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 1UL;
    CHECK(invpcid::get() == 1UL);
    g_vmcs_fields[vmcs::exit_qualification::addr] = 0UL;
    CHECK(invpcid::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_exit_qualification_invvpid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::exit_qualification;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 1UL;
    CHECK(invvpid::get() == 1UL);
    g_vmcs_fields[vmcs::exit_qualification::addr] = 0UL;
    CHECK(invvpid::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_exit_qualification_lgdt")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::exit_qualification;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 1UL;
    CHECK(lgdt::get() == 1UL);
    g_vmcs_fields[vmcs::exit_qualification::addr] = 0UL;
    CHECK(lgdt::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_exit_qualification_lidt")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::exit_qualification;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 1UL;
    CHECK(lidt::get() == 1UL);
    g_vmcs_fields[vmcs::exit_qualification::addr] = 0UL;
    CHECK(lidt::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_exit_qualification_lldt")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::exit_qualification;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 1UL;
    CHECK(lldt::get() == 1UL);
    g_vmcs_fields[vmcs::exit_qualification::addr] = 0UL;
    CHECK(lldt::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_exit_qualification_ltr")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::exit_qualification;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 1UL;
    CHECK(ltr::get() == 1UL);
    g_vmcs_fields[vmcs::exit_qualification::addr] = 0UL;
    CHECK(ltr::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_exit_qualification_sgdt")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::exit_qualification;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 1UL;
    CHECK(sgdt::get() == 1UL);
    g_vmcs_fields[vmcs::exit_qualification::addr] = 0UL;
    CHECK(sgdt::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_exit_qualification_sidt")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::exit_qualification;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 1UL;
    CHECK(sidt::get() == 1UL);
    g_vmcs_fields[vmcs::exit_qualification::addr] = 0UL;
    CHECK(sidt::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_exit_qualification_sldt")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::exit_qualification;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 1UL;
    CHECK(sldt::get() == 1UL);
    g_vmcs_fields[vmcs::exit_qualification::addr] = 0UL;
    CHECK(sldt::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_exit_qualification_str")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::exit_qualification;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 1UL;
    CHECK(str::get() == 1UL);
    g_vmcs_fields[vmcs::exit_qualification::addr] = 0UL;
    CHECK(str::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_exit_qualification_vmclear")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::exit_qualification;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 1UL;
    CHECK(vmclear::get() == 1UL);
    g_vmcs_fields[vmcs::exit_qualification::addr] = 0UL;
    CHECK(vmclear::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_exit_qualification_vmptrld")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::exit_qualification;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 1UL;
    CHECK(vmptrld::get() == 1UL);
    g_vmcs_fields[vmcs::exit_qualification::addr] = 0UL;
    CHECK(vmptrld::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_exit_qualification_vmptrst")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::exit_qualification;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 1UL;
    CHECK(vmptrst::get() == 1UL);
    g_vmcs_fields[vmcs::exit_qualification::addr] = 0UL;
    CHECK(vmptrst::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_exit_qualification_vmread")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::exit_qualification;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 1UL;
    CHECK(vmread::get() == 1UL);
    g_vmcs_fields[vmcs::exit_qualification::addr] = 0UL;
    CHECK(vmread::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_exit_qualification_vmwrite")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::exit_qualification;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 1UL;
    CHECK(vmwrite::get() == 1UL);
    g_vmcs_fields[vmcs::exit_qualification::addr] = 0UL;
    CHECK(vmwrite::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_exit_qualification_vmxon")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::exit_qualification;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 1UL;
    CHECK(vmxon::get() == 1UL);
    g_vmcs_fields[vmcs::exit_qualification::addr] = 0UL;
    CHECK(vmxon::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_exit_qualification_xrstors")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::exit_qualification;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 1UL;
    CHECK(xrstors::get() == 1UL);
    g_vmcs_fields[vmcs::exit_qualification::addr] = 0UL;
    CHECK(xrstors::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_exit_qualification_xsaves")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::exit_qualification;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 1UL;
    CHECK(xsaves::get() == 1UL);
    g_vmcs_fields[vmcs::exit_qualification::addr] = 0UL;
    CHECK(xsaves::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_exit_qualification_control_register_access")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::exit_qualification;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 1UL;
    CHECK(control_register_access::get() == 1UL);
    g_vmcs_fields[vmcs::exit_qualification::addr] = 0UL;
    CHECK(control_register_access::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_exit_qualification_control_register_access_control_register_number")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::exit_qualification::control_register_access;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(control_register_number::get() == (control_register_number::mask >> control_register_number::from));

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(control_register_number::get(control_register_number::mask) == (control_register_number::mask >> control_register_number::from));

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(control_register_number::get_if_exists() == (control_register_number::mask >> control_register_number::from));
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

    using namespace vmcs::exit_qualification::control_register_access;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(reserved::get() == (reserved::mask >> reserved::from));

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(reserved::get(reserved::mask) == (reserved::mask >> reserved::from));

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(reserved::get_if_exists() == (reserved::mask >> reserved::from));
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

    using namespace vmcs::exit_qualification;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 1UL;
    CHECK(mov_dr::get() == 1UL);
    g_vmcs_fields[vmcs::exit_qualification::addr] = 0UL;
    CHECK(mov_dr::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_exit_qualification_mov_dr_debug_register_number")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::exit_qualification::mov_dr;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(debug_register_number::get() == (debug_register_number::mask >> debug_register_number::from));

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(debug_register_number::get(debug_register_number::mask) == (debug_register_number::mask >> debug_register_number::from));

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(debug_register_number::get_if_exists() == (debug_register_number::mask >> debug_register_number::from));
}

TEST_CASE("vmcs_exit_qualification_mov_dr_reserved")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::exit_qualification::mov_dr;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(reserved::get() == (reserved::mask >> reserved::from));

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(reserved::get(reserved::mask) == (reserved::mask >> reserved::from));

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(reserved::get_if_exists() == (reserved::mask >> reserved::from));
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

    using namespace vmcs::exit_qualification;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 1UL;
    CHECK(io_instruction::get() == 1UL);
    g_vmcs_fields[vmcs::exit_qualification::addr] = 0UL;
    CHECK(io_instruction::get_if_exists() == 0UL);
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

    g_vmcs_fields[vmcs::exit_qualification::addr] = string_instruction::mask;
    CHECK(string_instruction::is_enabled());
    CHECK(string_instruction::is_enabled(string_instruction::mask));
    CHECK(string_instruction::is_enabled_if_exists());

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0UL;
    CHECK(string_instruction::is_disabled());
    CHECK(string_instruction::is_disabled(0x0UL));
    CHECK(string_instruction::is_disabled_if_exists());
}

TEST_CASE("vmcs_exit_qualification_io_instruction_rep_prefixed")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::exit_qualification::io_instruction;

    g_vmcs_fields[vmcs::exit_qualification::addr] = rep_prefixed::mask;
    CHECK(rep_prefixed::is_enabled());
    CHECK(rep_prefixed::is_enabled(rep_prefixed::mask));
    CHECK(rep_prefixed::is_enabled_if_exists());

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0UL;
    CHECK(rep_prefixed::is_disabled());
    CHECK(rep_prefixed::is_disabled(0x0UL));
    CHECK(rep_prefixed::is_disabled_if_exists());
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

    using namespace vmcs::exit_qualification;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 1UL;
    CHECK(mwait::get() == 1UL);
    g_vmcs_fields[vmcs::exit_qualification::addr] = 0UL;
    CHECK(mwait::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_exit_qualification_linear_apic_access")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::exit_qualification;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 1UL;
    CHECK(linear_apic_access::get() == 1UL);
    g_vmcs_fields[vmcs::exit_qualification::addr] = 0UL;
    CHECK(linear_apic_access::get_if_exists() == 0UL);
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

    using namespace vmcs::exit_qualification;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 1UL;
    CHECK(guest_physical_apic_access::get() == 1UL);
    g_vmcs_fields[vmcs::exit_qualification::addr] = 0UL;
    CHECK(guest_physical_apic_access::get_if_exists() == 0UL);
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

    using namespace vmcs::exit_qualification;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 1UL;
    CHECK(ept_violation::get() == 1UL);
    g_vmcs_fields[vmcs::exit_qualification::addr] = 0UL;
    CHECK(ept_violation::get_if_exists() == 0UL);
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

    using namespace vmcs::exit_qualification;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 1UL;
    CHECK(eoi_virtualization::get() == 1UL);
    g_vmcs_fields[vmcs::exit_qualification::addr] = 0UL;
    CHECK(eoi_virtualization::get_if_exists() == 0UL);
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

    using namespace vmcs::exit_qualification;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 1UL;
    CHECK(apic_write::get() == 1UL);
    g_vmcs_fields[vmcs::exit_qualification::addr] = 0UL;
    CHECK(apic_write::get_if_exists() == 0UL);
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

    using namespace vmcs::io_rcx;

    CHECK(exists());
    g_vmcs_fields[addr] = 100UL;
    CHECK(get() == 100UL);
    g_vmcs_fields[addr] = 200UL;
    CHECK(get_if_exists() == 200UL);

    dump(0);
}

TEST_CASE("vmcs_io_rsi")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::io_rsi;

    CHECK(exists());
    g_vmcs_fields[addr] = 100UL;
    CHECK(get() == 100UL);
    g_vmcs_fields[addr] = 200UL;
    CHECK(get_if_exists() == 200UL);

    dump(0);
}

TEST_CASE("vmcs_io_rdi")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::io_rdi;

    CHECK(exists());
    g_vmcs_fields[addr] = 100UL;
    CHECK(get() == 100UL);
    g_vmcs_fields[addr] = 200UL;
    CHECK(get_if_exists() == 200UL);

    dump(0);
}

TEST_CASE("vmcs_io_rip")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::io_rip;

    CHECK(exists());
    g_vmcs_fields[addr] = 100UL;
    CHECK(get() == 100UL);
    g_vmcs_fields[addr] = 200UL;
    CHECK(get_if_exists() == 200UL);

    dump(0);
}

TEST_CASE("vmcs_guest_linear_address")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_linear_address;

    CHECK(exists());
    g_vmcs_fields[addr] = 100UL;
    CHECK(get() == 100UL);
    g_vmcs_fields[addr] = 200UL;
    CHECK(get_if_exists() == 200UL);

    dump(0);
}

#endif
