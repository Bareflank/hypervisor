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
#include <intrinsics/x86/common_x64.h>
#include <intrinsics/x86/intel_x64.h>

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

using namespace intel_x64;
using namespace msrs;
using namespace vmcs;
using namespace debug;

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

TEST_CASE("get_vmcs_field")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    constexpr const auto name = "field";

    CHECK_THROWS(get_vmcs_field(0ULL, name, false));

    g_vmcs_fields[0UL] = 42UL;
    CHECK(get_vmcs_field(0ULL, name, true) == 42UL);
}

TEST_CASE("get_vmcs_field_if_exists")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    constexpr const auto name = "field";

    g_vmcs_fields[0UL] = 42UL;

    CHECK(get_vmcs_field_if_exists(0ULL, name, true, false) == 0UL);
    CHECK(get_vmcs_field_if_exists(0ULL, name, true, true) == 42UL);
}

TEST_CASE("set_vmcs_field")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    constexpr const auto name("field");
    g_vmcs_fields[0UL] = 0UL;

    CHECK_THROWS(set_vmcs_field(1ULL, 0ULL, name, false));
    CHECK(g_vmcs_fields[0UL] == 0UL);

    CHECK_NOTHROW(set_vmcs_field(1ULL, 0ULL, name, true));
    CHECK(g_vmcs_fields[0UL] == 1UL);
}

TEST_CASE("set_vmcs_field_if_exists")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    constexpr const auto name("field");
    g_vmcs_fields[0UL] = 42UL;

    CHECK_NOTHROW(set_vmcs_field_if_exists(0ULL, 0ULL, name, false, false));
    CHECK(g_vmcs_fields[0UL] == 42UL);

    CHECK_NOTHROW(set_vmcs_field_if_exists(0ULL, 0ULL, name, true, false));
    CHECK(g_vmcs_fields[0UL] == 42UL);

    CHECK_NOTHROW(set_vmcs_field_if_exists(0ULL, 0ULL, name, false, true));
    CHECK(g_vmcs_fields[0UL] == 0U);

    CHECK_NOTHROW(set_vmcs_field_if_exists(1ULL, 0ULL, name, true, true));
    CHECK(g_vmcs_fields[0UL] == 1UL);
}

TEST_CASE("set_vm_control")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    constexpr const auto name = "control";
    auto mask = 0x0000000000000040ULL;
    auto ctls_addr = 0ULL;
    auto msr_addr = 0UL;

    CHECK_THROWS(set_vm_control(true, msr_addr, ctls_addr, name, mask, false));

    g_msrs[gsl::narrow_cast<uint16_t>(msr_addr)] = ~mask;
    CHECK_NOTHROW(set_vm_control(false, msr_addr, ctls_addr, name, mask, true));
    CHECK((g_vmcs_fields[ctls_addr] & mask) == 0UL);

    g_msrs[gsl::narrow_cast<uint16_t>(msr_addr)] = mask;
    CHECK_THROWS(set_vm_control(false, msr_addr, ctls_addr, name, mask, true));

    g_msrs[gsl::narrow_cast<uint16_t>(msr_addr)] = mask << 32;
    CHECK_NOTHROW(set_vm_control(true, msr_addr, ctls_addr, name, mask, true));
    CHECK((g_vmcs_fields[ctls_addr] & mask) != 0UL);

    g_msrs[gsl::narrow_cast<uint16_t>(msr_addr)] = ~(mask << 32);
    CHECK_THROWS(set_vm_control(true, msr_addr, ctls_addr, name, mask, true));
}

TEST_CASE("set_vm_control_if_allowed")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    constexpr const auto name = "control";
    auto mask = 0x0000000000000040ULL;
    auto ctls_addr = 0ULL;
    auto msr_addr = 0UL;

    CHECK_NOTHROW(set_vm_control_if_allowed(true, msr_addr, ctls_addr, name, mask, true, false));

    g_vmcs_fields[ctls_addr] = mask;
    g_msrs[gsl::narrow_cast<uint16_t>(msr_addr)] = ~mask;

    CHECK_NOTHROW(set_vm_control_if_allowed(false, msr_addr, ctls_addr, name, mask, true, true));
    CHECK((g_vmcs_fields[ctls_addr] & mask) == 0UL);

    g_msrs[gsl::narrow_cast<uint16_t>(msr_addr)] = mask;
    CHECK_NOTHROW(set_vm_control_if_allowed(false, msr_addr, ctls_addr, name, mask, true, true));

    g_msrs[gsl::narrow_cast<uint16_t>(msr_addr)] = mask;
    CHECK_NOTHROW(set_vm_control_if_allowed(true, msr_addr, ctls_addr, name, mask, true, true));

    g_msrs[gsl::narrow_cast<uint16_t>(msr_addr)] = mask << 32;
    CHECK_NOTHROW(set_vm_control_if_allowed(true, msr_addr, ctls_addr, name, mask, true, true));
    CHECK((g_vmcs_fields[ctls_addr] & mask) != 0UL);

    g_msrs[gsl::narrow_cast<uint16_t>(msr_addr)] = ~(mask << 32);
    CHECK_NOTHROW(set_vm_control_if_allowed(true, msr_addr, ctls_addr, name, mask, true, true));
}

TEST_CASE("set_vm_function_control")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    constexpr const auto name = "control";
    auto mask = 0x0000000000000040ULL;
    auto ctls_addr = 0ULL;
    auto msr_addr = 0UL;

    CHECK_THROWS(set_vm_function_control(true, msr_addr, ctls_addr, name, mask, false));
    CHECK_NOTHROW(set_vm_function_control(false, msr_addr, ctls_addr, name, mask, true));

    g_msrs[gsl::narrow_cast<uint16_t>(msr_addr)] = mask;
    CHECK_NOTHROW(set_vm_function_control(true, msr_addr, ctls_addr, name, mask, true));

    g_msrs[gsl::narrow_cast<uint16_t>(msr_addr)] = ~mask;
    CHECK_THROWS(set_vm_function_control(true, msr_addr, ctls_addr, name, mask, true));
}

TEST_CASE("set_vm_function_control_if_allowed")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    constexpr const auto name = "control";
    auto mask = 0x0000000000000040ULL;
    auto ctls_addr = 0ULL;
    auto msr_addr = 0UL;

    CHECK_NOTHROW(set_vm_function_control_if_allowed(true, msr_addr, ctls_addr, name, mask, true, false));
    CHECK_NOTHROW(set_vm_function_control_if_allowed(false, msr_addr, ctls_addr, name, mask, true, true));

    g_msrs[gsl::narrow_cast<uint16_t>(msr_addr)] = mask;
    CHECK_NOTHROW(set_vm_function_control_if_allowed(true, msr_addr, ctls_addr, name, mask, true, true));

    g_msrs[gsl::narrow_cast<uint16_t>(msr_addr)] = ~mask;
    CHECK_NOTHROW(set_vm_function_control_if_allowed(true, msr_addr, ctls_addr, name, mask, true, true));
}

TEST_CASE("memory_type_reserved")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK_FALSE(memory_type_reserved(0x00000000ULL));
    CHECK_FALSE(memory_type_reserved(0x00000001ULL));
    CHECK_FALSE(memory_type_reserved(0x00000004ULL));
    CHECK_FALSE(memory_type_reserved(0x00000005ULL));
    CHECK_FALSE(memory_type_reserved(0x00000006ULL));
    CHECK_FALSE(memory_type_reserved(0x00000007ULL));

    CHECK(memory_type_reserved(0x00000008ULL));
}

#endif
