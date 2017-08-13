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

TEST_CASE("vmcs_cr0_guest_host_mask")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::cr0_guest_host_mask::exists());

    vmcs::cr0_guest_host_mask::set(1UL);
    CHECK(vmcs::cr0_guest_host_mask::get() == 1UL);

    vmcs::cr0_guest_host_mask::set_if_exists(2UL);
    CHECK(vmcs::cr0_guest_host_mask::get_if_exists() == 2UL);
}

TEST_CASE("vmcs_cr4_guest_host_mask")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::cr4_guest_host_mask::exists());

    vmcs::cr4_guest_host_mask::set(1UL);
    CHECK(vmcs::cr4_guest_host_mask::get() == 1UL);

    vmcs::cr4_guest_host_mask::set_if_exists(2UL);
    CHECK(vmcs::cr4_guest_host_mask::get_if_exists() == 2UL);
}

TEST_CASE("vmcs_cr0_read_shadow")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::cr0_read_shadow::exists());

    vmcs::cr0_read_shadow::set(1UL);
    CHECK(vmcs::cr0_read_shadow::get() == 1UL);

    vmcs::cr0_read_shadow::set_if_exists(2UL);
    CHECK(vmcs::cr0_read_shadow::get_if_exists() == 2UL);
}

TEST_CASE("vmcs_cr4_read_shadow")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::cr4_read_shadow::exists());

    vmcs::cr4_read_shadow::set(1UL);
    CHECK(vmcs::cr4_read_shadow::get() == 1UL);

    vmcs::cr4_read_shadow::set_if_exists(2UL);
    CHECK(vmcs::cr4_read_shadow::get_if_exists() == 2UL);
}

TEST_CASE("vmcs_cr3_target_value_0")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::cr3_target_value_0::exists());

    vmcs::cr3_target_value_0::set(1UL);
    CHECK(vmcs::cr3_target_value_0::get() == 1UL);

    vmcs::cr3_target_value_0::set_if_exists(2UL);
    CHECK(vmcs::cr3_target_value_0::get_if_exists() == 2UL);
}

TEST_CASE("vmcs_cr3_target_value_1")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::cr3_target_value_1::exists());

    vmcs::cr3_target_value_1::set(1UL);
    CHECK(vmcs::cr3_target_value_1::get() == 1UL);

    vmcs::cr3_target_value_1::set_if_exists(2UL);
    CHECK(vmcs::cr3_target_value_1::get_if_exists() == 2UL);
}

TEST_CASE("vmcs_cr3_target_value_2")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::cr3_target_value_2::exists());

    vmcs::cr3_target_value_2::set(1UL);
    CHECK(vmcs::cr3_target_value_2::get() == 1UL);

    vmcs::cr3_target_value_2::set_if_exists(2UL);
    CHECK(vmcs::cr3_target_value_2::get_if_exists() == 2UL);
}

TEST_CASE("vmcs_cr3_target_value_3")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::cr3_target_value_3::exists());

    vmcs::cr3_target_value_3::set(1UL);
    CHECK(vmcs::cr3_target_value_3::get() == 1UL);

    vmcs::cr3_target_value_3::set_if_exists(2UL);
    CHECK(vmcs::cr3_target_value_3::get_if_exists() == 2UL);
}

#endif
