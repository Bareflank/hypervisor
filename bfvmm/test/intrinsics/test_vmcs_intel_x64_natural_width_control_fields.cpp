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

    using namespace vmcs::cr0_guest_host_mask;

    CHECK(exists());
    set(100UL);
    CHECK(get() == 100UL);
    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    dump(0);
}

TEST_CASE("vmcs_cr4_guest_host_mask")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::cr4_guest_host_mask;

    CHECK(exists());
    set(100UL);
    CHECK(get() == 100UL);
    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    dump(0);
}

TEST_CASE("vmcs_cr0_read_shadow")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::cr0_read_shadow;

    CHECK(exists());
    set(100UL);
    CHECK(get() == 100UL);
    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    dump(0);
}

TEST_CASE("vmcs_cr4_read_shadow")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::cr4_read_shadow;

    CHECK(exists());
    set(100UL);
    CHECK(get() == 100UL);
    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    dump(0);
}

TEST_CASE("vmcs_cr3_target_value_0")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::cr3_target_value_0;

    CHECK(exists());
    set(100UL);
    CHECK(get() == 100UL);
    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    dump(0);
}

TEST_CASE("vmcs_cr3_target_value_1")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::cr3_target_value_1;

    CHECK(exists());
    set(100UL);
    CHECK(get() == 100UL);
    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    dump(0);
}

TEST_CASE("vmcs_cr3_target_value_2")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::cr3_target_value_2;

    CHECK(exists());
    set(100UL);
    CHECK(get() == 100UL);
    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    dump(0);
}

TEST_CASE("vmcs_cr3_target_value_3")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::cr3_target_value_3;

    CHECK(exists());
    set(100UL);
    CHECK(get() == 100UL);
    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    dump(0);
}

#endif
