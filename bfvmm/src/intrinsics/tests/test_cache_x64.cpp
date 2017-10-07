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
#include <intrinsics/x86/common_x64.h>

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

using namespace x64;

void
test_invd() noexcept
{ }

void
test_wbinvd() noexcept
{ }

void
test_clflush(void *addr) noexcept
{ (void) addr; }

static void
setup_intrinsics(MockRepository &mocks)
{
    mocks.OnCallFunc(_invd).Do(test_invd);
    mocks.OnCallFunc(_wbinvd).Do(test_wbinvd);
    mocks.OnCallFunc(_clflush).Do(test_clflush);
}

TEST_CASE("test name goes here")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(true);
}

TEST_CASE("cache_x64_invd")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK_NOTHROW(cache::invd());
}

TEST_CASE("cache_x64_wbinvd")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK_NOTHROW(cache::wbinvd());
}

TEST_CASE("cache_x64_clflush")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK_NOTHROW(cache::clflush(0x10));

    int test = 8;
    CHECK_NOTHROW(cache::clflush(&test));
}

#endif
