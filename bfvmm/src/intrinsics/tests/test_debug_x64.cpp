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

TEST_CASE("test name goes here")
{
    CHECK(true);
}

dr7::value_type g_dr7 = 0;

uint64_t
test_read_dr7() noexcept
{ return g_dr7; }

void
test_write_dr7(uint64_t val) noexcept
{ g_dr7 = val; }

static void
setup_intrinsics(MockRepository &mocks)
{
    mocks.OnCallFunc(_read_dr7).Do(test_read_dr7);
    mocks.OnCallFunc(_write_dr7).Do(test_write_dr7);
}

TEST_CASE("debug_x64_dr7")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    dr7::set(100U);
    CHECK(dr7::get() == 100UL);

    dr7::set(1000U);
    CHECK(dr7::get() == 1000UL);

    dr7::set(100UL);
    CHECK(dr7::get() == 100UL);

    dr7::set(1000UL);
    CHECK(dr7::get() == 1000UL);
}

#endif
