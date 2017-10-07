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

read_tsc::value_type g_read_tsc = 0;
read_tscp::value_type g_read_tscp = 0;

uint64_t
test_read_tsc() noexcept
{ return g_read_tsc; }

uint64_t
test_read_tscp() noexcept
{ return g_read_tscp; }

static void
setup_intrinsics(MockRepository &mocks)
{
    mocks.OnCallFunc(_read_tsc).Do(test_read_tsc);
    mocks.OnCallFunc(_read_tscp).Do(test_read_tscp);
}

TEST_CASE("test name goes here")
{
    CHECK(true);
}

TEST_CASE("_rdtsc_x64")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_read_tsc = 10U;
    CHECK(read_tsc::get() == 10U);
}

TEST_CASE("_rdtscp_x64")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_read_tscp = 10U;
    CHECK(read_tscp::get() == 10U);
}

#endif
