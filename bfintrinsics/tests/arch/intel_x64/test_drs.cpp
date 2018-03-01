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
#include <intrinsics.h>

using namespace intel_x64;

dr7::value_type g_dr7 = 0;

extern "C" uint64_t
_read_dr7() noexcept
{ return g_dr7; }

extern "C" void
_write_dr7(uint64_t val) noexcept
{ g_dr7 = val; }

TEST_CASE("debug_dr7")
{
    dr7::set(100U);
    CHECK(dr7::get() == 100UL);

    dr7::set(1000U);
    CHECK(dr7::get() == 1000UL);

    dr7::set(100UL);
    CHECK(dr7::get() == 100UL);

    dr7::set(1000UL);
    CHECK(dr7::get() == 1000UL);
}
