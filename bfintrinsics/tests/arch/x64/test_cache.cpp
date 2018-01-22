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

using namespace x64;

extern "C" void
_invd() noexcept
{ }

extern "C" void
_wbinvd() noexcept
{ }

extern "C" void
_clflush(void *addr) noexcept
{ (void) addr; }

TEST_CASE("cache_x64_invd")
{
    CHECK_NOTHROW(cache::invd());
}

TEST_CASE("cache_x64_wbinvd")
{
    CHECK_NOTHROW(cache::wbinvd());
}

TEST_CASE("cache_x64_clflush")
{
    CHECK_NOTHROW(cache::clflush(0x10));

    int test = 8;
    CHECK_NOTHROW(cache::clflush(&test));
}
