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

#include <bfgsl.h>
#include <bfnewdelete.h>

#ifndef _WIN32

TEST_CASE("bad alloc")
{
    g_new_throws_bad_alloc = 42;
    auto ___ = gsl::finally([] {
        g_new_throws_bad_alloc = 0;
    });

    CHECK_THROWS(std::make_unique<char[]>(42));
    CHECK_THROWS(std::make_unique<char[]>(0xFFFFFFFFFFFFFFFF));
}

TEST_CASE("non-array new/delete")
{
    std::make_unique<char>();
}

TEST_CASE("array new/delete")
{
    std::make_unique<char[]>(42);
    std::make_unique<char[]>(0x1000);
}

#endif
