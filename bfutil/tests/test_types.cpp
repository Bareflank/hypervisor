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

// TIDY_EXCLUSION=-cppcoreguidelines-pro-type-reinterpret-cast
//
// Reason:
//     Although in general this is a good rule, for hypervisor level code that
//     interfaces with the kernel, and raw hardware, this rule is
//     impractical.
//

#include <catch/catch.hpp>
#include <bftypes.h>

TEST_CASE("bfscast")
{
    CHECK(bfscast(unsigned, 42) == 42U);
}

TEST_CASE("bfrcast")
{
    CHECK(bfrcast(void *, 0) == nullptr);
}

TEST_CASE("bfadd")
{
    std::vector<int> buf(10);
    CHECK(bfadd(int *, buf.data(), sizeof(int)) == &buf.at(1));
}

TEST_CASE("bfcadd")
{
    std::vector<int> buf(10);
    CHECK(bfcadd(const int *, buf.data(), sizeof(int)) == &buf.at(1));
}

TEST_CASE("bfignored")
{
    auto i = 42;
    bfignored(i);
}
