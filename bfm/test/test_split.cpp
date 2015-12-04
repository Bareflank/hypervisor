//
// Bareflank Hypervisor
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

#include <test.h>

#include <split.h>

void
bfm_ut::test_split_empty_string()
{
    auto fields = split(std::string(), ' ');

    EXPECT_TRUE(fields.empty() == true);
}

void
bfm_ut::test_split_with_non_existing_delimiter()
{
    auto str = "the cow is blue for this is true";
    auto fields = split(str, 'z');

    ASSERT_TRUE(fields.size() == 1);
    EXPECT_TRUE(fields[0] == str);
}

void
bfm_ut::test_split_with_delimiter()
{
    auto str = "the cow is blue for this is true";
    auto fields = split(str, ' ');

    ASSERT_TRUE(fields.size() == 8);
    EXPECT_TRUE(fields[0] == "the");
    EXPECT_TRUE(fields[1] == "cow");
    EXPECT_TRUE(fields[2] == "is");
    EXPECT_TRUE(fields[3] == "blue");
    EXPECT_TRUE(fields[4] == "for");
    EXPECT_TRUE(fields[5] == "this");
    EXPECT_TRUE(fields[6] == "is");
    EXPECT_TRUE(fields[7] == "true");
}
