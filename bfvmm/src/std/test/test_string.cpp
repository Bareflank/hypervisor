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
#include <std/string.h>

// The STD functions are a bit more difficult to test as the native environment
// already has versions of these functions. We specifically name these
// functions the same so that this code works the same within the unit tests.
// To get around this, we wrap the normal calls with "bf" versions, and then
// explicitly include our versions of the headers. In the normal includes
// the "std/" would be left out resulting in the native versions being used on
// native, and the cross-compiled versions be used in the vmm, all while still
// providing a means to get at the custom versions for testing as needed.

void
std_ut::test_string_null()
{
    EXPECT_TRUE(bfstrlen(0) == 0);
}

void
std_ut::test_string_empty_string()
{
    EXPECT_TRUE(bfstrlen("") == 0);
}

void
std_ut::test_string_string_of_zeros()
{
    EXPECT_TRUE(bfstrlen("\0\0\0\0\0\0") == 0);
}

void
std_ut::test_string_normal_string()
{
    EXPECT_TRUE(bfstrlen("hello world\n") == 12);
}

void
std_ut::test_string_multiple_normal_string()
{
    EXPECT_TRUE(bfstrlen("hello\0 world\n") == 5);
}
