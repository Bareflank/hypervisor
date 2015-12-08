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
#include <std/stdlib.h>

// The STD functions are a bit more difficult to test as the native environment
// already has versions of these functions. We specifically name these
// functions the same so that this code works the same within the unit tests.
// To get around this, we wrap the normal calls with "bf" versions, and then
// explicitly include our versions of the headers. In the normal includes
// the "std/" would be left out resulting in the native versions being used on
// native, and the cross-compiled versions be used in the vmm, all while still
// providing a means to get at the custom versions for testing as needed.

char g_itoar[IOTA_MIN_BUF_SIZE];

void
std_ut::test_itoa_null_string()
{
    EXPECT_TRUE(bfitoa(10, NULL, 10) == 0);
}

void
std_ut::test_itoa_zero()
{
    EXPECT_TRUE(strcmp(bfitoa(0, g_itoar, 10), "0") == 0);
    EXPECT_TRUE(strcmp(bfitoa(0, g_itoar, 16), "0") == 0);
}

void
std_ut::test_itoa_zero_base()
{
    EXPECT_TRUE(strcmp(bfitoa(10, g_itoar, 0), "0") == 0);
}

void
std_ut::test_itoa_positive_number()
{
    EXPECT_TRUE(strcmp(bfitoa(1, g_itoar, 10), "1") == 0);
    EXPECT_TRUE(strcmp(bfitoa(15, g_itoar, 10), "15") == 0);
    EXPECT_TRUE(strcmp(bfitoa(100, g_itoar, 10), "100") == 0);
}

void
std_ut::test_itoa_negative_number()
{
    EXPECT_TRUE(strcmp(bfitoa(-1, g_itoar, 10), "-1") == 0);
    EXPECT_TRUE(strcmp(bfitoa(-15, g_itoar, 10), "-15") == 0);
    EXPECT_TRUE(strcmp(bfitoa(-100, g_itoar, 10), "-100") == 0);
}

void
std_ut::test_itoa_int_max()
{
    EXPECT_TRUE(strcmp(bfitoa(INT64_MAX, g_itoar, 10), "9223372036854775807") == 0);
}

void
std_ut::test_itoa_int_min()
{
    EXPECT_TRUE(strcmp(bfitoa(INT64_MIN, g_itoar, 10), "-9223372036854775808") == 0);
}

void
std_ut::test_itoa_hex()
{
    EXPECT_TRUE(strcmp(bfitoa(0x1, g_itoar, 16), "1") == 0);
    EXPECT_TRUE(strcmp(bfitoa(0x123456, g_itoar, 16), "123456") == 0);
    EXPECT_TRUE(strcmp(bfitoa(0xABCDEF, g_itoar, 16), "ABCDEF") == 0);
}

void
std_ut::test_itoa_hex_max()
{
    EXPECT_TRUE(strcmp(bfitoa(UINT64_MAX, g_itoar, 16), "FFFFFFFFFFFFFFFF") == 0);
}
