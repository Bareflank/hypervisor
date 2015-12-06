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

std_ut::std_ut()
{
}

bool
std_ut::init()
{
    return true;
}

bool
std_ut::fini()
{
    return true;
}

bool
std_ut::list()
{
    this->test_string_null();
    this->test_string_empty_string();
    this->test_string_string_of_zeros();
    this->test_string_normal_string();
    this->test_string_multiple_normal_string();

    this->test_itoa_null_string();
    this->test_itoa_zero();
    this->test_itoa_zero_base();
    this->test_itoa_positive_number();
    this->test_itoa_negative_number();
    this->test_itoa_int_max();
    this->test_itoa_int_min();
    this->test_itoa_hex();
    this->test_itoa_hex_max();

    return true;
}

int
main(int argc, char *argv[])
{
    return RUN_ALL_TESTS(std_ut);
}
