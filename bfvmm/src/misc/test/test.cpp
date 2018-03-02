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

misc_ut::misc_ut()
{
}

bool
misc_ut::init()
{
    return true;
}

bool
misc_ut::fini()
{
    return true;
}

bool
misc_ut::list()
{
    this->test_error_codes_valid();
    this->test_error_codes_unknown();

    this->test_string_literal();
    this->test_string_to_string();

    this->test_vector_find();
    this->test_vector_cfind();
    this->test_vector_take();
    this->test_vector_remove();

    this->test_guard_exceptions_no_return();
    this->test_guard_exceptions_with_return();

    this->test_bitmanip_set_bit();
    this->test_bitmanip_clear_bit();
    this->test_bitmanip_get_bit();
    this->test_bitmanip_is_bit_set();
    this->test_bitmanip_is_bit_cleared();
    this->test_bitmanip_num_bits_set();
    this->test_bitmanip_get_bits();
    this->test_bitmanip_set_bits();

    this->test_exceptions();

    this->test_upper();
    this->test_lower();

    return true;
}

int
main(int argc, char *argv[])
{
    return RUN_ALL_TESTS(misc_ut);
}
