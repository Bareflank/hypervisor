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

debug_ring_ut::debug_ring_ut()
{
}

bool
debug_ring_ut::init()
{
    return this->init_debug_ring();
}

bool
debug_ring_ut::fini()
{
    return this->fini_debug_ring();
}

bool
debug_ring_ut::list()
{
    this->test_init_dr_with_null_drr();
    this->test_init_dr_with_zero_length();
    this->test_read_with_invalid_drr();
    this->test_write_with_invalid_dr();
    this->test_read_with_null_string();
    this->test_read_with_zero_length();
    this->test_write_with_null_string();
    this->test_write_with_zero_length();
    this->test_write_string_to_dr_that_is_larger_than_dr();
    this->test_write_string_to_dr_that_is_much_larger_than_dr();
    this->test_write_one_small_string_to_dr();
    this->test_fill_dr();
    this->test_overcommit_dr();
    this->test_overcommit_dr_more_than_once();
    this->test_read_with_empty_dr();

    this->acceptance_test_stress();

    return true;
}

int
main(int argc, char *argv[])
{
    return RUN_ALL_TESTS(debug_ring_ut);
}
