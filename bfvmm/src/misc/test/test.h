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

#ifndef TEST_H
#define TEST_H

#include <unittest.h>

class misc_ut : public unittest
{
public:

    misc_ut();
    ~misc_ut() override = default;

protected:

    bool init() override;
    bool fini() override;
    bool list() override;

private:

    void test_error_codes_valid();
    void test_error_codes_unknown();

    void test_string_literal();
    void test_string_to_string();

    void test_vector_find();
    void test_vector_cfind();
    void test_vector_take();
    void test_vector_remove();

    void test_guard_exceptions_no_return();
    void test_guard_exceptions_with_return();

    void test_bitmanip_set_bit();
    void test_bitmanip_clear_bit();
    void test_bitmanip_get_bit();
    void test_bitmanip_is_bit_set();
    void test_bitmanip_is_bit_cleared();
    void test_bitmanip_num_bits_set();
    void test_bitmanip_get_bits();
    void test_bitmanip_set_bits();

    void test_exceptions();

    void test_upper();
    void test_lower();
};

#endif
