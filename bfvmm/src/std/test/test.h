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

class std_ut : public unittest
{
public:

    std_ut();
    ~std_ut() {}

protected:

    bool init() override;
    bool fini() override;
    bool list() override;

private:

    void test_string_null();
    void test_string_empty_string();
    void test_string_string_of_zeros();
    void test_string_normal_string();
    void test_string_multiple_normal_string();

    void test_itoa_null_string();
    void test_itoa_zero();
    void test_itoa_zero_base();
    void test_itoa_positive_number();
    void test_itoa_negative_number();
    void test_itoa_int_max();
    void test_itoa_int_min();
    void test_itoa_hex();
    void test_itoa_hex_max();
};

#endif
