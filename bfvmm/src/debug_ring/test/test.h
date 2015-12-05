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

class debug_ring_ut : public unittest
{
public:

    debug_ring_ut();
    ~debug_ring_ut() {}

protected:

    bool init() override;
    bool fini() override;
    bool list() override;

private:

    bool init_debug_ring();
    bool fini_debug_ring();

    void test_init_dr_with_null_drr();
    void test_init_dr_with_zero_length();
    void test_read_with_invalid_drr();
    void test_write_with_invalid_dr();
    void test_read_with_null_string();
    void test_read_with_zero_length();
    void test_write_with_null_string();
    void test_write_with_zero_length();
    void test_write_string_to_dr_that_is_larger_than_dr();
    void test_write_string_to_dr_that_is_much_larger_than_dr();
    void test_write_one_small_string_to_dr();
    void test_fill_dr();
    void test_overcommit_dr();
    void test_overcommit_dr_more_than_once();
    void test_read_with_empty_dr();

    void acceptance_test_stress();
};

#endif
