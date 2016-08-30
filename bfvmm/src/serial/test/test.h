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

class serial_ut : public unittest
{
public:

    serial_ut();
    ~serial_ut() override = default;

protected:

    bool init() override;
    bool fini() override;
    bool list() override;

private:

    void test_serial_null_intrinsics();
    void test_serial_success();
    void test_serial_set_baud_rate_success();
    void test_serial_set_data_bits_success();
    void test_serial_set_data_bits_success_extra_bits();
    void test_serial_set_stop_bits_success();
    void test_serial_set_stop_bits_success_extra_bits();
    void test_serial_set_parity_bits_success();
    void test_serial_set_parity_bits_success_extra_bits();
    void test_serial_write_character();
    void test_serial_write_string();
};

#endif
