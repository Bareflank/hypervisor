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

class crt_ut : public unittest
{
public:

    crt_ut();
    ~crt_ut() override = default;

protected:

    bool init() override;
    bool fini() override;
    bool list() override;

private:

    void test_coveralls();
    void test_local_init_invalid_arg();
    void test_local_init_invalid_addr();
    void test_local_init_invalid_size();
    void test_local_init_register_eh_frame_failure();
    void test_local_init_valid_stop_at_size();
    void test_local_init_valid_stop_at_null();
    void test_local_init_catch_exception();
    void test_local_fini_invalid_arg();
    void test_local_fini_invalid_addr();
    void test_local_fini_invalid_size();
    void test_local_fini_valid_stop_at_size();
    void test_local_fini_valid_stop_at_null();
    void test_local_fini_catch_exception();
};

#endif
