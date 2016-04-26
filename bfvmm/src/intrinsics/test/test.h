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

class intrinsics_ut : public unittest
{
public:

    intrinsics_ut();
    ~intrinsics_ut() {}

protected:

    bool init() override;
    bool fini() override;
    bool list() override;

private:

    void test_constructor_no_size();
    void test_constructor_zero_size();
    void test_constructor_size();
    void test_base();
    void test_limit();
    void test_set_base_zero_index();
    void test_set_base_invalid_index();
    void test_set_base_tss_at_end_of_gdt();
    void test_set_base_descriptor_success();
    void test_set_base_tss_success();
    void test_base_zero_index();
    void test_base_invalid_index();
    void test_base_tss_at_end_of_gdt();
    void test_base_descriptor_success();
    void test_base_tss_success();
    void test_set_limit_zero_index();
    void test_set_limit_invalid_index();
    void test_set_limit_descriptor_success();
    void test_limit_zero_index();
    void test_limit_invalid_index();
    void test_limit_descriptor_success();
    void test_set_access_rights_zero_index();
    void test_set_access_rights_invalid_index();
    void test_set_access_rights_descriptor_success();
    void test_access_rights_zero_index();
    void test_access_rights_invalid_index();
    void test_access_rights_descriptor_success();
};

#endif
