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

class memory_manager_ut : public unittest
{
public:

    memory_manager_ut();
    ~memory_manager_ut() {}

protected:

    bool init() override;
    bool fini() override;
    bool list() override;

private:

    void test_page_constructor_blank_page();
    void test_page_constructor_invalid_phys();
    void test_page_constructor_invalid_virt();
    void test_page_constructor_invalid_size();
    void test_page_constructor_valid_page();
    void test_page_allocated();
    void test_page_allocated_multiple_times();
    void test_page_phys();
    void test_page_virt();
    void test_page_size();
    void test_page_copy_constructor_copy_blank();
    void test_page_copy_constructor_copy_valid();
    void test_page_equal_operator_copy_blank();
    void test_page_equal_operator_copy_valid();
    void test_page_blank_equal_blank();
    void test_page_blank_equal_valid();
    void test_page_valid_equal_valid_different_phys();
    void test_page_valid_equal_valid_different_virt();
    void test_page_valid_equal_valid_different_size();
    void test_page_valid_equal_valid_same();

    void test_memory_manager_add_invalid_page();
    void test_memory_manager_add_valid_page();
    void test_memory_manager_add_same_page();
    void test_memory_manager_add_too_many_pages();
    void test_memory_manager_alloc_page_null_arg();
    void test_memory_manager_alloc_page_too_many_pages();
    void test_memory_manager_alloc_page();
    void test_memory_manager_free_allocated_page();
};

#endif
