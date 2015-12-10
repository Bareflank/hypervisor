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

memory_manager_ut::memory_manager_ut()
{
}

bool
memory_manager_ut::init()
{
    return true;
}

bool
memory_manager_ut::fini()
{
    return true;
}

bool
memory_manager_ut::list()
{
    this->test_page_constructor_blank_page();
    this->test_page_constructor_invalid_phys();
    this->test_page_constructor_invalid_virt();
    this->test_page_constructor_invalid_size();
    this->test_page_constructor_valid_page();
    this->test_page_allocated();
    this->test_page_allocated_multiple_times();
    this->test_page_phys();
    this->test_page_virt();
    this->test_page_size();
    this->test_page_copy_constructor_copy_blank();
    this->test_page_copy_constructor_copy_valid();
    this->test_page_equal_operator_copy_blank();
    this->test_page_equal_operator_copy_valid();
    this->test_page_blank_equal_blank();
    this->test_page_blank_equal_valid();
    this->test_page_valid_equal_valid_different_phys();
    this->test_page_valid_equal_valid_different_virt();
    this->test_page_valid_equal_valid_different_size();
    this->test_page_valid_equal_valid_same();

    this->test_memory_manager_add_invalid_page();
    this->test_memory_manager_add_valid_page();
    this->test_memory_manager_add_same_page();
    this->test_memory_manager_add_too_many_pages();
    this->test_memory_manager_alloc_page_null_arg();
    this->test_memory_manager_alloc_page_too_many_pages();
    this->test_memory_manager_alloc_page();
    this->test_memory_manager_free_allocated_page();

    return true;
}

int
main(int argc, char *argv[])
{
    return RUN_ALL_TESTS(memory_manager_ut);
}
