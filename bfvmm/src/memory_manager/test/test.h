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
    ~memory_manager_ut() override = default;

protected:

    bool init() override;
    bool fini() override;
    bool list() override;

private:

    void test_memory_manager_free_zero();
    void test_memory_manager_free_heap_twice();
    void test_memory_manager_malloc_zero();
    void test_memory_manager_multiple_malloc_heap_should_be_contiguous();
    void test_memory_manager_malloc_heap_all_of_memory();
    void test_memory_manager_malloc_heap_all_of_memory_one_block();
    void test_memory_manager_malloc_heap_all_memory_fragmented();
    void test_memory_manager_malloc_heap_too_much_memory_one_block();
    void test_memory_manager_malloc_heap_too_much_memory_non_block_size();
    void test_memory_manager_malloc_heap_massive();
    void test_memory_manager_size_out_of_bounds();
    void test_memory_manager_size_unallocated();
    void test_memory_manager_size();
    void test_memory_manager_contains_out_of_bounds();
    void test_memory_manager_contains();
    void test_memory_manager_malloc_out_of_memory();
    void test_memory_manager_malloc_heap();
    void test_memory_manager_malloc_page();
    void test_memory_manager_add_md_no_exceptions();
    void test_memory_manager_add_md_invalid_md();
    void test_memory_manager_add_md_invalid_virt();
    void test_memory_manager_add_md_invalid_phys();
    void test_memory_manager_add_md_invalid_type();
    void test_memory_manager_add_md_unaligned_physical();
    void test_memory_manager_add_md_unaligned_virtual();
    void test_memory_manager_virtint_to_physint_unknown();
    void test_memory_manager_physint_to_virtint_unknown();
    void test_memory_manager_virtint_to_physint_random_address();
    void test_memory_manager_virtint_to_physint_nullptr();
    void test_memory_manager_virtint_to_physint_upper_limit();
    void test_memory_manager_virtint_to_physint_lower_limit();
    void test_memory_manager_virt_to_phys_map();
    void test_memory_manager_physint_to_virtint_random_address();
    void test_memory_manager_physint_to_virtint_nullptr();
    void test_memory_manager_physint_to_virtint_upper_limit();
    void test_memory_manager_physint_to_virtint_lower_limit();
    void test_memory_manager_phys_to_virt_map();

    void test_page_table_x64_no_entry();
    void test_page_table_x64_with_entry();
    void test_page_table_x64_add_page_success();
    void test_page_table_x64_add_two_pages_no_added_mem_success();
    void test_page_table_x64_add_two_pages_with_added_mem_success();
    void test_page_table_x64_add_many_pages_success();
    void test_page_table_x64_add_page_twice_failure();
    void test_page_table_x64_table_phys_addr_success();
    void test_page_table_x64_table_phys_addr_failure();

    void test_page_table_entry_x64_present();
    void test_page_table_entry_x64_rw();
    void test_page_table_entry_x64_us();
    void test_page_table_entry_x64_pwt();
    void test_page_table_entry_x64_pcd();
    void test_page_table_entry_x64_accessed();
    void test_page_table_entry_x64_dirty();
    void test_page_table_entry_x64_pat();
    void test_page_table_entry_x64_global();
    void test_page_table_entry_x64_nx();
    void test_page_table_entry_x64_phys_addr();
};

#endif
