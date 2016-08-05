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
    this->test_memory_manager_malloc_zero();
    this->test_memory_manager_malloc_valid();
    this->test_memory_manager_multiple_malloc_should_be_contiguous();
    this->test_memory_manager_malloc_free_malloc();
    this->test_memory_manager_malloc_page_is_page_aligned();
    this->test_memory_manager_free_zero();
    this->test_memory_manager_free_random();
    this->test_memory_manager_free_twice();
    this->test_memory_manager_malloc_all_of_memory();
    this->test_memory_manager_malloc_all_of_memory_fragmented();
    this->test_memory_manager_malloc_aligned_ignored_alignment();
    this->test_memory_manager_malloc_aligned();
    this->test_memory_manager_malloc_alloc_fragment();
    this->test_memory_manager_malloc_alloc_multiple_fragments();
    this->test_memory_manager_add_md_no_exceptions();
    this->test_memory_manager_add_md_invalid_md();
    this->test_memory_manager_add_md_invalid_virt();
    this->test_memory_manager_add_md_invalid_phys();
    this->test_memory_manager_add_md_invalid_type();
    this->test_memory_manager_add_md_unaligned_physical();
    this->test_memory_manager_add_md_unaligned_virtual();
    this->test_memory_manager_block_to_virt_unknown();
    this->test_memory_manager_virt_to_block_unknown();
    this->test_memory_manager_is_block_aligned_unknown();
    this->test_memory_manager_virt_to_phys_unknown();
    this->test_memory_manager_phys_to_virt_unknown();
    this->test_memory_manager_virt_to_phys_random_address();
    this->test_memory_manager_virt_to_phys_upper_limit();
    this->test_memory_manager_virt_to_phys_lower_limit();
    this->test_memory_manager_virt_to_phys_map();
    this->test_memory_manager_phys_to_virt_random_address();
    this->test_memory_manager_phys_to_virt_upper_limit();
    this->test_memory_manager_phys_to_virt_lower_limit();
    this->test_memory_manager_phys_to_virt_map();

    this->test_page_table_x64_no_entry();
    this->test_page_table_x64_with_entry();
    this->test_page_table_x64_add_page_success();
    this->test_page_table_x64_add_two_pages_no_added_mem_success();
    this->test_page_table_x64_add_two_pages_with_added_mem_success();
    this->test_page_table_x64_add_many_pages_success();
    this->test_page_table_x64_add_page_twice_failure();
    this->test_page_table_x64_table_phys_addr_success();
    this->test_page_table_x64_table_phys_addr_failure();
    this->test_page_table_x64_coveralls_cleanup();

    this->test_page_table_entry_x64_null_present();
    this->test_page_table_entry_x64_present();
    this->test_page_table_entry_x64_null_rw();
    this->test_page_table_entry_x64_rw();
    this->test_page_table_entry_x64_null_us();
    this->test_page_table_entry_x64_us();
    this->test_page_table_entry_x64_null_pwt();
    this->test_page_table_entry_x64_pwt();
    this->test_page_table_entry_x64_null_pcd();
    this->test_page_table_entry_x64_pcd();
    this->test_page_table_entry_x64_null_accessed();
    this->test_page_table_entry_x64_accessed();
    this->test_page_table_entry_x64_null_dirty();
    this->test_page_table_entry_x64_dirty();
    this->test_page_table_entry_x64_null_pat();
    this->test_page_table_entry_x64_pat();
    this->test_page_table_entry_x64_null_global();
    this->test_page_table_entry_x64_global();
    this->test_page_table_entry_x64_null_nx();
    this->test_page_table_entry_x64_nx();
    this->test_page_table_entry_x64_null_phys_addr();
    this->test_page_table_entry_x64_phys_addr();

    return true;
}

int
main(int argc, char *argv[])
{
    return RUN_ALL_TESTS(memory_manager_ut);
}
