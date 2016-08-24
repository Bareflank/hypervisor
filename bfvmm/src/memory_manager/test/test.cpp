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

void *
operator new(std::size_t size)
{
    if ((size & (MAX_PAGE_SIZE - 1)) == 0)
    {
        void *ptr = nullptr;
        auto ignored_ret = posix_memalign(&ptr, MAX_PAGE_SIZE, size);
        (void) ignored_ret;
        return ptr;
    }

    return malloc(size);
}

void
operator delete(void *ptr, std::size_t size) throw()
{
    (void) size;
    free(ptr);
}

void
operator delete(void *ptr) throw()
{
    free(ptr);
}

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
    this->test_memory_manager_free_zero();
    this->test_memory_manager_malloc_heap_valid();
    this->test_memory_manager_multiple_malloc_heap_should_be_contiguous();
    this->test_memory_manager_malloc_heap_free_malloc();
    this->test_memory_manager_free_heap_twice();
    this->test_memory_manager_malloc_heap_all_of_memory();
    this->test_memory_manager_malloc_heap_all_of_memory_one_block();
    this->test_memory_manager_malloc_heap_all_memory_fragmented();
    this->test_memory_manager_malloc_heap_too_much_memory_one_block();
    this->test_memory_manager_malloc_heap_too_much_memory_non_block_size();
    this->test_memory_manager_malloc_heap_really_small_fragment();
    this->test_memory_manager_malloc_heap_sparse_fragments();
    this->test_memory_manager_malloc_heap_massive();
    this->test_memory_manager_malloc_heap_resize_fragments();
    this->test_memory_manager_malloc_page_valid();
    this->test_memory_manager_multiple_malloc_page_should_be_contiguous();
    this->test_memory_manager_malloc_page_free_malloc();
    this->test_memory_manager_free_page_twice();
    this->test_memory_manager_malloc_page_all_of_memory();
    this->test_memory_manager_malloc_page_all_of_memory_one_block();
    this->test_memory_manager_malloc_page_all_memory_fragmented();
    this->test_memory_manager_malloc_page_too_much_memory_one_block();
    this->test_memory_manager_malloc_page_sparse_fragments();
    this->test_memory_manager_malloc_page_resize_fragments();
    this->test_memory_manager_malloc_page_alignment();
    this->test_memory_manager_add_md_no_exceptions();
    this->test_memory_manager_add_md_invalid_md();
    this->test_memory_manager_add_md_invalid_virt();
    this->test_memory_manager_add_md_invalid_phys();
    this->test_memory_manager_add_md_invalid_type();
    this->test_memory_manager_add_md_unaligned_physical();
    this->test_memory_manager_add_md_unaligned_virtual();
    this->test_memory_manager_virtint_to_physint_unknown();
    this->test_memory_manager_physint_to_virtint_unknown();
    this->test_memory_manager_virtint_to_physint_random_address();
    this->test_memory_manager_virtint_to_physint_nullptr();
    this->test_memory_manager_virtint_to_physint_upper_limit();
    this->test_memory_manager_virtint_to_physint_lower_limit();
    this->test_memory_manager_virt_to_phys_map();
    this->test_memory_manager_physint_to_virtint_random_address();
    this->test_memory_manager_physint_to_virtint_nullptr();
    this->test_memory_manager_physint_to_virtint_upper_limit();
    this->test_memory_manager_physint_to_virtint_lower_limit();
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

    this->test_page_table_entry_x64_present();
    this->test_page_table_entry_x64_rw();
    this->test_page_table_entry_x64_us();
    this->test_page_table_entry_x64_pwt();
    this->test_page_table_entry_x64_pcd();
    this->test_page_table_entry_x64_accessed();
    this->test_page_table_entry_x64_dirty();
    this->test_page_table_entry_x64_pat();
    this->test_page_table_entry_x64_global();
    this->test_page_table_entry_x64_nx();
    this->test_page_table_entry_x64_phys_addr();

    return true;
}

int
main(int argc, char *argv[])
{
    return RUN_ALL_TESTS(memory_manager_ut);
}
