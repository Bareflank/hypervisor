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
#include <new_delete.h>

#include <exception>

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
    this->test_mem_pool_free_zero();
    this->test_mem_pool_free_heap_twice();
    this->test_mem_pool_invalid_pool();
    this->test_mem_pool_malloc_zero();
    this->test_mem_pool_multiple_malloc_heap_should_be_contiguous();
    this->test_mem_pool_malloc_heap_all_of_memory();
    this->test_mem_pool_malloc_heap_all_of_memory_one_block();
    this->test_mem_pool_malloc_heap_all_memory_fragmented();
    this->test_mem_pool_malloc_heap_too_much_memory_one_block();
    this->test_mem_pool_malloc_heap_too_much_memory_non_block_size();
    this->test_mem_pool_malloc_heap_massive();
    this->test_mem_pool_size_out_of_bounds();
    this->test_mem_pool_size_unallocated();
    this->test_mem_pool_size();
    this->test_mem_pool_contains_out_of_bounds();
    this->test_mem_pool_contains();

    this->test_memory_manager_x64_size_out_of_bounds();
    this->test_memory_manager_x64_malloc_out_of_memory();
    this->test_memory_manager_x64_malloc_heap();
    this->test_memory_manager_x64_malloc_page();
    this->test_memory_manager_x64_malloc_map();
    this->test_memory_manager_x64_add_md();
    this->test_memory_manager_x64_add_md_invalid_type();
    this->test_memory_manager_x64_add_md_unaligned_physical();
    this->test_memory_manager_x64_add_md_unaligned_virtual();
    this->test_memory_manager_x64_remove_md_invalid_virt();
    this->test_memory_manager_x64_virtint_to_physint_failure();
    this->test_memory_manager_x64_physint_to_virtint_failure();
    this->test_memory_manager_x64_virtint_to_attrint_failure();
    this->test_memory_manager_x64_virtint_to_physint_random_address();
    this->test_memory_manager_x64_virtint_to_physint_nullptr();
    this->test_memory_manager_x64_physint_to_virtint_random_address();
    this->test_memory_manager_x64_physint_to_virtint_nullptr();
    this->test_memory_manager_x64_virtint_to_attrint_random_address();
    this->test_memory_manager_x64_virtint_to_attrint_nullptr();

    this->test_page_table_x64_add_remove_page_success_without_setting();
    this->test_page_table_x64_add_remove_page_1g_success();
    this->test_page_table_x64_add_remove_page_2m_success();
    this->test_page_table_x64_add_remove_page_4k_success();
    this->test_page_table_x64_add_remove_page_swap_success();
    this->test_page_table_x64_add_page_twice_success();
    this->test_page_table_x64_remove_page_twice_success();
    this->test_page_table_x64_remove_page_unknown_success();
    this->test_page_table_x64_virt_to_pte_invalid();
    this->test_page_table_x64_virt_to_pte_success();
    this->test_page_table_x64_pt_to_mdl_success();

    this->test_page_table_entry_x64_present();
    this->test_page_table_entry_x64_rw();
    this->test_page_table_entry_x64_us();
    this->test_page_table_entry_x64_pwt();
    this->test_page_table_entry_x64_pcd();
    this->test_page_table_entry_x64_accessed();
    this->test_page_table_entry_x64_dirty();
    this->test_page_table_entry_x64_pat();
    this->test_page_table_entry_x64_ps();
    this->test_page_table_entry_x64_global();
    this->test_page_table_entry_x64_nx();
    this->test_page_table_entry_x64_phys_addr();
    this->test_page_table_entry_x64_pat_index();
    this->test_page_table_entry_x64_clear();

    this->test_unique_map_ptr_x64_default_constructor();
    this->test_unique_map_ptr_x64_phys_constructor_invalid_args();
    this->test_unique_map_ptr_x64_phys_constructor_mm_map_fails();
    this->test_unique_map_ptr_x64_phys_constructor_success();
    this->test_unique_map_ptr_x64_phys_range_constructor_invalid_args();
    this->test_unique_map_ptr_x64_phys_range_constructor_mm_map_fails();
    this->test_unique_map_ptr_x64_phys_range_constructor_success();
    this->test_unique_map_ptr_x64_virt_cr3_constructor_invalid_args();
    this->test_unique_map_ptr_x64_virt_cr3_constructor_mm_map_fails();
    this->test_unique_map_ptr_x64_virt_cr3_constructor_success_1g();
    this->test_unique_map_ptr_x64_virt_cr3_constructor_success_2m();
    this->test_unique_map_ptr_x64_virt_cr3_constructor_success_4k();
    this->test_unique_map_ptr_x64_virt_cr3_constructor_success_4k_aligned_addr();
    this->test_unique_map_ptr_x64_virt_cr3_constructor_success_4k_aligned_size();
    this->test_unique_map_ptr_x64_virt_cr3_constructor_not_present();
    this->test_unique_map_ptr_x64_virt_cr3_constructor_invalid_phys_addr();
    this->test_unique_map_ptr_x64_copy_constructor();
    this->test_unique_map_ptr_x64_move_operator_valid();
    this->test_unique_map_ptr_x64_move_operator_invalid();
    this->test_unique_map_ptr_x64_reference_operators();
    this->test_unique_map_ptr_x64_release();
    this->test_unique_map_ptr_x64_reset();
    this->test_unique_map_ptr_x64_swap();
    this->test_unique_map_ptr_x64_flush();
    this->test_unique_map_ptr_x64_cache_flush();
    this->test_unique_map_ptr_x64_comparison();
    this->test_unique_map_ptr_x64_make_failure();
    this->test_virt_to_phys_with_cr3_invalid();
    this->test_virt_to_phys_with_cr3_1g();
    this->test_virt_to_phys_with_cr3_2m();
    this->test_virt_to_phys_with_cr3_4k();

    this->test_root_page_table_x64_init_failure();
    this->test_root_page_table_x64_init_success();
    this->test_root_page_table_x64_cr3();
    this->test_root_page_table_x64_map_1g();
    this->test_root_page_table_x64_map_2m();
    this->test_root_page_table_x64_map_4k();
    this->test_root_page_table_x64_map_invalid();
    this->test_root_page_table_x64_map_unmap_twice_success();
    this->test_root_page_table_x64_setup_identity_map_1g_invalid();
    this->test_root_page_table_x64_setup_identity_map_1g_valid();
    this->test_root_page_table_x64_setup_identity_map_2m_invalid();
    this->test_root_page_table_x64_setup_identity_map_2m_valid();
    this->test_root_page_table_x64_setup_identity_map_4k_invalid();
    this->test_root_page_table_x64_setup_identity_map_4k_valid();
    this->test_root_page_table_x64_pt_to_mdl();

    this->test_pat_x64_mem_attr_to_pat_index();
    this->test_mem_attr_x64_mem_type_to_attr();

    return true;
}

int
main(int argc, char *argv[])
{
    return RUN_ALL_TESTS(memory_manager_ut);
}
