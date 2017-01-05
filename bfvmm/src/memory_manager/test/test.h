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

    void test_mem_pool_free_zero();
    void test_mem_pool_free_heap_twice();
    void test_mem_pool_invalid_pool();
    void test_mem_pool_malloc_zero();
    void test_mem_pool_multiple_malloc_heap_should_be_contiguous();
    void test_mem_pool_malloc_heap_all_of_memory();
    void test_mem_pool_malloc_heap_all_of_memory_one_block();
    void test_mem_pool_malloc_heap_all_memory_fragmented();
    void test_mem_pool_malloc_heap_too_much_memory_one_block();
    void test_mem_pool_malloc_heap_too_much_memory_non_block_size();
    void test_mem_pool_malloc_heap_massive();
    void test_mem_pool_size_out_of_bounds();
    void test_mem_pool_size_unallocated();
    void test_mem_pool_size();
    void test_mem_pool_contains_out_of_bounds();
    void test_mem_pool_contains();

    void test_memory_manager_x64_size_out_of_bounds();
    void test_memory_manager_x64_malloc_out_of_memory();
    void test_memory_manager_x64_malloc_heap();
    void test_memory_manager_x64_malloc_page();
    void test_memory_manager_x64_malloc_map();
    void test_memory_manager_x64_add_md();
    void test_memory_manager_x64_add_md_invalid_type();
    void test_memory_manager_x64_add_md_unaligned_physical();
    void test_memory_manager_x64_add_md_unaligned_virtual();
    void test_memory_manager_x64_remove_md_invalid_virt();
    void test_memory_manager_x64_virtint_to_physint_failure();
    void test_memory_manager_x64_physint_to_virtint_failure();
    void test_memory_manager_x64_virtint_to_attrint_failure();
    void test_memory_manager_x64_virtint_to_physint_random_address();
    void test_memory_manager_x64_virtint_to_physint_nullptr();
    void test_memory_manager_x64_physint_to_virtint_random_address();
    void test_memory_manager_x64_physint_to_virtint_nullptr();
    void test_memory_manager_x64_virtint_to_attrint_random_address();
    void test_memory_manager_x64_virtint_to_attrint_nullptr();

    void test_page_table_x64_add_remove_page_success_without_setting();
    void test_page_table_x64_add_remove_page_1g_success();
    void test_page_table_x64_add_remove_page_2m_success();
    void test_page_table_x64_add_remove_page_4k_success();
    void test_page_table_x64_add_remove_page_swap_success();
    void test_page_table_x64_add_page_twice_success();
    void test_page_table_x64_remove_page_twice_success();
    void test_page_table_x64_remove_page_unknown_success();
    void test_page_table_x64_virt_to_pte_invalid();
    void test_page_table_x64_virt_to_pte_success();
    void test_page_table_x64_pt_to_mdl_success();

    void test_page_table_entry_x64_present();
    void test_page_table_entry_x64_rw();
    void test_page_table_entry_x64_us();
    void test_page_table_entry_x64_pwt();
    void test_page_table_entry_x64_pcd();
    void test_page_table_entry_x64_accessed();
    void test_page_table_entry_x64_dirty();
    void test_page_table_entry_x64_pat();
    void test_page_table_entry_x64_ps();
    void test_page_table_entry_x64_global();
    void test_page_table_entry_x64_nx();
    void test_page_table_entry_x64_phys_addr();
    void test_page_table_entry_x64_pat_index();
    void test_page_table_entry_x64_clear();

    void test_unique_map_ptr_x64_default_constructor();
    void test_unique_map_ptr_x64_phys_constructor_invalid_args();
    void test_unique_map_ptr_x64_phys_constructor_mm_map_fails();
    void test_unique_map_ptr_x64_phys_constructor_success();
    void test_unique_map_ptr_x64_phys_range_constructor_invalid_args();
    void test_unique_map_ptr_x64_phys_range_constructor_mm_map_fails();
    void test_unique_map_ptr_x64_phys_range_constructor_success();
    void test_unique_map_ptr_x64_virt_cr3_constructor_invalid_args();
    void test_unique_map_ptr_x64_virt_cr3_constructor_mm_map_fails();
    void test_unique_map_ptr_x64_virt_cr3_constructor_success_1g();
    void test_unique_map_ptr_x64_virt_cr3_constructor_success_2m();
    void test_unique_map_ptr_x64_virt_cr3_constructor_success_4k();
    void test_unique_map_ptr_x64_virt_cr3_constructor_success_4k_aligned_addr();
    void test_unique_map_ptr_x64_virt_cr3_constructor_success_4k_aligned_size();
    void test_unique_map_ptr_x64_virt_cr3_constructor_not_present();
    void test_unique_map_ptr_x64_virt_cr3_constructor_invalid_phys_addr();
    void test_unique_map_ptr_x64_copy_constructor();
    void test_unique_map_ptr_x64_move_operator_valid();
    void test_unique_map_ptr_x64_move_operator_invalid();
    void test_unique_map_ptr_x64_reference_operators();
    void test_unique_map_ptr_x64_release();
    void test_unique_map_ptr_x64_reset();
    void test_unique_map_ptr_x64_swap();
    void test_unique_map_ptr_x64_flush();
    void test_unique_map_ptr_x64_cache_flush();
    void test_unique_map_ptr_x64_comparison();
    void test_unique_map_ptr_x64_make_failure();
    void test_virt_to_phys_with_cr3_invalid();
    void test_virt_to_phys_with_cr3_1g();
    void test_virt_to_phys_with_cr3_2m();
    void test_virt_to_phys_with_cr3_4k();

    void test_root_page_table_x64_init_failure();
    void test_root_page_table_x64_init_success();
    void test_root_page_table_x64_cr3();
    void test_root_page_table_x64_map_1g();
    void test_root_page_table_x64_map_2m();
    void test_root_page_table_x64_map_4k();
    void test_root_page_table_x64_map_invalid();
    void test_root_page_table_x64_map_unmap_twice_success();
    void test_root_page_table_x64_setup_identity_map_1g_invalid();
    void test_root_page_table_x64_setup_identity_map_1g_valid();
    void test_root_page_table_x64_setup_identity_map_2m_invalid();
    void test_root_page_table_x64_setup_identity_map_2m_valid();
    void test_root_page_table_x64_setup_identity_map_4k_invalid();
    void test_root_page_table_x64_setup_identity_map_4k_valid();
    void test_root_page_table_x64_pt_to_mdl();

    void test_pat_x64_mem_attr_to_pat_index();
    void test_mem_attr_x64_mem_type_to_attr();
};

#endif
