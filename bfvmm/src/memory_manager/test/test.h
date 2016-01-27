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

    void test_memory_manager_malloc_zero();
    void test_memory_manager_malloc_valid();
    void test_memory_manager_multiple_malloc_should_be_contiguous();
    void test_memory_manager_malloc_free_malloc();
    void test_memory_manager_malloc_page_is_page_aligned();
    void test_memory_manager_free_zero();
    void test_memory_manager_free_random();
    void test_memory_manager_free_twice();
    void test_memory_manager_malloc_all_of_memory();
    void test_memory_manager_malloc_all_of_memory_fragmented();
    void test_memory_manager_malloc_aligned_ignored_alignment();
    void test_memory_manager_malloc_aligned();
    void test_memory_manager_malloc_alloc_fragment();
    void test_memory_manager_add_mdl_invalid_mdl();
    void test_memory_manager_add_mdl_invalid_num();
    void test_memory_manager_add_mdl_invalid_size();
    void test_memory_manager_add_mdl_unaligned_physical();
    void test_memory_manager_add_mdl_unaligned_virtual();
    void test_memory_manager_virt_to_phys_unknown();
    void test_memory_manager_phys_to_virt_unknown();
    void test_memory_manager_virt_to_phys_random_address();
    void test_memory_manager_virt_to_phys_upper_limit();
    void test_memory_manager_virt_to_phys_lower_limit();
    void test_memory_manager_phys_to_virt_random_address();
    void test_memory_manager_phys_to_virt_upper_limit();
    void test_memory_manager_phys_to_virt_lower_limit();
};

#endif
