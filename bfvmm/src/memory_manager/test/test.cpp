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
    this->test_memory_manager_add_mdl_invalid_mdl();
    this->test_memory_manager_add_mdl_invalid_num();
    this->test_memory_manager_add_mdl_invalid_size();
    this->test_memory_manager_add_mdl_unaligned_physical();
    this->test_memory_manager_add_mdl_unaligned_virtual();
    this->test_memory_manager_virt_to_phys_unknown();
    this->test_memory_manager_phys_to_virt_unknown();
    this->test_memory_manager_virt_to_phys_random_address();
    this->test_memory_manager_virt_to_phys_upper_limit();
    this->test_memory_manager_virt_to_phys_lower_limit();
    this->test_memory_manager_phys_to_virt_random_address();
    this->test_memory_manager_phys_to_virt_upper_limit();
    this->test_memory_manager_phys_to_virt_lower_limit();

    return true;
}

int
main(int argc, char *argv[])
{
    return RUN_ALL_TESTS(memory_manager_ut);
}
