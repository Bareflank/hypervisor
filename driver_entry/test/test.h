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

class driver_entry_ut : public unittest
{
public:

    driver_entry_ut();
    ~driver_entry_ut() {}

protected:

    bool init() override;
    bool fini() override;
    bool list() override;

private:

    void test_commit_fini_common_stop_failure();
    void test_commit_fini_common_unload_failure();
    void test_commit_fini_success();
    void test_commit_fini_success_multiple_times();

    void test_common_add_module_invalid_file();
    void test_common_add_module_invalid_file_size();
    void test_common_add_module_status_corrupt();
    void test_common_add_module_status_loaded();
    void test_common_add_module_status_running();
    void test_common_add_module_get_next_file_failed();
    void test_common_add_module_elf_file_init_failed();
    void test_common_add_module_elf_file_total_exec_failed();
    void test_common_add_module_add_elf_file_failed();
    void test_common_add_module_elf_file_load_failed();
    void test_common_add_module_add_success();

    void test_common_load_status_corrupt();
    void test_common_load_status_loaded();
    void test_common_load_status_running();
    void test_common_load_loader_init_failed();
    void test_common_load_loader_add_file_failed();
    void test_common_load_loader_relocate_failed();
    void test_common_load_allocate_page_pool_failed();
    void test_common_load_success();

    void test_common_unload_status_corrupt();
    void test_common_unload_status_running();
    void test_common_unload_free_page_pool_failed();
    void test_common_unload_remove_elf_files_failed();
    void test_common_unload_success_with_loaded();
    void test_common_unload_success_with_unloaded_without_modules();
    void test_common_unload_success_with_unloaded_with_modules();

    void test_common_start_status_corrupt();
    void test_common_start_status_running();
    void test_common_start_status_unloaded();
    void test_common_start_init_vmm_failed();
    void test_common_start_start_vmm_failed();
    void test_common_start_success();
    void test_common_start_success_multiple_times();

    void test_common_stop_status_corrupt();
    void test_common_stop_status_loaded();
    void test_common_stop_status_unloaded();
    void test_common_stop_start_vmm_failed();
    void test_common_stop_success();
    void test_common_stop_success_multiple_times();

    void test_common_dump_status_corrupt();
    void test_common_dump_status_unloaded();
    void test_common_dump_platform_alloc_failed();
    void test_common_dump_resolve_symbol_failed();
    void test_common_dump_debug_ring_read_failed();
    void test_common_dump_success();
    void test_common_dump_success_multiple_times();

    void test_helper_set_vmm_status();
    void test_helper_vmm_status();
    void test_helper_get_file_invalid_index();
    void test_helper_get_file_success();
    void test_helper_get_next_file_too_man_files();
    void test_helper_get_next_file_success();
    void test_helper_add_elf_file_invalid_size();
    void test_helper_add_elf_file_();
    void test_helper_add_elf_file_get_next_file_failed();
    void test_helper_add_elf_file_platform_alloc_exec_failed();
    void test_helper_add_elf_file_success();
    void test_helper_add_elf_file_success_multiple_times();
    void test_helper_symbol_length_null_symbol();
    void test_helper_symbol_length_success();
    void test_helper_resolve_symbol_invalid_name();
    void test_helper_resolve_symbol_invalid_sym();
    void test_helper_resolve_symbol_resolve_symbol_failed();
    void test_helper_resolve_symbol_success();
    void test_helper_execute_symbol_invalid_arg();
    void test_helper_execute_symbol_resolve_symbol_failed();
    void test_helper_execute_symbol_sym_failed();
    void test_helper_execute_symbol_sym_success();
    void test_helper_allocate_page_pool_resolve_symbol_failed();
    void test_helper_allocate_page_pool_alloc_page_failed();
    void test_helper_allocate_page_pool_add_page_failed();
    void test_helper_allocate_page_pool_success();
    void test_helper_allocate_page_pool_success_multiple_times();
    void test_helper_free_page_pool_resolve_symbol_failed();
    void test_helper_free_page_pool_remove_page_failed();
    void test_helper_free_page_pool_success();
    void test_helper_free_page_pool_success_multiple_times();

private:

    char *m_dummy1;
    char *m_dummy2;
    char *m_dummy3;
    int32_t m_dummy1_length;
    int32_t m_dummy2_length;
    int32_t m_dummy3_length;
};

#endif
