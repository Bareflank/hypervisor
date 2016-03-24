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

    void test_common_fini_unloaded();
    void test_common_fini_successful_start();
    void test_common_fini_successful_load();
    void test_common_fini_successful_add_module();
    void test_common_fini_corrupted();
    void test_common_fini_failed_load();
    void test_common_fini_failed_start();

    void test_common_add_module_invalid_file();
    void test_common_add_module_invalid_file_size();
    void test_common_add_module_garbage_module();
    void test_common_add_module_add_when_already_loaded();
    void test_common_add_module_add_when_already_running();
    void test_common_add_module_add_when_corrupt();
    void test_common_add_module_add_too_many();

    void test_common_load_successful_load();
    void test_common_load_load_when_already_loaded();
    void test_common_load_load_when_already_running();
    void test_common_load_load_when_corrupt();
    void test_common_load_fail_due_to_relocation_error();
    void test_common_load_fail_due_to_no_modules_added();
    void test_common_load_add_mdl_failed();

    void test_common_unload_unload_when_already_unloaded();
    void test_common_unload_unload_when_running();
    void test_common_unload_unload_when_corrupt();

    void test_common_start_start_when_unloaded();
    void test_common_start_start_when_already_running();
    void test_common_start_start_when_corrupt();
    void test_common_start_start_when_init_vmm_missing();
    void test_common_start_start_when_start_vmm_missing();
    void test_common_start_init_vmm_failure();
    void test_common_start_start_vmm_failure();

    void test_common_stop_stop_when_unloaded();
    void test_common_stop_stop_when_not_running();
    void test_common_stop_stop_when_alread_stopped();
    void test_common_stop_stop_when_corrupt();
    void test_common_stop_stop_vmm_missing();
    void test_common_stop_stop_vmm_failure();

    void test_common_dump_invalid_drr();
    void test_common_dump_dump_when_unloaded();
    void test_common_dump_dump_when_corrupt();
    void test_common_dump_dump_when_loaded();
    void test_common_dump_get_drr_missing();
    void test_common_dump_get_drr_failure();

    void test_helper_common_vmm_status();
    void test_helper_get_file_invalid_index();
    void test_helper_get_file_success();
    void test_helper_symbol_length_null_symbol();
    void test_helper_symbol_length_success();
    void test_helper_resolve_symbol_invalid_name();
    void test_helper_resolve_symbol_invalid_sym();
    void test_helper_resolve_symbol_missing_symbol();
    void test_helper_execute_symbol_invalid_arg();
    void test_helper_execute_symbol_missing_symbol();
    void test_helper_execute_symbol_sym_failed();
    void test_helper_execute_symbol_sym_success();
    void test_helper_constructors_success();
    void test_helper_destructors_success();
    void test_helper_add_mdl_invalid_exec();
    void test_helper_add_mdl_invalid_size();
    void test_helper_add_mdl_1_page();
    void test_helper_add_mdl_3_pages();
    void test_helper_add_mdl_3_pages_plus();

private:

    char *m_dummy_add_mdl_failure;
    char *m_dummy_add_mdl_success;
    char *m_dummy_get_drr_failure;
    char *m_dummy_get_drr_success;
    char *m_dummy_init_vmm_failure;
    char *m_dummy_init_vmm_success;
    char *m_dummy_misc;
    char *m_dummy_start_vmm_failure;
    char *m_dummy_start_vmm_success;
    char *m_dummy_stop_vmm_failure;
    char *m_dummy_stop_vmm_success;

    int32_t m_dummy_add_mdl_failure_length;
    int32_t m_dummy_add_mdl_success_length;
    int32_t m_dummy_get_drr_failure_length;
    int32_t m_dummy_get_drr_success_length;
    int32_t m_dummy_init_vmm_failure_length;
    int32_t m_dummy_init_vmm_success_length;
    int32_t m_dummy_misc_length;
    int32_t m_dummy_start_vmm_failure_length;
    int32_t m_dummy_start_vmm_success_length;
    int32_t m_dummy_stop_vmm_failure_length;
    int32_t m_dummy_stop_vmm_success_length;
};

#endif
