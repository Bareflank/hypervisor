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
    ~driver_entry_ut() override = default;

protected:

    bool init() override;
    bool fini() override;
    bool list() override;

private:

    void test_common_init();

    void test_common_fini_unloaded();
    void test_common_fini_successful_start();
    void test_common_fini_successful_load();
    void test_common_fini_successful_add_module();
    void test_common_fini_corrupted();
    void test_common_fini_failed_load();
    void test_common_fini_failed_start();
    void test_common_fini_unload_failed();
    void test_common_fini_stop_failed();
    void test_common_fini_reset_failed();

    void test_common_add_module_invalid_file();
    void test_common_add_module_invalid_file_size();
    void test_common_add_module_garbage_module();
    void test_common_add_module_add_when_already_loaded();
    void test_common_add_module_add_when_already_running();
    void test_common_add_module_add_when_corrupt();
    void test_common_add_module_add_too_many();
    void test_common_add_module_platform_alloc_fails();
    void test_common_add_module_load_elf_fails();

    void test_common_load_successful_load();
    void test_common_load_load_when_already_loaded();
    void test_common_load_load_when_already_running();
    void test_common_load_load_when_corrupt();
    void test_common_load_fail_due_to_relocation_error();
    void test_common_load_fail_due_to_no_modules_added();
    void test_common_load_add_md_failed();
    void test_common_load_add_md_tls_failed();
    void test_common_load_tls_platform_alloc_failed();
    void test_common_load_stack_platform_alloc_failed();
    void test_common_load_loader_add_failed();
    void test_common_load_resolve_symbol_failed();
    void test_common_load_execute_symbol_failed();

    void test_common_unload_unload_when_already_unloaded();
    void test_common_unload_unload_when_running();
    void test_common_unload_unload_when_corrupt();
    void test_common_unload_execute_symbol_failed();

    void test_common_start_start_when_unloaded();
    void test_common_start_start_when_already_running();
    void test_common_start_start_when_corrupt();
    void test_common_start_start_when_start_vmm_missing();
    void test_common_start_start_vmm_failure();
    void test_common_start_set_affinity_failed();
    void test_common_start_vmcall_failed();

    void test_common_stop_stop_when_unloaded();
    void test_common_stop_stop_when_not_running();
    void test_common_stop_stop_when_alread_stopped();
    void test_common_stop_stop_when_corrupt();
    void test_common_stop_stop_vmm_missing();
    void test_common_stop_stop_vmm_failure();
    void test_common_stop_set_affinity_failed();
    void test_common_stop_vmcall_failed();

    void test_common_dump_invalid_drr();
    void test_common_dump_invalid_vcpuid();
    void test_common_dump_dump_when_unloaded();
    void test_common_dump_dump_when_corrupt();
    void test_common_dump_dump_when_loaded();
    void test_common_dump_get_drr_missing();
    void test_common_dump_get_drr_failure();

    void test_common_vmcall_invalid_args();
    void test_common_vmcall_set_affinity_failure();
    void test_common_vmcall_success();
    void test_common_vmcall_success_event();
    void test_common_vmcall_vmcall_when_unloaded();
    void test_common_vmcall_vmcall_when_corrupt();
    void test_common_vmcall_vmcall_when_loaded();

    void test_helper_common_vmm_status();
    void test_helper_get_file_invalid_index();
    void test_helper_get_file_success();
    void test_helper_symbol_length_null_symbol();
    void test_helper_symbol_length_success();
    void test_helper_resolve_symbol_invalid_name();
    void test_helper_resolve_symbol_invalid_sym();
    void test_helper_resolve_symbol_no_loaded_modules();
    void test_helper_resolve_symbol_missing_symbol();
    void test_helper_execute_symbol_invalid_arg();
    void test_helper_execute_symbol_missing_symbol();
    void test_helper_execute_symbol_sym_failed();
    void test_helper_execute_symbol_sym_success();
    void test_helper_add_md_to_memory_manager_null_module();
    void test_helper_load_elf_file_null_module();

private:

    std::unique_ptr<char[]> m_dummy_add_md_failure;
    std::unique_ptr<char[]> m_dummy_add_md_success;
    std::unique_ptr<char[]> m_dummy_get_drr_failure;
    std::unique_ptr<char[]> m_dummy_get_drr_success;
    std::unique_ptr<char[]> m_dummy_misc;
    std::unique_ptr<char[]> m_dummy_start_vmm_failure;
    std::unique_ptr<char[]> m_dummy_start_vmm_success;
    std::unique_ptr<char[]> m_dummy_stop_vmm_failure;
    std::unique_ptr<char[]> m_dummy_stop_vmm_success;

    uint64_t m_dummy_add_md_failure_length;
    uint64_t m_dummy_add_md_success_length;
    uint64_t m_dummy_get_drr_failure_length;
    uint64_t m_dummy_get_drr_success_length;
    uint64_t m_dummy_misc_length;
    uint64_t m_dummy_start_vmm_failure_length;
    uint64_t m_dummy_start_vmm_success_length;
    uint64_t m_dummy_stop_vmm_failure_length;
    uint64_t m_dummy_stop_vmm_success_length;
};

#endif
