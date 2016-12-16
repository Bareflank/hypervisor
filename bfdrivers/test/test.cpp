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

#include <fstream>
#include <sys/mman.h>

const auto c_dummy_add_md_failure_filename = "../cross/libdummy_add_md_failure.so";
const auto c_dummy_add_md_success_filename = "../cross/libdummy_add_md_success.so";
const auto c_dummy_get_drr_failure_filename = "../cross/libdummy_get_drr_failure.so";
const auto c_dummy_get_drr_success_filename = "../cross/libdummy_get_drr_success.so";
const auto c_dummy_misc_filename = "../cross/libdummy_misc.so";
const auto c_dummy_start_vmm_failure_filename = "../cross/libdummy_start_vmm_failure.so";
const auto c_dummy_start_vmm_success_filename = "../cross/libdummy_start_vmm_success.so";
const auto c_dummy_stop_vmm_failure_filename = "../cross/libdummy_stop_vmm_failure.so";
const auto c_dummy_stop_vmm_success_filename = "../cross/libdummy_stop_vmm_success.so";

extern "C" int verify_no_mem_leaks(void);

driver_entry_ut::driver_entry_ut() :
    m_dummy_add_md_failure(nullptr),
    m_dummy_add_md_success(nullptr),
    m_dummy_get_drr_failure(nullptr),
    m_dummy_get_drr_success(nullptr),
    m_dummy_misc(nullptr),
    m_dummy_start_vmm_failure(nullptr),
    m_dummy_start_vmm_success(nullptr),
    m_dummy_stop_vmm_failure(nullptr),
    m_dummy_stop_vmm_success(nullptr),
    m_dummy_add_md_failure_length(0),
    m_dummy_add_md_success_length(0),
    m_dummy_get_drr_failure_length(0),
    m_dummy_get_drr_success_length(0),
    m_dummy_misc_length(0),
    m_dummy_start_vmm_failure_length(0),
    m_dummy_start_vmm_success_length(0),
    m_dummy_stop_vmm_failure_length(0),
    m_dummy_stop_vmm_success_length(0)
{
}

bool
driver_entry_ut::init()
{
    std::ifstream dummy_add_md_failure_ifs(c_dummy_add_md_failure_filename, std::ifstream::ate);
    std::ifstream dummy_add_md_success_ifs(c_dummy_add_md_success_filename, std::ifstream::ate);
    std::ifstream dummy_get_drr_failure_ifs(c_dummy_get_drr_failure_filename, std::ifstream::ate);
    std::ifstream dummy_get_drr_success_ifs(c_dummy_get_drr_success_filename, std::ifstream::ate);
    std::ifstream dummy_misc_ifs(c_dummy_misc_filename, std::ifstream::ate);
    std::ifstream dummy_start_vmm_failure_ifs(c_dummy_start_vmm_failure_filename, std::ifstream::ate);
    std::ifstream dummy_start_vmm_success_ifs(c_dummy_start_vmm_success_filename, std::ifstream::ate);
    std::ifstream dummy_stop_vmm_failure_ifs(c_dummy_stop_vmm_failure_filename, std::ifstream::ate);
    std::ifstream dummy_stop_vmm_success_ifs(c_dummy_stop_vmm_success_filename, std::ifstream::ate);

    m_dummy_add_md_failure_length = static_cast<uint64_t>(dummy_add_md_failure_ifs.tellg());
    m_dummy_add_md_success_length = static_cast<uint64_t>(dummy_add_md_success_ifs.tellg());
    m_dummy_get_drr_failure_length = static_cast<uint64_t>(dummy_get_drr_failure_ifs.tellg());
    m_dummy_get_drr_success_length = static_cast<uint64_t>(dummy_get_drr_success_ifs.tellg());
    m_dummy_misc_length = static_cast<uint64_t>(dummy_misc_ifs.tellg());
    m_dummy_start_vmm_failure_length = static_cast<uint64_t>(dummy_start_vmm_failure_ifs.tellg());
    m_dummy_start_vmm_success_length = static_cast<uint64_t>(dummy_start_vmm_success_ifs.tellg());
    m_dummy_stop_vmm_failure_length = static_cast<uint64_t>(dummy_stop_vmm_failure_ifs.tellg());
    m_dummy_stop_vmm_success_length = static_cast<uint64_t>(dummy_stop_vmm_success_ifs.tellg());

    m_dummy_add_md_failure = std::make_unique<char[]>(m_dummy_add_md_failure_length);
    m_dummy_add_md_success = std::make_unique<char[]>(m_dummy_add_md_success_length);
    m_dummy_get_drr_failure = std::make_unique<char[]>(m_dummy_get_drr_failure_length);
    m_dummy_get_drr_success = std::make_unique<char[]>(m_dummy_get_drr_success_length);
    m_dummy_misc = std::make_unique<char[]>(m_dummy_misc_length);
    m_dummy_start_vmm_failure = std::make_unique<char[]>(m_dummy_start_vmm_failure_length);
    m_dummy_start_vmm_success = std::make_unique<char[]>(m_dummy_start_vmm_success_length);
    m_dummy_stop_vmm_failure = std::make_unique<char[]>(m_dummy_stop_vmm_failure_length);
    m_dummy_stop_vmm_success = std::make_unique<char[]>(m_dummy_stop_vmm_success_length);

    dummy_add_md_failure_ifs.seekg(0);
    dummy_add_md_success_ifs.seekg(0);
    dummy_get_drr_failure_ifs.seekg(0);
    dummy_get_drr_success_ifs.seekg(0);
    dummy_misc_ifs.seekg(0);
    dummy_start_vmm_failure_ifs.seekg(0);
    dummy_start_vmm_success_ifs.seekg(0);
    dummy_stop_vmm_failure_ifs.seekg(0);
    dummy_stop_vmm_success_ifs.seekg(0);

    dummy_add_md_failure_ifs.read(m_dummy_add_md_failure.get(), static_cast<int64_t>(m_dummy_add_md_failure_length));
    dummy_add_md_success_ifs.read(m_dummy_add_md_success.get(), static_cast<int64_t>(m_dummy_add_md_success_length));
    dummy_get_drr_failure_ifs.read(m_dummy_get_drr_failure.get(), static_cast<int64_t>(m_dummy_get_drr_failure_length));
    dummy_get_drr_success_ifs.read(m_dummy_get_drr_success.get(), static_cast<int64_t>(m_dummy_get_drr_success_length));
    dummy_misc_ifs.read(m_dummy_misc.get(), static_cast<int64_t>(m_dummy_misc_length));
    dummy_start_vmm_failure_ifs.read(m_dummy_start_vmm_failure.get(), static_cast<int64_t>(m_dummy_start_vmm_failure_length));
    dummy_start_vmm_success_ifs.read(m_dummy_start_vmm_success.get(), static_cast<int64_t>(m_dummy_start_vmm_success_length));
    dummy_stop_vmm_failure_ifs.read(m_dummy_stop_vmm_failure.get(), static_cast<int64_t>(m_dummy_stop_vmm_failure_length));
    dummy_stop_vmm_success_ifs.read(m_dummy_stop_vmm_success.get(), static_cast<int64_t>(m_dummy_stop_vmm_success_length));

    return true;
}

bool
driver_entry_ut::fini()
{
    return true;
}

bool
driver_entry_ut::list()
{
    this->test_common_init();

    this->test_common_fini_unloaded();
    this->test_common_fini_successful_start();
    this->test_common_fini_successful_load();
    this->test_common_fini_successful_add_module();
    this->test_common_fini_corrupted();
    this->test_common_fini_failed_load();
    this->test_common_fini_failed_start();
    this->test_common_fini_unload_failed();
    this->test_common_fini_stop_failed();
    this->test_common_fini_reset_failed();

    this->test_common_add_module_invalid_file();
    this->test_common_add_module_invalid_file_size();
    this->test_common_add_module_garbage_module();
    this->test_common_add_module_add_when_already_loaded();
    this->test_common_add_module_add_when_already_running();
    this->test_common_add_module_add_when_corrupt();
    this->test_common_add_module_add_too_many();
    this->test_common_add_module_get_elf_file_size_fails();
    this->test_common_add_module_platform_alloc_fails();
    this->test_common_add_module_load_elf_fails();

    this->test_common_load_successful_load();
    this->test_common_load_load_when_already_loaded();
    this->test_common_load_load_when_already_running();
    this->test_common_load_load_when_corrupt();
    this->test_common_load_fail_due_to_relocation_error();
    this->test_common_load_fail_due_to_no_modules_added();
    this->test_common_load_add_md_failed();
    this->test_common_load_add_md_tls_failed();
    this->test_common_load_tls_platform_alloc_failed();
    this->test_common_load_stack_platform_alloc_failed();
    this->test_common_load_loader_add_failed();
    this->test_common_load_resolve_symbol_failed();
    this->test_common_load_loader_get_info_failed();
    this->test_common_load_execute_symbol_failed();

    this->test_common_unload_unload_when_already_unloaded();
    this->test_common_unload_unload_when_running();
    this->test_common_unload_unload_when_corrupt();
    this->test_common_unload_loader_get_info_failed();
    this->test_common_unload_execute_symbol_failed();

    this->test_common_start_start_when_unloaded();
    this->test_common_start_start_when_already_running();
    this->test_common_start_start_when_corrupt();
    this->test_common_start_start_when_start_vmm_missing();
    this->test_common_start_start_vmm_failure();
    this->test_common_start_set_affinity_failed();

    this->test_common_stop_stop_when_unloaded();
    this->test_common_stop_stop_when_not_running();
    this->test_common_stop_stop_when_alread_stopped();
    this->test_common_stop_stop_when_corrupt();
    this->test_common_stop_stop_vmm_missing();
    this->test_common_stop_stop_vmm_failure();
    this->test_common_stop_set_affinity_failed();

    this->test_common_dump_invalid_drr();
    this->test_common_dump_invalid_vcpuid();
    this->test_common_dump_dump_when_unloaded();
    this->test_common_dump_dump_when_corrupt();
    this->test_common_dump_dump_when_loaded();
    this->test_common_dump_get_drr_missing();
    this->test_common_dump_get_drr_failure();

    this->test_common_vmcall_invalid_args();
    this->test_common_vmcall_set_affinity_failure();
    this->test_common_vmcall_success();
    this->test_common_vmcall_success_event();
    this->test_common_vmcall_vmcall_when_unloaded();
    this->test_common_vmcall_vmcall_when_corrupt();
    this->test_common_vmcall_vmcall_when_loaded();

    this->test_helper_common_vmm_status();
    this->test_helper_get_file_invalid_index();
    this->test_helper_get_file_success();
    this->test_helper_symbol_length_null_symbol();
    this->test_helper_symbol_length_success();
    this->test_helper_resolve_symbol_invalid_name();
    this->test_helper_resolve_symbol_invalid_sym();
    this->test_helper_resolve_symbol_no_loaded_modules();
    this->test_helper_resolve_symbol_missing_symbol();
    this->test_helper_execute_symbol_invalid_arg();
    this->test_helper_execute_symbol_missing_symbol();
    this->test_helper_execute_symbol_sym_failed();
    this->test_helper_execute_symbol_sym_success();
    this->test_helper_add_md_to_memory_manager_null_module();
    this->test_helper_get_elf_file_size_null_module();
    this->test_helper_get_elf_file_size_get_segment_fails();
    this->test_helper_load_elf_file_null_module();
    this->test_helper_load_elf_file_get_segment_fails();

    return verify_no_mem_leaks() != 0;
}

int
main(int argc, char *argv[])
{
    return RUN_ALL_TESTS(driver_entry_ut);
}
