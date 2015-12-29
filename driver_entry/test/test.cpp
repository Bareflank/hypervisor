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

auto c_dummy1_filename = "../../../bfelf_loader/bin/cross/libdummy1.so";
auto c_dummy2_filename = "../../../bfelf_loader/bin/cross/libdummy2.so";
auto c_dummy3_filename = "../../../bfelf_loader/bin/cross/libdummy3.so";

extern "C" int verify_no_mem_leaks(void);

driver_entry_ut::driver_entry_ut()
{
}

bool
driver_entry_ut::init()
{
    auto result = false;

    std::ifstream dummy1_ifs(c_dummy1_filename, std::ifstream::ate);
    std::ifstream dummy2_ifs(c_dummy2_filename, std::ifstream::ate);
    std::ifstream dummy3_ifs(c_dummy3_filename, std::ifstream::ate);

    if (dummy1_ifs.is_open() == false ||
        dummy2_ifs.is_open() == false ||
        dummy3_ifs.is_open() == false)
    {
        std::cout << "unable to open one or more dummy libraries: " << std::endl;
        std::cout << "    - dummy1: " << dummy1_ifs.is_open() << std::endl;
        std::cout << "    - dummy2: " << dummy2_ifs.is_open() << std::endl;
        std::cout << "    - dummy3: " << dummy3_ifs.is_open() << std::endl;
        goto close;
    }

    m_dummy1_length = dummy1_ifs.tellg();
    m_dummy2_length = dummy2_ifs.tellg();
    m_dummy3_length = dummy3_ifs.tellg();

    if (m_dummy1_length == 0 ||
        m_dummy2_length == 0 ||
        m_dummy3_length == 0)
    {
        std::cout << "one or more of the dummy libraries is empty: " << std::endl;
        std::cout << "    - dummy1: " << m_dummy1_length << std::endl;
        std::cout << "    - dummy2: " << m_dummy2_length << std::endl;
        std::cout << "    - dummy3: " << m_dummy3_length << std::endl;
        goto close;
    }

    m_dummy1 = new char[dummy1_ifs.tellg()];
    m_dummy2 = new char[dummy2_ifs.tellg()];
    m_dummy3 = new char[dummy3_ifs.tellg()];

    if (m_dummy1 == NULL ||
        m_dummy2 == NULL ||
        m_dummy3 == NULL)
    {
        std::cout << "unable to allocate space for one or more of the dummy libraries: " << std::endl;
        std::cout << "    - dummy1: " << (void *)m_dummy1 << std::endl;
        std::cout << "    - dummy2: " << (void *)m_dummy2 << std::endl;
        std::cout << "    - dummy3: " << (void *)m_dummy3 << std::endl;
        goto close;
    }

    dummy1_ifs.seekg(0);
    dummy2_ifs.seekg(0);
    dummy3_ifs.seekg(0);

    dummy1_ifs.read(m_dummy1, m_dummy1_length);
    dummy2_ifs.read(m_dummy2, m_dummy2_length);
    dummy3_ifs.read(m_dummy3, m_dummy3_length);

    if (dummy1_ifs.fail() == true ||
        dummy2_ifs.fail() == true ||
        dummy3_ifs.fail() == true)
    {
        std::cout << "unable to load one or more dummy libraries into memory: " << std::endl;
        std::cout << "    - dummy1: " << dummy1_ifs.fail() << std::endl;
        std::cout << "    - dummy2: " << dummy2_ifs.fail() << std::endl;
        std::cout << "    - dummy3: " << dummy3_ifs.fail() << std::endl;
        goto close;
    }

    result = true;

close:

    dummy1_ifs.close();
    dummy2_ifs.close();
    dummy3_ifs.close();

done:

    return result;
}

bool
driver_entry_ut::fini()
{
    if (m_dummy1 != NULL)
        delete[] m_dummy1;

    if (m_dummy2 != NULL)
        delete[] m_dummy2;

    if (m_dummy3 != NULL)
        delete[] m_dummy3;

    return true;
}

bool
driver_entry_ut::list()
{
    this->test_commit_fini_common_stop_failure();
    this->test_commit_fini_common_unload_failure();
    this->test_commit_fini_success();
    this->test_commit_fini_success_multiple_times();

    this->test_common_add_module_invalid_file();
    this->test_common_add_module_invalid_file_size();
    this->test_common_add_module_status_corrupt();
    this->test_common_add_module_status_loaded();
    this->test_common_add_module_status_running();
    this->test_common_add_module_get_next_file_failed();
    this->test_common_add_module_elf_file_init_failed();
    this->test_common_add_module_elf_file_total_exec_failed();
    this->test_common_add_module_add_elf_file_failed();
    this->test_common_add_module_elf_file_load_failed();
    this->test_common_add_module_add_success();

    this->test_common_load_status_corrupt();
    this->test_common_load_status_loaded();
    this->test_common_load_status_running();
    this->test_common_load_loader_init_failed();
    this->test_common_load_loader_add_file_failed();
    this->test_common_load_loader_relocate_failed();
    this->test_common_load_allocate_page_pool_failed();
    this->test_common_load_success();

    this->test_common_unload_status_corrupt();
    this->test_common_unload_status_running();
    this->test_common_unload_free_page_pool_failed();
    this->test_common_unload_remove_elf_files_failed();
    this->test_common_unload_success_with_loaded();
    this->test_common_unload_success_with_unloaded_without_modules();
    this->test_common_unload_success_with_unloaded_with_modules();

    this->test_common_start_status_corrupt();
    this->test_common_start_status_running();
    this->test_common_start_status_unloaded();
    this->test_common_start_init_vmm_failed();
    this->test_common_start_start_vmm_failed();
    this->test_common_start_success();
    this->test_common_start_success_multiple_times();

    this->test_common_stop_status_corrupt();
    this->test_common_stop_status_loaded();
    this->test_common_stop_status_unloaded();
    this->test_common_stop_start_vmm_failed();
    this->test_common_stop_success();
    this->test_common_stop_success_multiple_times();

    this->test_common_dump_status_corrupt();
    this->test_common_dump_status_unloaded();
    this->test_common_dump_platform_alloc_failed();
    this->test_common_dump_resolve_symbol_failed();
    this->test_common_dump_debug_ring_read_failed();
    this->test_common_dump_success();
    this->test_common_dump_success_multiple_times();

    this->test_helper_set_vmm_status();
    this->test_helper_vmm_status();
    this->test_helper_get_file_invalid_index();
    this->test_helper_get_file_success();
    this->test_helper_get_next_file_too_man_files();
    this->test_helper_get_next_file_success();
    this->test_helper_add_elf_file_invalid_size();
    this->test_helper_add_elf_file_();
    this->test_helper_add_elf_file_get_next_file_failed();
    this->test_helper_add_elf_file_platform_alloc_exec_failed();
    this->test_helper_add_elf_file_success();
    this->test_helper_add_elf_file_success_multiple_times();
    this->test_helper_symbol_length_null_symbol();
    this->test_helper_symbol_length_success();
    this->test_helper_resolve_symbol_invalid_name();
    this->test_helper_resolve_symbol_invalid_sym();
    this->test_helper_resolve_symbol_resolve_symbol_failed();
    this->test_helper_resolve_symbol_success();
    this->test_helper_execute_symbol_invalid_arg();
    this->test_helper_execute_symbol_resolve_symbol_failed();
    this->test_helper_execute_symbol_sym_failed();
    this->test_helper_execute_symbol_sym_success();
    // this->test_helper_allocate_page_pool_resolve_symbol_failed();
    // this->test_helper_allocate_page_pool_alloc_page_failed();
    // this->test_helper_allocate_page_pool_add_page_failed();
    // this->test_helper_allocate_page_pool_success();
    // this->test_helper_allocate_page_pool_success_multiple_times();
    // this->test_helper_free_page_pool_resolve_symbol_failed();
    // this->test_helper_free_page_pool_remove_page_failed();
    // this->test_helper_free_page_pool_success();
    // this->test_helper_free_page_pool_success_multiple_times();

    return verify_no_mem_leaks();
}

int
main(int argc, char *argv[])
{
    return RUN_ALL_TESTS(driver_entry_ut);
}
