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

#include <memory>

#include <unittest.h>
#include <test_elf.h>

class bfelf_loader_ut : public unittest
{
public:

    bfelf_loader_ut();
    ~bfelf_loader_ut() override = default;

protected:

    bool init() override;
    bool fini() override;
    bool list() override;

private:

    std::pair<std::unique_ptr<char[]>, uint64_t> get_elf_exec(bfelf_file_t *ef);
    std::pair<std::unique_ptr<char[]>, uint64_t> get_test();

    void test_bfelf_file_init_success();
    void test_bfelf_file_init_invalid_file_arg();
    void test_bfelf_file_init_invalid_file_size_arg();
    void test_bfelf_file_init_invalid_elf_file();
    void test_bfelf_file_init_invalid_magic_0();
    void test_bfelf_file_init_invalid_magic_1();
    void test_bfelf_file_init_invalid_magic_2();
    void test_bfelf_file_init_invalid_magic_3();
    void test_bfelf_file_init_invalid_class();
    void test_bfelf_file_init_invalid_data();
    void test_bfelf_file_init_invalid_ident_version();
    void test_bfelf_file_init_invalid_osabi();
    void test_bfelf_file_init_invalid_abiversion();
    void test_bfelf_file_init_invalid_type();
    void test_bfelf_file_init_invalid_machine();
    void test_bfelf_file_init_invalid_version();
    void test_bfelf_file_init_invalid_flags();

    void test_bfelf_file_num_load_instrs_invalid_ef();
    void test_bfelf_file_num_load_instrs_uninitalized();
    void test_bfelf_file_num_load_instrs_success();

    void test_bfelf_file_get_load_instr_invalid_ef();
    void test_bfelf_file_get_load_instr_invalid_index();
    void test_bfelf_file_get_load_instr_invalid_instr();
    void test_bfelf_file_get_load_instr_success();

    void test_bfelf_file_resolve_symbol_invalid_loader();
    void test_bfelf_file_resolve_symbol_invalid_name();
    void test_bfelf_file_resolve_symbol_invalid_addr();
    void test_bfelf_file_resolve_no_such_symbol_no_relocation();
    void test_bfelf_file_resolve_no_such_symbol();
    void test_bfelf_file_resolve_symbol_success();
    void test_bfelf_file_resolve_no_such_symbol_no_hash();
    void test_bfelf_file_resolve_symbol_success_no_hash();

    void test_bfelf_loader_add_invalid_loader();
    void test_bfelf_loader_add_invalid_elf_file();
    void test_bfelf_loader_add_invalid_addr();
    void test_bfelf_loader_add_too_many_files();
    void test_bfelf_loader_add_fake();

    void test_bfelf_loader_relocate_invalid_loader();
    void test_bfelf_loader_relocate_no_files_added();
    void test_bfelf_loader_relocate_uninitialized_files();
    void test_bfelf_loader_relocate_twice();

    void test_bfelf_file_get_section_info_invalid_elf_file();
    void test_bfelf_file_get_section_info_invalid_info();
    void test_bfelf_file_get_section_info_expected_misc_resources();
    void test_bfelf_file_get_section_info_expected_code_resources();
    void test_bfelf_file_get_section_info_init_fini();

    void test_bfelf_loader_resolve_symbol_invalid_loader();
    void test_bfelf_loader_resolve_symbol_invalid_name();
    void test_bfelf_loader_resolve_symbol_invalid_addr();
    void test_bfelf_loader_resolve_symbol_no_files_added();
    void test_bfelf_loader_resolve_symbol_uninitialized_files();
    void test_bfelf_loader_resolve_no_such_symbol();
    void test_bfelf_loader_resolve_symbol_success();
    void test_bfelf_loader_resolve_no_such_symbol_no_hash();
    void test_bfelf_loader_resolve_symbol_success_no_hash();
    void test_bfelf_loader_resolve_symbol_real_test();

    void test_bfelf_file_get_entry_invalid_ef();
    void test_bfelf_file_get_entry_invalid_addr();
    void test_bfelf_file_get_entry_success();

    void test_bfelf_file_get_stack_perm_invalid_ef();
    void test_bfelf_file_get_stack_perm_invalid_addr();
    void test_bfelf_file_get_stack_perm_success();

    void test_bfelf_file_get_relro_invalid_ef();
    void test_bfelf_file_get_relro_invalid_addr();
    void test_bfelf_file_get_relro_invalid_size();
    void test_bfelf_file_get_relro_success();

    void test_bfelf_file_get_num_needed_invalid_ef();
    void test_bfelf_file_get_num_needed_success();

    void test_bfelf_file_get_needed_invalid_ef();
    void test_bfelf_file_get_needed_invalid_index();
    void test_bfelf_file_get_needed_invalid_size();
    void test_bfelf_file_get_needed_success();

    void test_bfelf_file_get_total_size_invalid_ef();
    void test_bfelf_file_get_total_size_success();

    void test_bfelf_file_get_pic_pie_invalid_ef();
    void test_bfelf_file_get_pic_pie_success();

    void test_private_hash();
    void test_private_relocate_invalid_relocation();
    void test_private_no_loadable_segments();

private:

    std::unique_ptr<char[]> m_dummy_misc;
    std::unique_ptr<char[]> m_dummy_code;
    uint64_t m_dummy_misc_length;
    uint64_t m_dummy_code_length;

    std::shared_ptr<char> m_dummy_misc_exec;
    std::shared_ptr<char> m_dummy_code_exec;
};

#endif
