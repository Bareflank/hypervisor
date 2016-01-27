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
#include <bfelf_loader.h>

class bfelf_loader_ut : public unittest
{
public:

    bfelf_loader_ut();
    ~bfelf_loader_ut() {}

protected:

    bool init() override;
    bool fini() override;
    bool list() override;

private:

    void test_bfelf_file_init();
    void test_bfelf_file_size();
    void test_bfelf_file_load();
    void test_bfelf_loader_init();
    void test_bfelf_loader_add();
    void test_bfelf_loader_relocate();
    void test_bfelf_section_header();
    void test_bfelf_string_table_entry();
    void test_bfelf_section_name_string();
    void test_bfelf_symbol_by_index();
    void test_bfelf_symbol_by_name();
    void test_bfelf_symbol_by_name_global();
    void test_bfelf_resolve_symbol();
    void test_bfelf_relocate_symbol();
    void test_bfelf_relocate_symbol_addend();
    void test_bfelf_relocate_symbols();
    void test_bfelf_ctor_num();
    void test_bfelf_dtor_num();
    void test_bfelf_resolve_ctor();
    void test_bfelf_resolve_dtor();
    void test_bfelf_init_num();
    void test_bfelf_fini_num();
    void test_bfelf_resolve_init();
    void test_bfelf_resolve_fini();
    void test_bfelf_program_header();
    void test_bfelf_load_segments();
    void test_bfelf_load_segment();

    void test_bfelf_file_print_header();
    void test_bfelf_print_section_header_table();
    void test_bfelf_print_program_header_table();
    void test_bfelf_print_sym_table();
    void test_bfelf_print_relocations();

    void test_resolve();

private:

    char *m_dummy_misc;
    char *m_dummy_code;
    int32_t m_dummy_misc_length;
    int32_t m_dummy_code_length;

    char *m_dummy_misc_exec;
    char *m_dummy_code_exec;
    int32_t m_dummy_misc_esize;
    int32_t m_dummy_code_esize;

    bfelf_file_t m_dummy_misc_ef;
    bfelf_file_t m_dummy_code_ef;

    char *m_test_exec;
    int32_t m_test_esize;
    bfelf_file_t m_test_elf;

    bfelf_loader_t m_loader;
    bfelf_loader_t m_test_loader;
};

#endif
