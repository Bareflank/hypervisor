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
#include <elf_loader.h>

class elf_loader_ut : public unittest
{
public:

    elf_loader_ut();
    ~elf_loader_ut() {}

protected:

    bool init() override;
    bool fini() override;
    bool list() override;

private:

    void test_elf_file_init();
    void test_elf_file_size();
    void test_elf_file_load();
    void test_elf_loader_init();
    void test_elf_loader_add();
    void test_elf_loader_relocate();
    void test_elf_section_header();
    void test_elf_string_table_entry();
    void test_elf_section_name_string();
    void test_elf_symbol_by_index();
    void test_elf_symbol_by_name();
    void test_elf_symbol_by_name_global();
    void test_elf_resolve_symbol();
    void test_elf_relocate_symbol();
    void test_elf_relocate_symbol_addend();
    void test_elf_relocate_symbols();
    void test_elf_program_header();
    void test_elf_load_segments();
    void test_elf_load_segment();

    void test_elf_file_print_header();
    void test_elf_print_section_header_table();
    void test_elf_print_program_header_table();
    void test_elf_print_sym_table();
    void test_elf_print_relocations();

    void test_resolve();

private:

    char *m_dummy1;
    char *m_dummy2;
    char *m_dummy3;
    int32_t m_dummy1_length;
    int32_t m_dummy2_length;
    int32_t m_dummy3_length;

    char *m_dummy1_exec;
    char *m_dummy2_exec;
    char *m_dummy3_exec;
    int32_t m_dummy1_esize;
    int32_t m_dummy2_esize;
    int32_t m_dummy3_esize;

    elf_file_t m_dummy1_ef;
    elf_file_t m_dummy2_ef;
    elf_file_t m_dummy3_ef;

    char *m_test_exec;
    int32_t m_test_esize;
    elf_file_t m_test_elf;

    elf_loader_t m_loader;
    elf_loader_t m_test_loader;
};

#endif
