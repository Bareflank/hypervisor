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

    std::shared_ptr<char> load_elf_file(bfelf_file_t *ef);
    bfelf_test get_test() const;

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
    void test_bfelf_file_init_invalid_header_size();
    void test_bfelf_file_init_invalid_program_header_size();
    void test_bfelf_file_init_invalid_section_header_size();
    void test_bfelf_file_init_invalid_program_header_offset();
    void test_bfelf_file_init_invalid_section_header_offset();
    void test_bfelf_file_init_invalid_program_header_num();
    void test_bfelf_file_init_invalid_section_header_num();
    void test_bfelf_file_init_invalid_section_header_string_table_index();
    void test_bfelf_file_init_invalid_segment_file_size();
    void test_bfelf_file_init_invalid_segment_addresses();
    void test_bfelf_file_init_invalid_segment_alignment();
    void test_bfelf_file_init_invalid_segment_offset();
    void test_bfelf_file_init_invalid_section_offset();
    void test_bfelf_file_init_invalid_section_size();
    void test_bfelf_file_init_invalid_section_name();
    void test_bfelf_file_init_invalid_section_link();
    void test_bfelf_file_init_invalid_segment_address();
    void test_bfelf_file_init_invalid_segment_size();
    void test_bfelf_file_init_invalid_entry();
    void test_bfelf_file_init_invalid_section_type();
    void test_bfelf_file_init_invalid_section_flags();
    void test_bfelf_file_init_invalid_section_address_alignment();
    void test_bfelf_file_init_invalid_section_entry_size();
    void test_bfelf_file_init_missing_dynsym();
    void test_bfelf_file_init_too_many_program_segments();
    void test_bfelf_file_init_too_many_relocation_tables();
    void test_bfelf_file_init_invalid_hash_table_size1();
    void test_bfelf_file_init_invalid_hash_table_size2();
    void test_bfelf_file_init_invalid_hash_table_size3();

    void test_bfelf_file_num_segments_invalid_ef();
    void test_bfelf_file_num_segments_uninitalized();
    void test_bfelf_file_num_segments_success();

    void test_bfelf_file_get_segment_invalid_ef();
    void test_bfelf_file_get_segment_invalid_index();
    void test_bfelf_file_get_segment_invalid_phdr();
    void test_bfelf_file_get_segment_success();

    void test_bfelf_file_resolve_symbol_invalid_loader();
    void test_bfelf_file_resolve_symbol_invalid_name();
    void test_bfelf_file_resolve_symbol_invalid_addr();
    void test_bfelf_file_resolve_symbol_no_relocation();
    void test_bfelf_file_resolve_no_such_symbol();
    void test_bfelf_file_resolve_zero_length_symbol();
    void test_bfelf_file_resolve_invalid_symbol_length();
    void test_bfelf_file_resolve_symbol_length_too_large();
    void test_bfelf_file_resolve_symbol_success();
    void test_bfelf_file_resolve_no_such_symbol_no_hash();
    void test_bfelf_file_resolve_zero_length_symbol_no_hash();
    void test_bfelf_file_resolve_invalid_symbol_length_no_hash();
    void test_bfelf_file_resolve_symbol_length_too_large_no_hash();
    void test_bfelf_file_resolve_symbol_success_no_hash();

    void test_bfelf_loader_add_invalid_loader();
    void test_bfelf_loader_add_invalid_elf_file();
    void test_bfelf_loader_add_too_many_files();

    void test_bfelf_loader_resolve_symbol_invalid_loader();
    void test_bfelf_loader_resolve_symbol_invalid_name();
    void test_bfelf_loader_resolve_symbol_invalid_addr();
    void test_bfelf_loader_resolve_symbol_no_relocation();
    void test_bfelf_loader_resolve_symbol_no_files_added();
    void test_bfelf_loader_resolve_symbol_uninitialized_files();
    void test_bfelf_loader_resolve_no_such_symbol();
    void test_bfelf_loader_resolve_zero_length_symbol();
    void test_bfelf_loader_resolve_invalid_symbol_length();
    void test_bfelf_loader_resolve_symbol_length_too_large();
    void test_bfelf_loader_resolve_symbol_success();
    void test_bfelf_loader_resolve_no_such_symbol_no_hash();
    void test_bfelf_loader_resolve_zero_length_symbol_no_hash();
    void test_bfelf_loader_resolve_invalid_symbol_length_no_hash();
    void test_bfelf_loader_resolve_symbol_length_too_large_no_hash();
    void test_bfelf_loader_resolve_symbol_success_no_hash();
    void test_bfelf_loader_resolve_symbol_real_test();
    void test_bfelf_file_resolve_symbol_resolve_fail();
    void test_bfelf_loader_resolve_symbol_resolve_fail();

    void test_bfelf_loader_relocate_invalid_loader();
    void test_bfelf_loader_relocate_no_files_added();
    void test_bfelf_loader_relocate_uninitialized_files();
    void test_bfelf_loader_relocate_twice();

    void test_bfelf_loader_get_info_invalid_loader();
    void test_bfelf_loader_get_info_invalid_elf_file();
    void test_bfelf_loader_get_info_invalid_info();
    void test_bfelf_loader_get_info_no_relocation();
    void test_bfelf_loader_get_info_expected_misc_resources();
    void test_bfelf_loader_get_info_expected_code_resources();
    void test_bfelf_loader_get_info_get_section_name_failure_ctors();
    void test_bfelf_loader_get_info_check_section_name_failure_ctors();
    void test_bfelf_loader_get_info_get_section_name_failure_dtors();
    void test_bfelf_loader_get_info_check_section_name_failure_dtors();
    void test_bfelf_loader_get_info_get_section_name_failure_init_array();
    void test_bfelf_loader_get_info_check_section_name_failure_init_array();
    void test_bfelf_loader_get_info_get_section_name_failure_fini_array();
    void test_bfelf_loader_get_info_check_section_name_failure_fini_array();
    void test_bfelf_loader_get_info_get_section_name_failure_eh_frame();
    void test_bfelf_loader_get_info_check_section_name_failure_eh_frame();
    void test_bfelf_loader_get_info_all();

    void test_private_bfelf_error();
    void test_private_invalid_symbol_index();
    void test_private_corrupt_symbol_table();
    void test_private_relocate_invalid_index();
    void test_private_relocate_invalid_name();
    void test_private_relocate_invalid_relocation();
    void test_private_get_section_invalid_name();
    void test_private_symbol_table_sections_invalid_dynsym();
    void test_private_symbol_table_sections_invalid_hash();
    void test_private_string_table_sections_invalid();
    void test_private_get_relocation_tables_invalid_type();
    void test_private_get_relocation_tables_invalid_section();
    void test_private_hash();

private:

    std::unique_ptr<char[]> m_dummy_misc;
    std::unique_ptr<char[]> m_dummy_code;
    uint64_t m_dummy_misc_length;
    uint64_t m_dummy_code_length;

    std::shared_ptr<char> m_dummy_misc_exec;
    std::shared_ptr<char> m_dummy_code_exec;
};

#endif
