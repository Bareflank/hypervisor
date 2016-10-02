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

void
bfelf_loader_ut::test_bfelf_file_init_success()
{
    bfelf_file_t ef;
    auto test = get_test();

    auto ret = bfelf_file_init(reinterpret_cast<char *>(&test), sizeof(test), &ef);
    this->expect_true(ret == BFELF_SUCCESS);
}

void
bfelf_loader_ut::test_bfelf_file_init_invalid_file_arg()
{
    bfelf_file_t ef;
    auto test = get_test();

    auto ret = bfelf_file_init(nullptr, sizeof(test), &ef);
    this->expect_true(ret == BFELF_ERROR_INVALID_ARG);
}

void
bfelf_loader_ut::test_bfelf_file_init_invalid_file_size_arg()
{
    bfelf_file_t ef;
    auto test = get_test();

    auto ret = bfelf_file_init(reinterpret_cast<char *>(&test), 0, &ef);
    this->expect_true(ret == BFELF_ERROR_INVALID_ARG);
}

void
bfelf_loader_ut::test_bfelf_file_init_invalid_elf_file()
{
    auto test = get_test();

    auto ret = bfelf_file_init(reinterpret_cast<char *>(&test), sizeof(test), nullptr);
    this->expect_true(ret == BFELF_ERROR_INVALID_ARG);
}

void
bfelf_loader_ut::test_bfelf_file_init_invalid_magic_0()
{
    bfelf_file_t ef;
    auto test = get_test();

    test.header.e_ident[bfei_mag0] = 0;

    auto ret = bfelf_file_init(reinterpret_cast<char *>(&test), sizeof(test), &ef);
    this->expect_true(ret == BFELF_ERROR_INVALID_SIGNATURE);
}

void
bfelf_loader_ut::test_bfelf_file_init_invalid_magic_1()
{
    bfelf_file_t ef;
    auto test = get_test();

    test.header.e_ident[bfei_mag1] = 0;

    auto ret = bfelf_file_init(reinterpret_cast<char *>(&test), sizeof(test), &ef);
    this->expect_true(ret == BFELF_ERROR_INVALID_SIGNATURE);
}

void
bfelf_loader_ut::test_bfelf_file_init_invalid_magic_2()
{
    bfelf_file_t ef;
    auto test = get_test();

    test.header.e_ident[bfei_mag2] = 0;

    auto ret = bfelf_file_init(reinterpret_cast<char *>(&test), sizeof(test), &ef);
    this->expect_true(ret == BFELF_ERROR_INVALID_SIGNATURE);
}

void
bfelf_loader_ut::test_bfelf_file_init_invalid_magic_3()
{
    bfelf_file_t ef;
    auto test = get_test();

    test.header.e_ident[bfei_mag3] = 0;

    auto ret = bfelf_file_init(reinterpret_cast<char *>(&test), sizeof(test), &ef);
    this->expect_true(ret == BFELF_ERROR_INVALID_SIGNATURE);
}

void
bfelf_loader_ut::test_bfelf_file_init_invalid_class()
{
    bfelf_file_t ef;
    auto test = get_test();

    test.header.e_ident[bfei_class] = 0x4;

    auto ret = bfelf_file_init(reinterpret_cast<char *>(&test), sizeof(test), &ef);
    this->expect_true(ret == BFELF_ERROR_UNSUPPORTED_FILE);
}

void
bfelf_loader_ut::test_bfelf_file_init_invalid_data()
{
    bfelf_file_t ef;
    auto test = get_test();

    test.header.e_ident[bfei_data] = 0x8;

    auto ret = bfelf_file_init(reinterpret_cast<char *>(&test), sizeof(test), &ef);
    this->expect_true(ret == BFELF_ERROR_UNSUPPORTED_FILE);
}

void
bfelf_loader_ut::test_bfelf_file_init_invalid_ident_version()
{
    bfelf_file_t ef;
    auto test = get_test();

    test.header.e_ident[bfei_version] = 0x15;

    auto ret = bfelf_file_init(reinterpret_cast<char *>(&test), sizeof(test), &ef);
    this->expect_true(ret == BFELF_ERROR_UNSUPPORTED_FILE);
}

void
bfelf_loader_ut::test_bfelf_file_init_invalid_osabi()
{
    // bfelf_file_t ef;
    // auto test = get_test();

    // test.header.e_ident[bfei_osabi] = 0x16;

    // auto ret = bfelf_file_init(reinterpret_cast<char *>(&test), sizeof(test), &ef);
    // this->expect_true(ret == BFELF_ERROR_UNSUPPORTED_FILE);
}

void
bfelf_loader_ut::test_bfelf_file_init_invalid_abiversion()
{
    bfelf_file_t ef;
    auto test = get_test();

    test.header.e_ident[bfei_abiversion] = 0x23;

    auto ret = bfelf_file_init(reinterpret_cast<char *>(&test), sizeof(test), &ef);
    this->expect_true(ret == BFELF_ERROR_UNSUPPORTED_FILE);
}

void
bfelf_loader_ut::test_bfelf_file_init_invalid_type()
{
    bfelf_file_t ef;
    auto test = get_test();

    test.header.e_type = 0xDEAD;

    auto ret = bfelf_file_init(reinterpret_cast<char *>(&test), sizeof(test), &ef);
    this->expect_true(ret == BFELF_ERROR_UNSUPPORTED_FILE);
}

void
bfelf_loader_ut::test_bfelf_file_init_invalid_machine()
{
    bfelf_file_t ef;
    auto test = get_test();

    test.header.e_machine = 0xDEAD;

    auto ret = bfelf_file_init(reinterpret_cast<char *>(&test), sizeof(test), &ef);
    this->expect_true(ret == BFELF_ERROR_UNSUPPORTED_FILE);
}

void
bfelf_loader_ut::test_bfelf_file_init_invalid_version()
{
    bfelf_file_t ef;
    auto test = get_test();

    test.header.e_version = 0xDEAD;

    auto ret = bfelf_file_init(reinterpret_cast<char *>(&test), sizeof(test), &ef);
    this->expect_true(ret == BFELF_ERROR_UNSUPPORTED_FILE);
}

void
bfelf_loader_ut::test_bfelf_file_init_invalid_flags()
{
    bfelf_file_t ef;
    auto test = get_test();

    test.header.e_flags = 0xDEAD;

    auto ret = bfelf_file_init(reinterpret_cast<char *>(&test), sizeof(test), &ef);
    this->expect_true(ret == BFELF_ERROR_UNSUPPORTED_FILE);
}

void
bfelf_loader_ut::test_bfelf_file_init_invalid_header_size()
{
    bfelf_file_t ef;
    auto test = get_test();

    test.header.e_ehsize = 0xDEAD;

    auto ret = bfelf_file_init(reinterpret_cast<char *>(&test), sizeof(test), &ef);
    this->expect_true(ret == BFELF_ERROR_INVALID_FILE);
}

void
bfelf_loader_ut::test_bfelf_file_init_invalid_program_header_size()
{
    bfelf_file_t ef;
    auto test = get_test();

    test.header.e_phentsize = 0xDEAD;

    auto ret = bfelf_file_init(reinterpret_cast<char *>(&test), sizeof(test), &ef);
    this->expect_true(ret == BFELF_ERROR_INVALID_FILE);
}

void
bfelf_loader_ut::test_bfelf_file_init_invalid_section_header_size()
{
    bfelf_file_t ef;
    auto test = get_test();

    test.header.e_shentsize = 0xDEAD;

    auto ret = bfelf_file_init(reinterpret_cast<char *>(&test), sizeof(test), &ef);
    this->expect_true(ret == BFELF_ERROR_INVALID_FILE);
}

void
bfelf_loader_ut::test_bfelf_file_init_invalid_program_header_offset()
{
    bfelf_file_t ef;
    auto test = get_test();

    test.header.e_phoff = 0xDEADBEEF;

    auto ret = bfelf_file_init(reinterpret_cast<char *>(&test), sizeof(test), &ef);
    this->expect_true(ret == BFELF_ERROR_INVALID_FILE);
}

void
bfelf_loader_ut::test_bfelf_file_init_invalid_section_header_offset()
{
    bfelf_file_t ef;
    auto test = get_test();

    test.header.e_shoff = 0xDEADBEEF;

    auto ret = bfelf_file_init(reinterpret_cast<char *>(&test), sizeof(test), &ef);
    this->expect_true(ret == BFELF_ERROR_INVALID_FILE);
}

void
bfelf_loader_ut::test_bfelf_file_init_invalid_program_header_num()
{
    bfelf_file_t ef;
    auto test = get_test();

    test.header.e_phnum = 0xDEAD;

    auto ret = bfelf_file_init(reinterpret_cast<char *>(&test), sizeof(test), &ef);
    this->expect_true(ret == BFELF_ERROR_INVALID_FILE);
}

void
bfelf_loader_ut::test_bfelf_file_init_invalid_section_header_num()
{
    bfelf_file_t ef;
    auto test = get_test();

    test.header.e_shnum = 0xDEAD;

    auto ret = bfelf_file_init(reinterpret_cast<char *>(&test), sizeof(test), &ef);
    this->expect_true(ret == BFELF_ERROR_INVALID_FILE);
}

void
bfelf_loader_ut::test_bfelf_file_init_invalid_section_header_string_table_index()
{
    bfelf_file_t ef;
    auto test = get_test();

    test.header.e_shstrndx = 0xDEAD;

    auto ret = bfelf_file_init(reinterpret_cast<char *>(&test), sizeof(test), &ef);
    this->expect_true(ret == BFELF_ERROR_INVALID_FILE);
}

void
bfelf_loader_ut::test_bfelf_file_init_invalid_segment_file_size()
{
    bfelf_file_t ef;
    auto test = get_test();

    test.phdrtab.re_segment1.p_filesz = 0xDEADBEEF;

    auto ret = bfelf_file_init(reinterpret_cast<char *>(&test), sizeof(test), &ef);
    this->expect_true(ret == BFELF_ERROR_INVALID_SEGMENT);
}

void
bfelf_loader_ut::test_bfelf_file_init_invalid_segment_addresses()
{
    bfelf_file_t ef;
    auto test = get_test();

    test.phdrtab.re_segment1.p_vaddr = 0xDEADBEEF;

    auto ret = bfelf_file_init(reinterpret_cast<char *>(&test), sizeof(test), &ef);
    this->expect_true(ret == BFELF_ERROR_INVALID_SEGMENT);
}

void
bfelf_loader_ut::test_bfelf_file_init_invalid_segment_alignment()
{
    bfelf_file_t ef;
    auto test = get_test();

    test.phdrtab.re_segment1.p_align = 0xDEADBEEF;

    auto ret = bfelf_file_init(reinterpret_cast<char *>(&test), sizeof(test), &ef);
    this->expect_true(ret == BFELF_ERROR_INVALID_SEGMENT);
}

void
bfelf_loader_ut::test_bfelf_file_init_invalid_segment_offset()
{
    bfelf_file_t ef;
    auto test = get_test();

    test.phdrtab.re_segment1.p_offset = 0xDEADBEEF;

    auto ret = bfelf_file_init(reinterpret_cast<char *>(&test), sizeof(test), &ef);
    this->expect_true(ret == BFELF_ERROR_INVALID_SEGMENT);
}

void
bfelf_loader_ut::test_bfelf_file_init_invalid_section_offset()
{
    bfelf_file_t ef;
    auto test = get_test();

    test.shdrtab.hashtab.sh_offset = 0xDEADBEEF;

    auto ret = bfelf_file_init(reinterpret_cast<char *>(&test), sizeof(test), &ef);
    this->expect_true(ret == BFELF_ERROR_INVALID_SECTION);
}

void
bfelf_loader_ut::test_bfelf_file_init_invalid_section_size()
{
    bfelf_file_t ef;
    auto test = get_test();

    test.shdrtab.hashtab.sh_size = 0xDEADBEEF;

    auto ret = bfelf_file_init(reinterpret_cast<char *>(&test), sizeof(test), &ef);
    this->expect_true(ret == BFELF_ERROR_INVALID_SECTION);
}

void
bfelf_loader_ut::test_bfelf_file_init_invalid_section_name()
{
    bfelf_file_t ef;
    auto test = get_test();

    test.shdrtab.hashtab.sh_name = 0xDEAD;

    auto ret = bfelf_file_init(reinterpret_cast<char *>(&test), sizeof(test), &ef);
    this->expect_true(ret == BFELF_ERROR_INVALID_SECTION);
}

void
bfelf_loader_ut::test_bfelf_file_init_invalid_section_link()
{
    bfelf_file_t ef;
    auto test = get_test();

    test.shdrtab.hashtab.sh_link = 0xDEAD;

    auto ret = bfelf_file_init(reinterpret_cast<char *>(&test), sizeof(test), &ef);
    this->expect_true(ret == BFELF_ERROR_INVALID_SECTION);
}

void
bfelf_loader_ut::test_bfelf_file_init_invalid_segment_address()
{
    bfelf_file_t ef;
    auto test = get_test();

    test.phdrtab.re_segment1.p_paddr = 0xDEAD;
    test.phdrtab.re_segment1.p_vaddr = 0xDEAD;

    auto ret = bfelf_file_init(reinterpret_cast<char *>(&test), sizeof(test), &ef);
    this->expect_true(ret == BFELF_ERROR_INVALID_SECTION);
}

void
bfelf_loader_ut::test_bfelf_file_init_invalid_segment_size()
{
    bfelf_file_t ef;
    auto test = get_test();

    test.phdrtab.re_segment1.p_memsz = 0x275;
    test.phdrtab.re_segment1.p_filesz = 0x275;

    auto ret = bfelf_file_init(reinterpret_cast<char *>(&test), sizeof(test), &ef);
    this->expect_true(ret == BFELF_ERROR_INVALID_SECTION);
}

void
bfelf_loader_ut::test_bfelf_file_init_invalid_entry()
{
    bfelf_file_t ef;
    auto test = get_test();

    test.header.e_entry = 0xDEADBEEF;

    auto ret = bfelf_file_init(reinterpret_cast<char *>(&test), sizeof(test), &ef);
    this->expect_true(ret == BFELF_ERROR_INVALID_FILE);
}

void
bfelf_loader_ut::test_bfelf_file_init_invalid_section_type()
{
    bfelf_file_t ef;
    auto test = get_test();

    test.shdrtab.shstrtab.sh_type = 0xDEAD;

    auto ret = bfelf_file_init(reinterpret_cast<char *>(&test), sizeof(test), &ef);
    this->expect_true(ret == BFELF_ERROR_INVALID_SECTION);
}

void
bfelf_loader_ut::test_bfelf_file_init_invalid_section_flags()
{
    bfelf_file_t ef;
    auto test = get_test();

    test.shdrtab.shstrtab.sh_flags = 0xDEAD;

    auto ret = bfelf_file_init(reinterpret_cast<char *>(&test), sizeof(test), &ef);
    this->expect_true(ret == BFELF_ERROR_INVALID_SECTION);
}

void
bfelf_loader_ut::test_bfelf_file_init_invalid_section_address_alignment()
{
    bfelf_file_t ef;
    auto test = get_test();

    test.shdrtab.shstrtab.sh_addralign = 0xDEAD;

    auto ret = bfelf_file_init(reinterpret_cast<char *>(&test), sizeof(test), &ef);
    this->expect_true(ret == BFELF_ERROR_INVALID_SECTION);
}

void
bfelf_loader_ut::test_bfelf_file_init_invalid_section_entry_size()
{
    bfelf_file_t ef;
    auto test = get_test();

    test.shdrtab.shstrtab.sh_entsize = 0xDEAD;

    auto ret = bfelf_file_init(reinterpret_cast<char *>(&test), sizeof(test), &ef);
    this->expect_true(ret == BFELF_ERROR_INVALID_SECTION);
}

void
bfelf_loader_ut::test_bfelf_file_init_missing_dynsym()
{
    bfelf_file_t ef;
    auto test = get_test();

    test.shdrtab.dynsym.sh_type = 0xDEAD;

    auto ret = bfelf_file_init(reinterpret_cast<char *>(&test), sizeof(test), &ef);
    this->expect_true(ret == BFELF_ERROR_INVALID_FILE);
}

void
bfelf_loader_ut::test_bfelf_file_init_too_many_program_segments()
{
    bfelf_file_t ef;
    auto test = get_test();

    test.phdrtab.too_many.p_type = bfpt_load;

    auto ret = bfelf_file_init(reinterpret_cast<char *>(&test), sizeof(test), &ef);
    this->expect_true(ret == BFELF_ERROR_LOADER_FULL);
}

void
bfelf_loader_ut::test_bfelf_file_init_too_many_relocation_tables()
{
    bfelf_file_t ef;
    auto test = get_test();

    test.shdrtab.too_many.sh_type = bfsht_rela;

    auto ret = bfelf_file_init(reinterpret_cast<char *>(&test), sizeof(test), &ef);
    this->expect_true(ret == BFELF_ERROR_LOADER_FULL);
}

void
bfelf_loader_ut::test_bfelf_file_init_invalid_hash_table_size1()
{
    bfelf_file_t ef;
    auto test = get_test();

    test.shdrtab.hashtab.sh_size = 1;

    auto ret = bfelf_file_init(reinterpret_cast<char *>(&test), sizeof(test), &ef);
    this->expect_true(ret == BFELF_ERROR_INVALID_SECTION);
}

void
bfelf_loader_ut::test_bfelf_file_init_invalid_hash_table_size2()
{
    bfelf_file_t ef;
    auto test = get_test();

    test.hashtab.nbucket = 0xDEAD;

    auto ret = bfelf_file_init(reinterpret_cast<char *>(&test), sizeof(test), &ef);
    this->expect_true(ret == BFELF_ERROR_INVALID_SECTION);
}

void
bfelf_loader_ut::test_bfelf_file_init_invalid_hash_table_size3()
{
    bfelf_file_t ef;
    auto test = get_test();

    test.hashtab.nchain = 0xDEAD;

    auto ret = bfelf_file_init(reinterpret_cast<char *>(&test), sizeof(test), &ef);
    this->expect_true(ret == BFELF_ERROR_INVALID_SECTION);
}
