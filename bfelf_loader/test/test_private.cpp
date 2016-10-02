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

#include <gsl/gsl>

// -----------------------------------------------------------------------------
// Expose Private Functions
// -----------------------------------------------------------------------------

extern "C"
{
    int64_t
    private_check_symbol(struct bfelf_file_t *ef,
                         bfelf64_word index,
                         struct e_string_t *name,
                         struct bfelf_sym **sym);

    int64_t
    private_relocate_symbol(struct bfelf_loader_t *loader,
                            struct bfelf_file_t *ef,
                            struct bfelf_rela *rela);

    int64_t
    private_get_section_by_name(struct bfelf_file_t *ef,
                                struct e_string_t *name,
                                struct bfelf_shdr **shdr);

    int64_t
    private_check_section(struct bfelf_shdr *shdr,
                          bfelf64_word type,
                          bfelf64_xword flags,
                          bfelf64_xword addralign,
                          bfelf64_xword entsize);

    int64_t
    private_symbol_table_sections(struct bfelf_file_t *ef);

    int64_t
    private_get_string_table_sections(struct bfelf_file_t *ef);

    int64_t
    private_get_relocation_tables(struct bfelf_file_t *ef);

    unsigned long
    private_hash(const char *name);
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

void
bfelf_loader_ut::test_private_bfelf_error()
{
    this->expect_true(bfelf_error(0) == "SUCCESS"_s);
}

void
bfelf_loader_ut::test_private_invalid_symbol_index()
{
    bfelf_sym *sym = nullptr;
    bfelf_file_t ef = {};
    e_string_t name = {};
    bfelf_shdr strtab = {};

    ef.symnum = 1;
    ef.strtab = &strtab;

    this->expect_true(private_check_symbol(&ef, 2, &name, &sym) == BFELF_ERROR_MISMATCH);
}

void
bfelf_loader_ut::test_private_corrupt_symbol_table()
{
    auto file = "hello";

    bfelf_file_t ef = {};
    bfelf_shdr strtab = {};
    e_string_t name = {};
    bfelf_sym *sym = nullptr;
    bfelf_sym symtab[1] = {};

    gsl::at(symtab, 0).st_name = 0;

    ef.file = file;
    ef.strtab = &strtab;
    ef.symtab = static_cast<bfelf_sym *>(symtab);
    ef.symnum = 1;

    strtab.sh_size = 5;
    strtab.sh_offset = 0;

    this->expect_true(private_check_symbol(&ef, 0, &name, &sym) == BFELF_ERROR_MISMATCH);
}

void
bfelf_loader_ut::test_private_relocate_invalid_index()
{
    bfelf_loader_t loader = {};
    bfelf_file_t ef = {};
    bfelf_rela rela = {};
    bfelf_shdr strtab = {};

    rela.r_info = 0xFFFFFFFF00000000;

    ef.strtab = &strtab;

    this->expect_true(private_relocate_symbol(&loader, &ef, &rela) == BFELF_ERROR_INVALID_INDEX);
}

void
bfelf_loader_ut::test_private_relocate_invalid_name()
{
    bfelf_loader_t loader = {};
    bfelf_file_t ef = {};
    bfelf_rela rela = {};
    bfelf_shdr strtab = {};
    bfelf_sym symtab[1] = {};

    auto file = "hello";

    ef.file = file;
    ef.strtab = &strtab;
    ef.symtab = static_cast<bfelf_sym *>(symtab);
    ef.symnum = 1;

    strtab.sh_size = 5;
    strtab.sh_offset = 0;

    rela.r_info = 0x0;

    gsl::at(symtab, 0).st_name = 0xFFFFF;
    gsl::at(symtab, 0).st_value = 0x0;

    this->expect_true(private_relocate_symbol(&loader, &ef, &rela) == BFELF_ERROR_INVALID_FILE);
}

void
bfelf_loader_ut::test_private_relocate_invalid_relocation()
{
    bfelf_loader_t loader = {};
    bfelf_file_t ef = {};
    bfelf_rela rela = {};
    bfelf_shdr strtab = {};
    bfelf_sym symtab[1] = {};

    auto file = "hello";
    auto exec = std::make_unique<char[]>(1);

    ef.exec = exec.get();
    ef.file = file;
    ef.strtab = &strtab;
    ef.symtab = static_cast<bfelf_sym *>(symtab);
    ef.symnum = 1;

    strtab.sh_size = 5;
    strtab.sh_offset = 0;

    rela.r_info = 0xFFFFFFFF;
    rela.r_offset = 0x0;

    gsl::at(symtab, 0).st_name = 0xFFFFF;
    gsl::at(symtab, 0).st_value = 0x1;

    this->expect_true(private_relocate_symbol(&loader, &ef, &rela) == BFELF_ERROR_UNSUPPORTED_RELA);
}

void
bfelf_loader_ut::test_private_get_section_invalid_name()
{
    bfelf_file_t ef = {};
    e_string_t name = {};
    bfelf64_ehdr ehdr = {};
    bfelf_shdr *shdr = nullptr;
    bfelf_shdr shstrtab = {};
    bfelf_shdr shdrtab[1] = {};
    bfelf_shdr strtab = {};

    ef.ehdr = &ehdr;
    ef.shdrtab = static_cast<bfelf_shdr *>(shdrtab);
    ef.shstrtab = &shstrtab;
    ef.strtab = &strtab;

    ehdr.e_shnum = 1;

    gsl::at(shdrtab, 0).sh_name = 0;

    shstrtab.sh_size = 0;

    this->expect_true(private_get_section_by_name(&ef, &name, &shdr) == BFELF_ERROR_INVALID_FILE);
}

void
bfelf_loader_ut::test_private_symbol_table_sections_invalid_dynsym()
{
    MockRepository mocks;
    mocks.OnCallFunc(private_check_section).Return(-1);

    bfelf_file_t ef = {};
    bfelf64_ehdr ehdr = {};
    bfelf_shdr shdrtab[1] = {};
    bfelf_shdr strtab = {};

    ef.ehdr = &ehdr;
    ef.shdrtab = static_cast<bfelf_shdr *>(shdrtab);
    ef.strtab = &strtab;

    ehdr.e_shnum = 1;

    gsl::at(shdrtab, 0).sh_type = bfsht_dynsym;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_true(private_symbol_table_sections(&ef) == -1);
    });
}

void
bfelf_loader_ut::test_private_symbol_table_sections_invalid_hash()
{
    MockRepository mocks;
    mocks.OnCallFunc(private_check_section).Return(-1);

    bfelf_file_t ef = {};
    bfelf64_ehdr ehdr = {};
    bfelf_shdr shdrtab[1] = {};
    bfelf_shdr strtab = {};

    ef.ehdr = &ehdr;
    ef.shdrtab = static_cast<bfelf_shdr *>(shdrtab);
    ef.strtab = &strtab;

    ehdr.e_shnum = 1;

    gsl::at(shdrtab, 0).sh_type = bfsht_hash;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_true(private_symbol_table_sections(&ef) == -1);
    });
}

void
bfelf_loader_ut::test_private_string_table_sections_invalid()
{
    MockRepository mocks;
    mocks.OnCallFunc(private_check_section).Return(-1);

    bfelf_file_t ef = {};
    bfelf64_ehdr ehdr = {};
    bfelf_shdr dynsym = {};
    bfelf_shdr strtab = {};

    ef.ehdr = &ehdr;
    ef.dynsym = &dynsym;
    ef.strtab = &strtab;

    dynsym.sh_link = 0;
    ehdr.e_shstrndx = 0;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_true(private_get_string_table_sections(&ef) == -1);
    });
}

void
bfelf_loader_ut::test_private_get_relocation_tables_invalid_type()
{
    bfelf_file_t ef = {};
    bfelf64_ehdr ehdr = {};
    bfelf_shdr shdrtab[1] = {};
    bfelf_shdr strtab = {};

    ef.ehdr = &ehdr;
    ef.shdrtab = static_cast<bfelf_shdr *>(shdrtab);
    ef.strtab = &strtab;

    ehdr.e_shnum = 1;

    gsl::at(shdrtab, 0).sh_type = bfsht_rel;

    this->expect_true(private_get_relocation_tables(&ef) == BFELF_ERROR_UNSUPPORTED_RELA);
}

void
bfelf_loader_ut::test_private_get_relocation_tables_invalid_section()
{
    MockRepository mocks;
    mocks.OnCallFunc(private_check_section).Return(-1);

    bfelf_file_t ef = {};
    bfelf64_ehdr ehdr = {};
    bfelf_shdr shdrtab[1] = {};
    bfelf_shdr strtab = {};

    ef.ehdr = &ehdr;
    ef.shdrtab = static_cast<bfelf_shdr *>(shdrtab);
    ef.num_rela = 1;
    ef.strtab = &strtab;

    ehdr.e_shnum = 1;

    gsl::at(shdrtab, 0).sh_type = bfsht_rela;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_true(private_get_relocation_tables(&ef) == -1);
    });
}

void
bfelf_loader_ut::test_private_hash()
{
    const char name[2] = {static_cast<char>(-1), static_cast<char>(0)};

    this->expect_true(private_hash(static_cast<const char *>(name)) != 0);
}
