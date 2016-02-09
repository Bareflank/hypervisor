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

#ifndef TEST_ELF
#define TEST_ELF

#include <bfelf_loader.h>

struct test_dynsym
{
    struct bfelf_sym syms[2];
};

struct test_hashtab
{
    bfelf64_word nbucket;
    bfelf64_word nchain;
    bfelf64_word index1;
    bfelf64_word index2;
    bfelf64_word hash1;
    bfelf64_word hash2;
};

struct test_strtab
{
    const char *func1 = "function1";
    const char *func2 = "function2";
};

struct test_shstrtab
{
    const char *name1 = ".dynsym";
    const char *name2 = ".hash";
    const char *name3 = ".strtab";
    const char *name4 = ".shstrtab";
    const char *name5 = ".rela.dyn";
};

struct test_relatab
{
    struct bfelf_rela relas[2];
};

struct test_phdrtab
{
    struct bfelf_phdr re_segment1;
    struct bfelf_phdr re_segment2;
    struct bfelf_phdr rw_segment1;
    struct bfelf_phdr rw_segment2;
    struct bfelf_phdr too_many;
};

struct test_shdrtab
{
    struct bfelf_shdr dynsym;       // 0
    struct bfelf_shdr hashtab;      // 1
    struct bfelf_shdr strtab;       // 2
    struct bfelf_shdr shstrtab;     // 3
    struct bfelf_shdr relatab1;     // 4
    struct bfelf_shdr relatab2;     // 5
    struct bfelf_shdr relatab3;     // 6
    struct bfelf_shdr relatab4;     // 7
    struct bfelf_shdr relatab5;     // 8
    struct bfelf_shdr relatab6;     // 9
    struct bfelf_shdr relatab7;     // 10
    struct bfelf_shdr relatab8;     // 11
    struct bfelf_shdr too_many;     // 12
};

struct bfelf_test
{
    struct bfelf64_ehdr header;
    struct test_phdrtab phdrtab;

    struct test_dynsym dynsym;
    struct test_hashtab hashtab;
    struct test_strtab strtab;
    struct test_shstrtab shstrtab;
    struct test_relatab relatab;

    struct test_shdrtab shdrtab;
};

#endif
