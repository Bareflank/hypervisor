//
// Copyright (C) 2019 Assured Information Security, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#ifndef TEST_FAKE_ELF_H
#define TEST_FAKE_ELF_H

#include <memory>
#include <bfelf_loader.h>

std::pair<std::unique_ptr<char[]>, uint64_t>
get_fake_elf();

#pragma pack(push, 1)

#ifdef __cplusplus
extern "C" {
#endif

struct test_phdrtab {
    bfelf_phdr re_segment;
    bfelf_phdr rw_segment;
    bfelf_phdr dyn_segment;
    bfelf_phdr stack_segment;
    bfelf_phdr relro_segment;
};

struct test_hash {
    bfelf64_word nbucket;
    bfelf64_word nchain;
    bfelf64_word index1;
    bfelf64_word index2;
    bfelf64_word hash1;
    bfelf64_word hash2;
};

struct test_dynsym {
    bfelf_sym syms[2];
};

struct test_dynstr {
    char str1[10];
    char str2[10];
    char str3[10];
    char str4[10];
};

struct test_relatab {
    struct bfelf_rela relas[2];
};

struct test_eh_frame {
    const char *reserved[10];
};

struct test_init_array {
    const char *reserved[10];
};

struct test_fini_array {
    const char *reserved[10];
};

struct test_dynamic {
    struct bfelf_dyn needed1;
    struct bfelf_dyn needed2;
    struct bfelf_dyn pltgot;
    struct bfelf_dyn strtab;
    struct bfelf_dyn symtab;
    struct bfelf_dyn rela;
    struct bfelf_dyn relasz;
    struct bfelf_dyn relaent;
    struct bfelf_dyn strsz;
    struct bfelf_dyn init;
    struct bfelf_dyn fini;
    struct bfelf_dyn init_array;
    struct bfelf_dyn fini_array;
    struct bfelf_dyn init_arraysz;
    struct bfelf_dyn fini_arraysz;
    struct bfelf_dyn flags_1;
    struct bfelf_dyn last;
};

struct test_shdrtab {
    bfelf_shdr hash;
    bfelf_shdr dynsym;
    bfelf_shdr dynstr;
    bfelf_shdr relatab;
    bfelf_shdr eh_frame;
    bfelf_shdr init_array;
    bfelf_shdr fini_array;
    bfelf_shdr dynamic;
    bfelf_shdr ctors;
    bfelf_shdr dtors;
};

struct bfelf_test {
    bfelf_ehdr header;
    test_phdrtab phdrtab;

    test_dynsym dynsym;
    test_dynstr dynstr;
    test_hash hash;
    test_relatab relatab;
    test_eh_frame eh_frame;
    test_init_array init_array;
    test_fini_array fini_array;
    test_dynamic dynamic;

    test_shdrtab shdrtab;
};

#ifdef __cplusplus
}
#endif

#pragma pack(pop)

#endif
