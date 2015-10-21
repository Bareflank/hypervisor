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
#include <iostream>
#include <functional>

#include <sys/mman.h>

auto c_dummy1_filename = "libdummy1.so";
auto c_dummy2_filename = "libdummy2.so";
auto c_dummy3_filename = "libdummy3.so";

struct elf_test
{
    elf64_ehdr header;
    elf_phdr phdr1;
    elf_phdr phdr2;
    char tmp[16];
    char strtab[12];
    elf_sym symtab[2];
    elf_rel reltab[2];
    elf_rela relatab[2];
    elf_shdr shdr1;
    elf_shdr shdr2;
    elf_shdr shdr3;
    elf_shdr shdr4;
};

elf_test g_test = {0};

elf_loader_ut::elf_loader_ut() :
    m_dummy1(0),
    m_dummy2(0),
    m_dummy3(0),
    m_dummy1_length(0),
    m_dummy2_length(0),
    m_dummy3_length(0),
    m_dummy1_exec(0),
    m_dummy2_exec(0),
    m_dummy3_exec(0),
    m_dummy1_esize(0),
    m_dummy2_esize(0),
    m_dummy3_esize(0),
    m_test_exec(0),
    m_test_esize(0)
{
}

bool elf_loader_ut::init(void)
{
    auto result = false;

    auto dummy1_ifs = std::ifstream(c_dummy1_filename, std::ifstream::ate);
    auto dummy2_ifs = std::ifstream(c_dummy2_filename, std::ifstream::ate);
    auto dummy3_ifs = std::ifstream(c_dummy3_filename, std::ifstream::ate);

    if (dummy1_ifs.is_open() == false ||
        dummy2_ifs.is_open() == false ||
        dummy3_ifs.is_open() == false)
    {
        std::cout << "unable to open one or more dummy libraries: " << std::endl;
        std::cout << "    - dummy1: " << dummy1_ifs.is_open();
        std::cout << "    - dummy2: " << dummy2_ifs.is_open();
        std::cout << "    - dummy3: " << dummy3_ifs.is_open();
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
        std::cout << "    - dummy1: " << dummy1_ifs.tellg();
        std::cout << "    - dummy2: " << dummy2_ifs.tellg();
        std::cout << "    - dummy3: " << dummy3_ifs.tellg();
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
        std::cout << "    - dummy1: " << (void *)m_dummy1;
        std::cout << "    - dummy2: " << (void *)m_dummy2;
        std::cout << "    - dummy3: " << (void *)m_dummy3;
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
        std::cout << "    - dummy1: " << dummy1_ifs.fail();
        std::cout << "    - dummy2: " << dummy2_ifs.fail();
        std::cout << "    - dummy3: " << dummy3_ifs.fail();
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

bool elf_loader_ut::fini(void)
{
    if (m_dummy1 != NULL)
        delete[] m_dummy1;

    if (m_dummy2 != NULL)
        delete[] m_dummy2;

    if (m_dummy1 != NULL)
        delete[] m_dummy3;

    if (m_dummy1_exec != NULL)
        munmap(m_dummy1_exec, m_dummy1_esize);

    if (m_dummy2_exec != NULL)
        munmap(m_dummy2_exec, m_dummy2_esize);

    if (m_dummy3_exec != NULL)
        munmap(m_dummy3_exec, m_dummy3_esize);

    return true;
}

bool elf_loader_ut::list(void)
{
    this->test_elf_file_init();
    this->test_elf_file_size();
    this->test_elf_file_load();
    this->test_elf_loader_init();
    this->test_elf_loader_add();
    this->test_elf_loader_relocate();
    this->test_elf_section_header();
    this->test_elf_string_table_entry();
    this->test_elf_section_name_string();
    this->test_elf_symbol_by_index();
    this->test_elf_symbol_by_name();
    this->test_elf_symbol_by_name_global();
    this->test_elf_resolve_symbol();
    this->test_elf_relocate_symbol();
    this->test_elf_relocate_symbol_addend();
    this->test_elf_relocate_symbols();
    this->test_elf_program_header();
    this->test_elf_load_segments();
    this->test_elf_load_segment();

    this->test_elf_file_print_header();
    this->test_elf_print_section_header_table();
    this->test_elf_print_program_header_table();
    this->test_elf_print_sym_table();
    this->test_elf_print_relocations();

    this->test_resolve();

    return true;
}

char *alloc_exec(int32_t size)
{
    return (char *)mmap(0, size, PROT_READ | PROT_WRITE | PROT_EXEC,
                        MAP_PRIVATE | MAP_ANON, -1, 0);
}

void elf_loader_ut::test_elf_file_init(void)
{
    auto ret = 0;

    ret = elf_file_init(NULL, sizeof(g_test), &m_test_elf);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_ARG);
    ret = elf_file_init((char *)&g_test, 10, &m_test_elf);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_ARG);
    ret = elf_file_init((char *)&g_test, sizeof(g_test), NULL);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_ARG);

    ret = elf_file_init((char *)&g_test, sizeof(g_test), &m_test_elf);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_EI_MAG0);
    g_test.header.e_ident[ei_mag0] = 0x7F;

    ret = elf_file_init((char *)&g_test, sizeof(g_test), &m_test_elf);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_EI_MAG1);
    g_test.header.e_ident[ei_mag1] = 'E';

    ret = elf_file_init((char *)&g_test, sizeof(g_test), &m_test_elf);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_EI_MAG2);
    g_test.header.e_ident[ei_mag2] = 'L';

    ret = elf_file_init((char *)&g_test, sizeof(g_test), &m_test_elf);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_EI_MAG3);
    g_test.header.e_ident[ei_mag3] = 'F';

    ret = elf_file_init((char *)&g_test, sizeof(g_test), &m_test_elf);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_EI_CLASS);
    g_test.header.e_ident[ei_class] = elfclass64;

    ret = elf_file_init((char *)&g_test, sizeof(g_test), &m_test_elf);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_EI_DATA);
    g_test.header.e_ident[ei_data] = elfdata2lsb;

    ret = elf_file_init((char *)&g_test, sizeof(g_test), &m_test_elf);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_EI_VERSION);
    g_test.header.e_ident[ei_version] = ev_current;

    g_test.header.e_ident[ei_osabi] = 1;
    ret = elf_file_init((char *)&g_test, sizeof(g_test), &m_test_elf);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_EI_OSABI);
    g_test.header.e_ident[ei_osabi] = elfosabi_sysv;

    g_test.header.e_ident[ei_abiversion] = 1;
    ret = elf_file_init((char *)&g_test, sizeof(g_test), &m_test_elf);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_EI_ABIVERSION);
    g_test.header.e_ident[ei_abiversion] = 0;

    ret = elf_file_init((char *)&g_test, sizeof(g_test), &m_test_elf);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_E_TYPE);
    g_test.header.e_type = et_dyn;

    ret = elf_file_init((char *)&g_test, sizeof(g_test), &m_test_elf);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_E_MACHINE);
    g_test.header.e_machine = em_x86_64;

    ret = elf_file_init((char *)&g_test, sizeof(g_test), &m_test_elf);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_EI_VERSION);
    g_test.header.e_version = ev_current;

    g_test.header.e_entry = -1;
    ret = elf_file_init((char *)&g_test, sizeof(g_test), &m_test_elf);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_E_ENTRY);
    g_test.header.e_entry = 10000000;
    ret = elf_file_init((char *)&g_test, sizeof(g_test), &m_test_elf);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_E_ENTRY);
    g_test.header.e_entry = 10;

    g_test.header.e_phoff = -1;
    ret = elf_file_init((char *)&g_test, sizeof(g_test), &m_test_elf);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_E_PHOFF);
    g_test.header.e_phoff = 10000000;
    ret = elf_file_init((char *)&g_test, sizeof(g_test), &m_test_elf);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_E_PHOFF);
    g_test.header.e_phoff = (elf64_off)&g_test.phdr1 - (elf64_off)&g_test;

    g_test.header.e_shoff = -1;
    ret = elf_file_init((char *)&g_test, sizeof(g_test), &m_test_elf);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_E_SHOFF);
    g_test.header.e_shoff = 10000000;
    ret = elf_file_init((char *)&g_test, sizeof(g_test), &m_test_elf);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_E_SHOFF);
    g_test.header.e_shoff = (elf64_off)&g_test.shdr1 - (elf64_off)&g_test;

    g_test.header.e_flags = 1;
    ret = elf_file_init((char *)&g_test, sizeof(g_test), &m_test_elf);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_E_FLAGS);
    g_test.header.e_flags = 0;

    ret = elf_file_init((char *)&g_test, sizeof(g_test), &m_test_elf);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_E_EHSIZE);
    g_test.header.e_ehsize = sizeof(struct elf64_ehdr);

    ret = elf_file_init((char *)&g_test, sizeof(g_test), &m_test_elf);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_E_PHENTSIZE);
    g_test.header.e_phentsize = sizeof(struct elf_phdr);

    ret = elf_file_init((char *)&g_test, sizeof(g_test), &m_test_elf);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_E_SHENTSIZE);
    g_test.header.e_shentsize = sizeof(struct elf_shdr);

    g_test.header.e_phnum = 2;
    g_test.header.e_shnum = 4;

    g_test.header.e_shstrndx = 10;
    ret = elf_file_init((char *)&g_test, sizeof(g_test), &m_test_elf);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_E_SHSTRNDX);
    g_test.header.e_shstrndx = 0;

    g_test.header.e_phnum = 16000;
    ret = elf_file_init((char *)&g_test, sizeof(g_test), &m_test_elf);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_PHT);
    g_test.header.e_phnum = 2;

    g_test.header.e_shnum = 5;
    ret = elf_file_init((char *)&g_test, sizeof(g_test), &m_test_elf);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_SHT);
    g_test.header.e_shnum = 4;

    g_test.shdr1.sh_offset = 16000;
    ret = elf_file_init((char *)&g_test, sizeof(g_test), &m_test_elf);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_SH_SIZE);
    g_test.shdr1.sh_offset = (elf64_off)&g_test.strtab - (elf64_off)&g_test;

    g_test.shdr1.sh_size = 16000;
    ret = elf_file_init((char *)&g_test, sizeof(g_test), &m_test_elf);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_SH_SIZE);
    g_test.shdr1.sh_size = sizeof(g_test.strtab);

    g_test.shdr1.sh_offset = (elf64_off)&g_test.strtab - (elf64_off)&g_test;
    g_test.shdr2.sh_offset = (elf64_off)&g_test.symtab - (elf64_off)&g_test;
    g_test.shdr3.sh_offset = (elf64_off)&g_test.reltab - (elf64_off)&g_test;
    g_test.shdr4.sh_offset = (elf64_off)&g_test.relatab - (elf64_off)&g_test;
    g_test.shdr1.sh_size = sizeof(g_test.strtab);
    g_test.shdr2.sh_size = sizeof(g_test.symtab);
    g_test.shdr3.sh_size = sizeof(g_test.reltab);
    g_test.shdr4.sh_size = sizeof(g_test.relatab);

    g_test.phdr1.p_offset = 16000;
    ret = elf_file_init((char *)&g_test, sizeof(g_test), &m_test_elf);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_PH_FILESZ);
    g_test.phdr1.p_offset = (elf64_off)&g_test.strtab - (elf64_off)&g_test;

    g_test.phdr1.p_memsz = 16000;
    g_test.phdr1.p_filesz = 16000;
    ret = elf_file_init((char *)&g_test, sizeof(g_test), &m_test_elf);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_PH_FILESZ);
    g_test.phdr1.p_filesz = sizeof(g_test.strtab) + sizeof(g_test.symtab);

    g_test.phdr1.p_memsz = 1;
    ret = elf_file_init((char *)&g_test, sizeof(g_test), &m_test_elf);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_PH_FILESZ);
    g_test.phdr1.p_memsz = g_test.phdr1.p_filesz;

    g_test.phdr1.p_offset = (elf64_off)&g_test.strtab - (elf64_off)&g_test;
    g_test.phdr1.p_filesz = sizeof(g_test.strtab) + sizeof(g_test.symtab);
    g_test.phdr1.p_memsz = g_test.phdr1.p_filesz;
    g_test.phdr1.p_vaddr = g_test.phdr1.p_offset;

    g_test.phdr2.p_offset = (elf64_off)&g_test.reltab - (elf64_off)&g_test;
    g_test.phdr2.p_filesz = sizeof(g_test.reltab) + sizeof(g_test.relatab);
    g_test.phdr2.p_memsz = g_test.phdr2.p_filesz + 300;
    g_test.phdr2.p_vaddr = g_test.phdr2.p_offset;

    ret = elf_file_init((char *)&g_test, sizeof(g_test), &m_test_elf);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_FILE);
    g_test.shdr2.sh_type = sht_dynsym;

    g_test.shdr2.sh_link = 16000;
    ret = elf_file_init((char *)&g_test, sizeof(g_test), &m_test_elf);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_INDEX);
    g_test.shdr2.sh_link = 0;

    ret = elf_file_init((char *)&g_test, sizeof(g_test), &m_test_elf);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_SH_TYPE);

    g_test.shdr1.sh_type = sht_strtab;
    g_test.shdr2.sh_type = sht_dynsym;
    g_test.shdr3.sh_type = sht_rel;
    g_test.shdr4.sh_type = sht_rela;

    g_test.strtab[0] = 'h';
    g_test.strtab[1] = 'e';
    g_test.strtab[2] = 'l';
    g_test.strtab[3] = 'l';
    g_test.strtab[4] = 'o';
    g_test.strtab[5] = '\0';
    g_test.strtab[6] = 'w';
    g_test.strtab[7] = 'o';
    g_test.strtab[8] = 'r';
    g_test.strtab[9] = 'l';
    g_test.strtab[10] = 'd';
    g_test.strtab[11] = '\0';

    g_test.shdr1.sh_name = 0;
    g_test.shdr2.sh_name = 0;
    g_test.shdr3.sh_name = 6;
    g_test.shdr4.sh_name = 6;

    g_test.symtab[0].st_value = 0x10;
    g_test.symtab[1].st_value = 0x11;

    g_test.reltab[0].r_offset = (elf64_addr)g_test.tmp - (elf64_addr)&g_test;
    g_test.reltab[0].r_info = R_X86_64_GLOB_DAT;
    g_test.reltab[1].r_offset = (elf64_addr)g_test.tmp - (elf64_addr)&g_test;
    g_test.reltab[1].r_info = R_X86_64_JUMP_SLOT;

    g_test.relatab[0].r_offset = (elf64_addr)g_test.tmp - (elf64_addr)&g_test;
    g_test.relatab[0].r_info = R_X86_64_GLOB_DAT;
    g_test.relatab[1].r_offset = (elf64_addr)g_test.tmp - (elf64_addr)&g_test;
    g_test.relatab[1].r_info = R_X86_64_64;

    ret = elf_file_init((char *)&g_test, sizeof(g_test), &m_test_elf);
    ASSERT_TRUE(ret == ELF_SUCCESS);
    ret = elf_file_init((char *)&g_test, sizeof(g_test), &m_test_elf);
    ASSERT_TRUE(ret == ELF_SUCCESS);

    ret = elf_file_init(m_dummy1, m_dummy1_length, &m_dummy1_ef);
    ASSERT_TRUE(ret == ELF_SUCCESS);
    ret = elf_file_init(m_dummy2, m_dummy2_length, &m_dummy2_ef);
    ASSERT_TRUE(ret == ELF_SUCCESS);
    ret = elf_file_init(m_dummy3, m_dummy3_length, &m_dummy3_ef);
    ASSERT_TRUE(ret == ELF_SUCCESS);

}

void elf_loader_ut::test_elf_file_size(void)
{
    m_test_esize = elf_total_exec_size(NULL);
    ASSERT_TRUE(m_test_esize == ELF_ERROR_INVALID_ARG);

    m_test_elf.valid = ELF_FALSE;
    m_test_esize = elf_total_exec_size(&m_test_elf);
    ASSERT_TRUE(m_test_esize == ELF_ERROR_INVALID_FILE);
    m_test_elf.valid = ELF_TRUE;

    m_test_esize = elf_total_exec_size(&m_test_elf);
    ASSERT_TRUE(m_test_esize > ELF_SUCCESS);

    m_test_exec = alloc_exec(m_test_esize);
    ASSERT_TRUE(m_test_exec != NULL);

    m_dummy1_esize = elf_total_exec_size(&m_dummy1_ef);
    ASSERT_TRUE(m_dummy1_esize > ELF_SUCCESS);
    m_dummy2_esize = elf_total_exec_size(&m_dummy2_ef);
    ASSERT_TRUE(m_dummy2_esize > ELF_SUCCESS);
    m_dummy3_esize = elf_total_exec_size(&m_dummy3_ef);
    ASSERT_TRUE(m_dummy3_esize > ELF_SUCCESS);

    m_dummy1_exec = alloc_exec(m_dummy1_esize);
    ASSERT_TRUE(m_dummy1_exec != NULL);
    m_dummy2_exec = alloc_exec(m_dummy2_esize);
    ASSERT_TRUE(m_dummy2_exec != NULL);
    m_dummy3_exec = alloc_exec(m_dummy3_esize);
    ASSERT_TRUE(m_dummy3_exec != NULL);
}

void elf_loader_ut::test_elf_file_load(void)
{
    auto ret = 0;

    ret = elf_file_load(NULL, m_test_exec, m_test_esize);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_ARG);

    ret = elf_file_load(&m_test_elf, NULL, m_test_esize);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_ARG);

    ret = elf_file_load(&m_test_elf, m_test_exec, 10);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_ARG);

    m_test_elf.valid = ELF_FALSE;
    ret = elf_file_load(&m_test_elf, m_test_exec, m_test_esize);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_FILE);
    m_test_elf.valid = ELF_TRUE;

    ret = elf_file_load(&m_test_elf, m_test_exec, 1000000);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_ARG);

    ret = elf_file_load(&m_test_elf, m_test_exec, m_test_esize);
    ASSERT_TRUE(ret == ELF_SUCCESS);
    ret = elf_file_load(&m_test_elf, m_test_exec, m_test_esize);
    ASSERT_TRUE(ret == ELF_SUCCESS);

    ret = elf_file_load(&m_dummy1_ef, m_dummy1_exec, m_dummy1_esize);
    ASSERT_TRUE(ret == ELF_SUCCESS);
    ret = elf_file_load(&m_dummy2_ef, m_dummy2_exec, m_dummy2_esize);
    ASSERT_TRUE(ret == ELF_SUCCESS);
    ret = elf_file_load(&m_dummy3_ef, m_dummy3_exec, m_dummy3_esize);
    ASSERT_TRUE(ret == ELF_SUCCESS);
}

void elf_loader_ut::test_elf_loader_init(void)
{
    auto ret = 0;

    ret = elf_loader_init(NULL);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_ARG);

    ret = elf_loader_init(&m_test_loader);
    ASSERT_TRUE(ret == ELF_SUCCESS);

    ret = elf_loader_init(&m_loader);
    ASSERT_TRUE(ret == ELF_SUCCESS);
}

void elf_loader_ut::test_elf_loader_add(void)
{
    auto ret = 0;

    ret = elf_loader_add(NULL, &m_dummy1_ef);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_ARG);

    ret = elf_loader_add(&m_test_loader, NULL);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_ARG);

    m_test_elf.valid = ELF_FALSE;
    ret = elf_loader_add(&m_test_loader, &m_test_elf);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_FILE);
    m_test_elf.valid = ELF_TRUE;

    for (auto i = 0; i < ELF_MAX_MODULES + 1; i++)
        ret = elf_loader_add(&m_test_loader, &m_test_elf);
    ASSERT_TRUE(ret == ELF_ERROR_LOADER_FULL);

    ret = elf_loader_init(&m_test_loader);
    ASSERT_TRUE(ret == ELF_SUCCESS);
    ret = elf_loader_add(&m_test_loader, &m_test_elf);
    ASSERT_TRUE(ret == ELF_SUCCESS);

    ret = elf_loader_add(&m_loader, &m_dummy1_ef);
    ASSERT_TRUE(ret == ELF_SUCCESS);
    ret = elf_loader_add(&m_loader, &m_dummy2_ef);
    ASSERT_TRUE(ret == ELF_SUCCESS);
    ret = elf_loader_add(&m_loader, &m_dummy3_ef);
    ASSERT_TRUE(ret == ELF_SUCCESS);
}

void elf_loader_ut::test_elf_loader_relocate(void)
{
    auto ret = 0;

    ret = elf_loader_relocate(NULL);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_ARG);

    m_test_loader.num = 1000;
    ret = elf_loader_relocate(&m_test_loader);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_LOADER);
    m_test_loader.num = 1;

    ret = elf_loader_relocate(&m_test_loader);
    ASSERT_TRUE(ret == ELF_SUCCESS);
    ret = elf_loader_relocate(&m_test_loader);
    ASSERT_TRUE(ret == ELF_SUCCESS);

    ret = elf_loader_relocate(&m_loader);
    ASSERT_TRUE(ret == ELF_SUCCESS);
}

void elf_loader_ut::test_elf_section_header(void)
{
    auto ret = 0;
    struct elf_shdr *shdr = 0;
    struct elf_file_t tmp_elf = {0};

    ret = elf_section_header(NULL, 0, &shdr);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_ARG);

    ret = elf_section_header(&m_test_elf, 0, NULL);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_ARG);

    ret = elf_section_header(&tmp_elf, 0, NULL);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_ARG);

    tmp_elf.ehdr = m_test_elf.ehdr;
    ret = elf_section_header(&tmp_elf, 0, NULL);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_ARG);

    ret = elf_section_header(&m_test_elf, 100, &shdr);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_INDEX);

    ret = elf_section_header(&m_test_elf, 0, &shdr);
    ASSERT_TRUE(ret == ELF_SUCCESS);
}

void elf_loader_ut::test_elf_string_table_entry(void)
{
    auto ret = 0;
    struct e_string str = {0};

    ret = elf_string_table_entry(NULL, m_test_elf.strtab, 0, &str);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_ARG);

    ret = elf_string_table_entry(&m_test_elf, NULL, 0, &str);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_ARG);

    ret = elf_string_table_entry(&m_test_elf, m_test_elf.strtab, 0, NULL);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_ARG);

    m_test_elf.valid = ELF_FALSE;
    ret = elf_string_table_entry(&m_test_elf, m_test_elf.strtab, 0, &str);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_FILE);
    m_test_elf.valid = ELF_TRUE;

    ret = elf_string_table_entry(&m_test_elf, m_test_elf.strtab, 100, &str);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_OFFSET);

    g_test.strtab[11] = 'a';
    ret = elf_string_table_entry(&m_test_elf, m_test_elf.strtab, 6, &str);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_STRING_TABLE);
    g_test.strtab[11] = '\0';

    ret = elf_string_table_entry(&m_test_elf, m_test_elf.strtab, 0, &str);
    ASSERT_TRUE(ret == ELF_SUCCESS);
    ASSERT_TRUE(str.buf[0] == 'h');
    ASSERT_TRUE(str.len == 5);

    ret = elf_string_table_entry(&m_test_elf, m_test_elf.strtab, 6, &str);
    ASSERT_TRUE(ret == ELF_SUCCESS);
    ASSERT_TRUE(str.buf[0] == 'w');
    ASSERT_TRUE(str.len == 5);
}

void elf_loader_ut::test_elf_section_name_string(void)
{
    auto ret = 0;
    struct e_string str = {0};
    struct elf_shdr *shdr = 0;

    ret = elf_section_name_string(NULL, &g_test.shdr1, &str);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_ARG);

    ret = elf_section_name_string(&m_test_elf, NULL, &str);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_ARG);

    ret = elf_section_name_string(&m_test_elf, &g_test.shdr1, NULL);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_ARG);

    m_test_elf.valid = ELF_FALSE;
    ret = elf_section_name_string(&m_test_elf, &g_test.shdr1, &str);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_FILE);
    m_test_elf.valid = ELF_TRUE;

    ret = elf_section_name_string(&m_test_elf, &g_test.shdr1, &str);
    ASSERT_TRUE(ret == ELF_SUCCESS);
    ASSERT_TRUE(str.buf[0] == 'h');
}

void elf_loader_ut::test_elf_symbol_by_index(void)
{
    auto ret = 0;
    struct elf_sym *sym = 0;

    ret = elf_symbol_by_index(NULL, 0, &sym);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_ARG);

    ret = elf_symbol_by_index(&m_test_elf, 0, NULL);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_ARG);

    ret = elf_symbol_by_index(&m_test_elf, 3, &sym);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_INDEX);

    m_test_elf.valid = ELF_FALSE;
    ret = elf_symbol_by_index(&m_test_elf, 0, &sym);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_FILE);
    m_test_elf.valid = ELF_TRUE;

    ret = elf_symbol_by_index(&m_test_elf, 0, &sym);
    ASSERT_TRUE(ret == ELF_SUCCESS);
}

void elf_loader_ut::test_elf_symbol_by_name(void)
{
    auto ret = 0;
    struct elf_sym *sym = 0;
    struct e_string str = {0};

    ret = elf_symbol_by_name(NULL, &str, &sym);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_ARG);

    ret = elf_symbol_by_name(&m_test_elf, NULL, &sym);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_ARG);

    ret = elf_symbol_by_name(&m_test_elf, &str, NULL);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_ARG);

    m_test_elf.valid = ELF_FALSE;
    ret = elf_symbol_by_name(&m_test_elf, &str, &sym);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_FILE);
    m_test_elf.valid = ELF_TRUE;

    ret = elf_symbol_by_name(&m_test_elf, &str, &sym);
    ASSERT_TRUE(ret == ELF_ERROR_NO_SUCH_SYMBOL);

    ret = elf_string_table_entry(&m_test_elf, m_test_elf.strtab, 0, &str);
    ASSERT_TRUE(ret == ELF_SUCCESS);

    ret = elf_symbol_by_name(&m_test_elf, &str, &sym);
    ASSERT_TRUE(ret == ELF_SUCCESS);
}

void elf_loader_ut::test_elf_symbol_by_name_global(void)
{
    auto ret = 0;
    struct elf_sym *sym = 0;
    struct e_string str = {0};
    struct elf_file_t *efr = 0;

    ret = elf_symbol_by_name_global(NULL, &str, &efr, &sym);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_ARG);

    ret = elf_symbol_by_name_global(&m_test_elf, NULL, &efr, &sym);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_ARG);

    ret = elf_symbol_by_name_global(&m_test_elf, &str, NULL, &sym);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_ARG);

    ret = elf_symbol_by_name_global(&m_test_elf, &str, &efr, NULL);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_ARG);

    m_test_elf.valid = ELF_FALSE;
    ret = elf_symbol_by_name_global(&m_test_elf, &str, &efr, &sym);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_FILE);
    m_test_elf.valid = ELF_TRUE;

    ret = elf_symbol_by_name_global(&m_test_elf, &str, &efr, &sym);
    ASSERT_TRUE(ret == ELF_ERROR_NO_SUCH_SYMBOL);

    ret = elf_string_table_entry(&m_test_elf, m_test_elf.strtab, 0, &str);
    ASSERT_TRUE(ret == ELF_SUCCESS);

    g_test.symtab[0].st_value = 0x0;
    ret = elf_symbol_by_name_global(&m_test_elf, &str, &efr, &sym);
    ASSERT_TRUE(ret == ELF_ERROR_NO_SUCH_SYMBOL);
    g_test.symtab[0].st_value = 0x10;

    ret = elf_symbol_by_name_global(&m_test_elf, &str, &efr, &sym);
    ASSERT_TRUE(ret == ELF_SUCCESS);
    ASSERT_TRUE(efr == &m_test_elf);
}

void elf_loader_ut::test_elf_resolve_symbol(void)
{
    auto ret = 0;
    void *addr = 0;
    struct e_string str = {0};

    ret = elf_resolve_symbol(NULL, &str, &addr);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_ARG);

    ret = elf_resolve_symbol(&m_test_elf, NULL, &addr);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_ARG);

    ret = elf_resolve_symbol(&m_test_elf, &str, NULL);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_ARG);

    m_test_elf.valid = ELF_FALSE;
    ret = elf_resolve_symbol(&m_test_elf, &str, &addr);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_FILE);
    m_test_elf.valid = ELF_TRUE;

    ret = elf_resolve_symbol(&m_test_elf, &str, &addr);
    ASSERT_TRUE(ret == ELF_ERROR_NO_SUCH_SYMBOL);

    ret = elf_string_table_entry(&m_test_elf, m_test_elf.strtab, 0, &str);
    ASSERT_TRUE(ret == ELF_SUCCESS);

    ret = elf_resolve_symbol(&m_test_elf, &str, &addr);
    ASSERT_TRUE(ret == ELF_SUCCESS);
}

void elf_loader_ut::test_elf_relocate_symbol(void)
{
    auto ret = 0;

    ret = elf_relocate_symbol(NULL, &(g_test.reltab[0]));
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_ARG);

    ret = elf_relocate_symbol(&m_test_elf, NULL);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_ARG);

    m_test_elf.valid = ELF_FALSE;
    ret = elf_relocate_symbol(&m_test_elf, &(g_test.reltab[0]));
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_FILE);
    m_test_elf.valid = ELF_TRUE;

    g_test.reltab[0].r_info = 0xFFFFFFFFFFFFFFFF;
    ret = elf_relocate_symbol(&m_test_elf, &(g_test.reltab[0]));
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_INDEX);
    g_test.reltab[0].r_info = 0;

    g_test.reltab[0].r_offset = 1000000;
    ret = elf_relocate_symbol(&m_test_elf, &(g_test.reltab[0]));
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_FILE);
    g_test.reltab[0].r_offset = (elf64_addr)g_test.tmp - (elf64_addr)&g_test;

    g_test.reltab[0].r_info = 100;
    ret = elf_relocate_symbol(&m_test_elf, &(g_test.reltab[0]));
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_RELOCATION_TYPE);
    g_test.reltab[0].r_info = R_X86_64_GLOB_DAT;

    ret = elf_relocate_symbol(&m_test_elf, &(g_test.reltab[0]));
    ASSERT_TRUE(ret == ELF_SUCCESS);
}

void elf_loader_ut::test_elf_relocate_symbol_addend(void)
{
    auto ret = 0;

    ret = elf_relocate_symbol_addend(NULL, &(g_test.relatab[0]));
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_ARG);

    ret = elf_relocate_symbol_addend(&m_test_elf, NULL);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_ARG);

    m_test_elf.valid = ELF_FALSE;
    ret = elf_relocate_symbol_addend(&m_test_elf, &(g_test.relatab[0]));
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_FILE);
    m_test_elf.valid = ELF_TRUE;

    g_test.relatab[0].r_info = 0xFFFFFFFFFFFFFFFF;
    ret = elf_relocate_symbol_addend(&m_test_elf, &(g_test.relatab[0]));
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_INDEX);
    g_test.relatab[0].r_info = 0;

    g_test.relatab[0].r_offset = 1000000;
    ret = elf_relocate_symbol_addend(&m_test_elf, &(g_test.relatab[0]));
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_FILE);
    g_test.relatab[0].r_offset = (elf64_addr)g_test.tmp - (elf64_addr)&g_test;

    g_test.relatab[0].r_info = 100;
    ret = elf_relocate_symbol_addend(&m_test_elf, &(g_test.relatab[0]));
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_RELOCATION_TYPE);
    g_test.relatab[0].r_info = R_X86_64_GLOB_DAT;

    ret = elf_relocate_symbol_addend(&m_test_elf, &(g_test.relatab[0]));
    ASSERT_TRUE(ret == ELF_SUCCESS);
}

void elf_loader_ut::test_elf_relocate_symbols(void)
{
    auto ret = 0;

    ret = elf_relocate_symbols(NULL);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_ARG);

    m_test_elf.valid = ELF_FALSE;
    ret = elf_relocate_symbols(&m_test_elf);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_FILE);
    m_test_elf.valid = ELF_TRUE;

    ret = elf_relocate_symbols(&m_test_elf);
    ASSERT_TRUE(ret == ELF_SUCCESS);
}

void elf_loader_ut::test_elf_program_header(void)
{
    auto ret = 0;
    struct elf_phdr *phdr = 0;
    struct elf_file_t tmp_elf = {0};

    ret = elf_program_header(NULL, 0, &phdr);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_ARG);

    ret = elf_program_header(&m_test_elf, 0, NULL);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_ARG);

    ret = elf_program_header(&tmp_elf, 0, NULL);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_ARG);

    tmp_elf.ehdr = m_test_elf.ehdr;
    ret = elf_program_header(&tmp_elf, 0, NULL);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_ARG);

    ret = elf_program_header(&m_test_elf, 100, &phdr);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_INDEX);

    ret = elf_program_header(&m_test_elf, 0, &phdr);
    ASSERT_TRUE(ret == ELF_SUCCESS);
}

void elf_loader_ut::test_elf_load_segments(void)
{
    auto ret = 0;

    ret = elf_load_segments(NULL);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_ARG);

    m_test_elf.valid = ELF_FALSE;
    ret = elf_load_segments(&m_test_elf);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_FILE);
    m_test_elf.valid = ELF_TRUE;

    ret = elf_load_segments(&m_test_elf);
    ASSERT_TRUE(ret == ELF_SUCCESS);
}

void elf_loader_ut::test_elf_load_segment(void)
{
    auto ret = 0;

    ret = elf_load_segment(NULL, &g_test.phdr1);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_ARG);

    ret = elf_load_segment(&m_test_elf, NULL);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_ARG);

    m_test_elf.valid = ELF_FALSE;
    ret = elf_load_segment(&m_test_elf, &g_test.phdr1);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_FILE);
    m_test_elf.valid = ELF_TRUE;

    g_test.phdr1.p_memsz = 1000000;
    ret = elf_load_segment(&m_test_elf, &g_test.phdr1);
    ASSERT_TRUE(ret == ELF_ERROR_INVALID_PH_MEMSZ);
    g_test.phdr1.p_memsz = g_test.phdr1.p_filesz;

    ret = elf_load_segment(&m_test_elf, &g_test.phdr1);
    ASSERT_TRUE(ret == ELF_SUCCESS);
}

void elf_loader_ut::test_elf_file_print_header(void)
{
    auto ret = 0;

    ret = elf_file_print_header(&m_dummy3_ef);
    ASSERT_TRUE(ret == ELF_SUCCESS);
}

void elf_loader_ut::test_elf_print_section_header_table(void)
{
    auto ret = 0;

    ret = elf_print_section_header_table(&m_dummy3_ef);
    ASSERT_TRUE(ret == ELF_SUCCESS);
}

void elf_loader_ut::test_elf_print_program_header_table(void)
{
    auto ret = 0;

    ret = elf_print_program_header_table(&m_dummy3_ef);
    ASSERT_TRUE(ret == ELF_SUCCESS);
}

void elf_loader_ut::test_elf_print_sym_table(void)
{
    auto ret = 0;

    ret = elf_print_sym_table(&m_dummy3_ef);
    ASSERT_TRUE(ret == ELF_SUCCESS);
}

void elf_loader_ut::test_elf_print_relocations(void)
{
    auto ret = 0;

    ret = elf_print_relocations(&m_dummy3_ef);
    ASSERT_TRUE(ret == ELF_SUCCESS);
}

void elf_loader_ut::test_resolve(void)
{
    auto ret = 0;
    void *entry = 0;
    struct e_string str = {"_Z12dummy3_test2i", 17};

    ret = elf_resolve_symbol(&m_dummy3_ef, &str, &entry);
    EXPECT_TRUE(ret == ELF_SUCCESS);

    if (ret == ELF_SUCCESS)
    {
        std::function<int(int)> dummy3_test1 =
            reinterpret_cast<int(*)(int)>(entry);

        std::cout << std::endl;
        std::cout << "Result: " << dummy3_test1(5) << std::endl;
        std::cout << std::endl;
    }
    else
    {
        std::cout << std::endl;
        std::cout << "Error: " << elf_error(ret) << std::endl;
        std::cout << std::endl;
    }
}

int
main(int argc, char *argv[])
{
    return RUN_ALL_TESTS(elf_loader_ut);
}
