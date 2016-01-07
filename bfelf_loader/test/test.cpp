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
#include <abi_conversion.h>

#include <fstream>
#include <sys/mman.h>

auto c_dummy1_filename = "../cross/libdummy1.so";
auto c_dummy2_filename = "../cross/libdummy2.so";
auto c_dummy3_filename = "../cross/libdummy3.so";

struct bfelf_test
{
    bfelf64_ehdr header;
    bfelf_phdr phdr1;
    bfelf_phdr phdr2;
    char tmp[16];
    char strtab[12];
    bfelf_sym symtab[2];
    bfelf_rel reltab[2];
    bfelf_rela relatab[2];
    bfelf_shdr shdr1;
    bfelf_shdr shdr2;
    bfelf_shdr shdr3;
    bfelf_shdr shdr4;
};

bfelf_test g_test = {};

bfelf_loader_ut::bfelf_loader_ut() :
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

bool bfelf_loader_ut::init()
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

    return result;
}

bool bfelf_loader_ut::fini()
{
    if (m_dummy1 != NULL)
        delete[] m_dummy1;

    if (m_dummy2 != NULL)
        delete[] m_dummy2;

    if (m_dummy3 != NULL)
        delete[] m_dummy3;

    if (m_dummy1_exec != NULL)
        munmap(m_dummy1_exec, m_dummy1_esize);

    if (m_dummy2_exec != NULL)
        munmap(m_dummy2_exec, m_dummy2_esize);

    if (m_dummy3_exec != NULL)
        munmap(m_dummy3_exec, m_dummy3_esize);

    return true;
}

bool bfelf_loader_ut::list()
{
    this->test_bfelf_file_init();
    this->test_bfelf_file_size();
    this->test_bfelf_file_load();
    this->test_bfelf_loader_init();
    this->test_bfelf_loader_add();
    this->test_bfelf_loader_relocate();
    this->test_bfelf_section_header();
    this->test_bfelf_string_table_entry();
    this->test_bfelf_section_name_string();
    this->test_bfelf_symbol_by_index();
    this->test_bfelf_symbol_by_name();
    this->test_bfelf_symbol_by_name_global();
    this->test_bfelf_resolve_symbol();
    this->test_bfelf_relocate_symbol();
    this->test_bfelf_relocate_symbol_addend();
    this->test_bfelf_relocate_symbols();
    this->test_bfelf_program_header();
    this->test_bfelf_load_segments();
    this->test_bfelf_load_segment();

    this->test_bfelf_file_print_header();
    this->test_bfelf_print_section_header_table();
    this->test_bfelf_print_program_header_table();
    this->test_bfelf_print_sym_table();
    this->test_bfelf_print_relocations();

    this->test_resolve();

    return true;
}

char *alloc_exec(int32_t size)
{
    return (char *)mmap(0, size, PROT_READ | PROT_WRITE | PROT_EXEC,
                        MAP_PRIVATE | MAP_ANON, -1, 0);
}

void bfelf_loader_ut::test_bfelf_file_init()
{
    auto ret = 0;

    ret = bfelf_file_init(NULL, sizeof(g_test), &m_test_elf);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_ARG);
    ret = bfelf_file_init((char *)&g_test, 10, &m_test_elf);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_ARG);
    ret = bfelf_file_init((char *)&g_test, sizeof(g_test), NULL);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_ARG);

    ret = bfelf_file_init((char *)&g_test, sizeof(g_test), &m_test_elf);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_EI_MAG0);
    g_test.header.e_ident[bfei_mag0] = 0x7F;

    ret = bfelf_file_init((char *)&g_test, sizeof(g_test), &m_test_elf);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_EI_MAG1);
    g_test.header.e_ident[bfei_mag1] = 'E';

    ret = bfelf_file_init((char *)&g_test, sizeof(g_test), &m_test_elf);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_EI_MAG2);
    g_test.header.e_ident[bfei_mag2] = 'L';

    ret = bfelf_file_init((char *)&g_test, sizeof(g_test), &m_test_elf);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_EI_MAG3);
    g_test.header.e_ident[bfei_mag3] = 'F';

    ret = bfelf_file_init((char *)&g_test, sizeof(g_test), &m_test_elf);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_EI_CLASS);
    g_test.header.e_ident[bfei_class] = bfelfclass64;

    ret = bfelf_file_init((char *)&g_test, sizeof(g_test), &m_test_elf);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_EI_DATA);
    g_test.header.e_ident[bfei_data] = bfelfdata2lsb;

    ret = bfelf_file_init((char *)&g_test, sizeof(g_test), &m_test_elf);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_EI_VERSION);
    g_test.header.e_ident[bfei_version] = bfev_current;

    g_test.header.e_ident[bfei_osabi] = 1;
    ret = bfelf_file_init((char *)&g_test, sizeof(g_test), &m_test_elf);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_EI_OSABI);
    g_test.header.e_ident[bfei_osabi] = bfelfosabi_sysv;

    g_test.header.e_ident[bfei_abiversion] = 1;
    ret = bfelf_file_init((char *)&g_test, sizeof(g_test), &m_test_elf);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_EI_ABIVERSION);
    g_test.header.e_ident[bfei_abiversion] = 0;

    ret = bfelf_file_init((char *)&g_test, sizeof(g_test), &m_test_elf);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_E_TYPE);
    g_test.header.e_type = bfet_dyn;

    ret = bfelf_file_init((char *)&g_test, sizeof(g_test), &m_test_elf);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_E_MACHINE);
    g_test.header.e_machine = bfem_x86_64;

    ret = bfelf_file_init((char *)&g_test, sizeof(g_test), &m_test_elf);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_EI_VERSION);
    g_test.header.e_version = bfev_current;

    g_test.header.e_entry = -1;
    ret = bfelf_file_init((char *)&g_test, sizeof(g_test), &m_test_elf);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_E_ENTRY);
    g_test.header.e_entry = 10000000;
    ret = bfelf_file_init((char *)&g_test, sizeof(g_test), &m_test_elf);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_E_ENTRY);
    g_test.header.e_entry = 10;

    g_test.header.e_phoff = -1;
    ret = bfelf_file_init((char *)&g_test, sizeof(g_test), &m_test_elf);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_E_PHOFF);
    g_test.header.e_phoff = 10000000;
    ret = bfelf_file_init((char *)&g_test, sizeof(g_test), &m_test_elf);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_E_PHOFF);
    g_test.header.e_phoff = (bfelf64_off)&g_test.phdr1 - (bfelf64_off)&g_test;

    g_test.header.e_shoff = -1;
    ret = bfelf_file_init((char *)&g_test, sizeof(g_test), &m_test_elf);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_E_SHOFF);
    g_test.header.e_shoff = 10000000;
    ret = bfelf_file_init((char *)&g_test, sizeof(g_test), &m_test_elf);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_E_SHOFF);
    g_test.header.e_shoff = (bfelf64_off)&g_test.shdr1 - (bfelf64_off)&g_test;

    g_test.header.e_flags = 1;
    ret = bfelf_file_init((char *)&g_test, sizeof(g_test), &m_test_elf);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_E_FLAGS);
    g_test.header.e_flags = 0;

    ret = bfelf_file_init((char *)&g_test, sizeof(g_test), &m_test_elf);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_E_EHSIZE);
    g_test.header.e_ehsize = sizeof(struct bfelf64_ehdr);

    ret = bfelf_file_init((char *)&g_test, sizeof(g_test), &m_test_elf);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_E_PHENTSIZE);
    g_test.header.e_phentsize = sizeof(struct bfelf_phdr);

    ret = bfelf_file_init((char *)&g_test, sizeof(g_test), &m_test_elf);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_E_SHENTSIZE);
    g_test.header.e_shentsize = sizeof(struct bfelf_shdr);

    g_test.header.e_phnum = 2;
    g_test.header.e_shnum = 4;

    g_test.header.e_shstrndx = 10;
    ret = bfelf_file_init((char *)&g_test, sizeof(g_test), &m_test_elf);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_E_SHSTRNDX);
    g_test.header.e_shstrndx = 0;

    g_test.header.e_phnum = 16000;
    ret = bfelf_file_init((char *)&g_test, sizeof(g_test), &m_test_elf);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_PHT);
    g_test.header.e_phnum = 2;

    g_test.header.e_shnum = 5;
    ret = bfelf_file_init((char *)&g_test, sizeof(g_test), &m_test_elf);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_SHT);
    g_test.header.e_shnum = 4;

    g_test.shdr1.sh_offset = 16000;
    ret = bfelf_file_init((char *)&g_test, sizeof(g_test), &m_test_elf);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_SH_SIZE);
    g_test.shdr1.sh_offset = (bfelf64_off)&g_test.strtab - (bfelf64_off)&g_test;

    g_test.shdr1.sh_size = 16000;
    ret = bfelf_file_init((char *)&g_test, sizeof(g_test), &m_test_elf);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_SH_SIZE);
    g_test.shdr1.sh_size = sizeof(g_test.strtab);

    g_test.shdr1.sh_offset = (bfelf64_off)&g_test.strtab - (bfelf64_off)&g_test;
    g_test.shdr2.sh_offset = (bfelf64_off)&g_test.symtab - (bfelf64_off)&g_test;
    g_test.shdr3.sh_offset = (bfelf64_off)&g_test.reltab - (bfelf64_off)&g_test;
    g_test.shdr4.sh_offset = (bfelf64_off)&g_test.relatab - (bfelf64_off)&g_test;
    g_test.shdr1.sh_size = sizeof(g_test.strtab);
    g_test.shdr2.sh_size = sizeof(g_test.symtab);
    g_test.shdr3.sh_size = sizeof(g_test.reltab);
    g_test.shdr4.sh_size = sizeof(g_test.relatab);

    g_test.phdr1.p_offset = 16000;
    ret = bfelf_file_init((char *)&g_test, sizeof(g_test), &m_test_elf);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_PH_FILESZ);
    g_test.phdr1.p_offset = (bfelf64_off)&g_test.strtab - (bfelf64_off)&g_test;

    g_test.phdr1.p_memsz = 16000;
    g_test.phdr1.p_filesz = 16000;
    ret = bfelf_file_init((char *)&g_test, sizeof(g_test), &m_test_elf);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_PH_FILESZ);
    g_test.phdr1.p_filesz = sizeof(g_test.strtab) + sizeof(g_test.symtab);

    g_test.phdr1.p_memsz = 1;
    ret = bfelf_file_init((char *)&g_test, sizeof(g_test), &m_test_elf);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_PH_FILESZ);
    g_test.phdr1.p_memsz = g_test.phdr1.p_filesz;

    g_test.phdr1.p_offset = (bfelf64_off)&g_test.strtab - (bfelf64_off)&g_test;
    g_test.phdr1.p_filesz = sizeof(g_test.strtab) + sizeof(g_test.symtab);
    g_test.phdr1.p_memsz = g_test.phdr1.p_filesz;
    g_test.phdr1.p_vaddr = g_test.phdr1.p_offset;

    g_test.phdr2.p_offset = (bfelf64_off)&g_test.reltab - (bfelf64_off)&g_test;
    g_test.phdr2.p_filesz = sizeof(g_test.reltab) + sizeof(g_test.relatab);
    g_test.phdr2.p_memsz = g_test.phdr2.p_filesz + 300;
    g_test.phdr2.p_vaddr = g_test.phdr2.p_offset;

    ret = bfelf_file_init((char *)&g_test, sizeof(g_test), &m_test_elf);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_FILE);
    g_test.shdr2.sh_type = bfsht_dynsym;

    g_test.shdr2.sh_link = 16000;
    ret = bfelf_file_init((char *)&g_test, sizeof(g_test), &m_test_elf);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_INDEX);
    g_test.shdr2.sh_link = 0;

    ret = bfelf_file_init((char *)&g_test, sizeof(g_test), &m_test_elf);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_SH_TYPE);

    g_test.shdr1.sh_type = bfsht_strtab;
    g_test.shdr2.sh_type = bfsht_dynsym;
    g_test.shdr3.sh_type = bfsht_rel;
    g_test.shdr4.sh_type = bfsht_rela;

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

    g_test.reltab[0].r_offset = (bfelf64_addr)g_test.tmp - (bfelf64_addr)&g_test;
    g_test.reltab[0].r_info = BFR_X86_64_GLOB_DAT;
    g_test.reltab[1].r_offset = (bfelf64_addr)g_test.tmp - (bfelf64_addr)&g_test;
    g_test.reltab[1].r_info = BFR_X86_64_JUMP_SLOT;

    g_test.relatab[0].r_offset = (bfelf64_addr)g_test.tmp - (bfelf64_addr)&g_test;
    g_test.relatab[0].r_info = BFR_X86_64_GLOB_DAT;
    g_test.relatab[1].r_offset = (bfelf64_addr)g_test.tmp - (bfelf64_addr)&g_test;
    g_test.relatab[1].r_info = BFR_X86_64_64;

    ret = bfelf_file_init((char *)&g_test, sizeof(g_test), &m_test_elf);
    ASSERT_TRUE(ret == BFELF_SUCCESS);
    ret = bfelf_file_init((char *)&g_test, sizeof(g_test), &m_test_elf);
    ASSERT_TRUE(ret == BFELF_SUCCESS);

    ret = bfelf_file_init(m_dummy1, m_dummy1_length, &m_dummy1_ef);
    ASSERT_TRUE(ret == BFELF_SUCCESS);
    ret = bfelf_file_init(m_dummy2, m_dummy2_length, &m_dummy2_ef);
    ASSERT_TRUE(ret == BFELF_SUCCESS);
    ret = bfelf_file_init(m_dummy3, m_dummy3_length, &m_dummy3_ef);
    ASSERT_TRUE(ret == BFELF_SUCCESS);

}

void bfelf_loader_ut::test_bfelf_file_size()
{
    m_test_esize = bfelf_total_exec_size(NULL);
    ASSERT_TRUE(m_test_esize == BFELF_ERROR_INVALID_ARG);

    m_test_elf.valid = BFELF_FALSE;
    m_test_esize = bfelf_total_exec_size(&m_test_elf);
    ASSERT_TRUE(m_test_esize == BFELF_ERROR_INVALID_FILE);
    m_test_elf.valid = BFELF_TRUE;

    m_test_esize = bfelf_total_exec_size(&m_test_elf);
    ASSERT_TRUE(m_test_esize > BFELF_SUCCESS);

    m_test_exec = alloc_exec(m_test_esize);
    ASSERT_TRUE(m_test_exec != NULL);

    m_dummy1_esize = bfelf_total_exec_size(&m_dummy1_ef);
    ASSERT_TRUE(m_dummy1_esize > BFELF_SUCCESS);
    m_dummy2_esize = bfelf_total_exec_size(&m_dummy2_ef);
    ASSERT_TRUE(m_dummy2_esize > BFELF_SUCCESS);
    m_dummy3_esize = bfelf_total_exec_size(&m_dummy3_ef);
    ASSERT_TRUE(m_dummy3_esize > BFELF_SUCCESS);

    m_dummy1_exec = alloc_exec(m_dummy1_esize);
    ASSERT_TRUE(m_dummy1_exec != NULL);
    m_dummy2_exec = alloc_exec(m_dummy2_esize);
    ASSERT_TRUE(m_dummy2_exec != NULL);
    m_dummy3_exec = alloc_exec(m_dummy3_esize);
    ASSERT_TRUE(m_dummy3_exec != NULL);
}

void bfelf_loader_ut::test_bfelf_file_load()
{
    auto ret = 0;

    ret = bfelf_file_load(NULL, m_test_exec, m_test_esize);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_ARG);

    ret = bfelf_file_load(&m_test_elf, NULL, m_test_esize);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_ARG);

    ret = bfelf_file_load(&m_test_elf, m_test_exec, 10);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_ARG);

    m_test_elf.valid = BFELF_FALSE;
    ret = bfelf_file_load(&m_test_elf, m_test_exec, m_test_esize);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_FILE);
    m_test_elf.valid = BFELF_TRUE;

    ret = bfelf_file_load(&m_test_elf, m_test_exec, 1000000);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_ARG);

    ret = bfelf_file_load(&m_test_elf, m_test_exec, m_test_esize);
    ASSERT_TRUE(ret == BFELF_SUCCESS);
    ret = bfelf_file_load(&m_test_elf, m_test_exec, m_test_esize);
    ASSERT_TRUE(ret == BFELF_SUCCESS);

    ret = bfelf_file_load(&m_dummy1_ef, m_dummy1_exec, m_dummy1_esize);
    ASSERT_TRUE(ret == BFELF_SUCCESS);
    ret = bfelf_file_load(&m_dummy2_ef, m_dummy2_exec, m_dummy2_esize);
    ASSERT_TRUE(ret == BFELF_SUCCESS);
    ret = bfelf_file_load(&m_dummy3_ef, m_dummy3_exec, m_dummy3_esize);
    ASSERT_TRUE(ret == BFELF_SUCCESS);
}

void bfelf_loader_ut::test_bfelf_loader_init()
{
    auto ret = 0;

    ret = bfelf_loader_init(NULL);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_ARG);

    ret = bfelf_loader_init(&m_test_loader);
    ASSERT_TRUE(ret == BFELF_SUCCESS);

    ret = bfelf_loader_init(&m_loader);
    ASSERT_TRUE(ret == BFELF_SUCCESS);
}

void bfelf_loader_ut::test_bfelf_loader_add()
{
    auto ret = 0;

    ret = bfelf_loader_add(NULL, &m_dummy1_ef);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_ARG);

    ret = bfelf_loader_add(&m_test_loader, NULL);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_ARG);

    m_test_elf.valid = BFELF_FALSE;
    ret = bfelf_loader_add(&m_test_loader, &m_test_elf);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_FILE);
    m_test_elf.valid = BFELF_TRUE;

    for (auto i = 0; i < BFELF_MAX_MODULES + 1; i++)
        ret = bfelf_loader_add(&m_test_loader, &m_test_elf);
    ASSERT_TRUE(ret == BFELF_ERROR_LOADER_FULL);

    ret = bfelf_loader_init(&m_test_loader);
    ASSERT_TRUE(ret == BFELF_SUCCESS);
    ret = bfelf_loader_add(&m_test_loader, &m_test_elf);
    ASSERT_TRUE(ret == BFELF_SUCCESS);

    ret = bfelf_loader_add(&m_loader, &m_dummy1_ef);
    ASSERT_TRUE(ret == BFELF_SUCCESS);
    ret = bfelf_loader_add(&m_loader, &m_dummy2_ef);
    ASSERT_TRUE(ret == BFELF_SUCCESS);
    ret = bfelf_loader_add(&m_loader, &m_dummy3_ef);
    ASSERT_TRUE(ret == BFELF_SUCCESS);
}

void bfelf_loader_ut::test_bfelf_loader_relocate()
{
    auto ret = 0;

    ret = bfelf_loader_relocate(NULL);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_ARG);

    m_test_loader.num = 1000;
    ret = bfelf_loader_relocate(&m_test_loader);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_LOADER);
    m_test_loader.num = 1;

    ret = bfelf_loader_relocate(&m_test_loader);
    ASSERT_TRUE(ret == BFELF_SUCCESS);
    ret = bfelf_loader_relocate(&m_test_loader);
    ASSERT_TRUE(ret == BFELF_SUCCESS);

    ret = bfelf_loader_relocate(&m_loader);
    ASSERT_TRUE(ret == BFELF_SUCCESS);
}

void bfelf_loader_ut::test_bfelf_section_header()
{
    auto ret = 0;
    struct bfelf_shdr *shdr = 0;
    struct bfelf_file_t tmp_elf = {};

    ret = bfelf_section_header(NULL, 0, &shdr);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_ARG);

    ret = bfelf_section_header(&m_test_elf, 0, NULL);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_ARG);

    ret = bfelf_section_header(&tmp_elf, 0, NULL);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_ARG);

    tmp_elf.ehdr = m_test_elf.ehdr;
    ret = bfelf_section_header(&tmp_elf, 0, NULL);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_ARG);

    ret = bfelf_section_header(&m_test_elf, 100, &shdr);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_INDEX);

    ret = bfelf_section_header(&m_test_elf, 0, &shdr);
    ASSERT_TRUE(ret == BFELF_SUCCESS);
}

void bfelf_loader_ut::test_bfelf_string_table_entry()
{
    auto ret = 0;
    struct e_string_t str = {};

    ret = bfelf_string_table_entry(NULL, m_test_elf.strtab, 0, &str);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_ARG);

    ret = bfelf_string_table_entry(&m_test_elf, NULL, 0, &str);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_ARG);

    ret = bfelf_string_table_entry(&m_test_elf, m_test_elf.strtab, 0, NULL);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_ARG);

    m_test_elf.valid = BFELF_FALSE;
    ret = bfelf_string_table_entry(&m_test_elf, m_test_elf.strtab, 0, &str);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_FILE);
    m_test_elf.valid = BFELF_TRUE;

    ret = bfelf_string_table_entry(&m_test_elf, m_test_elf.strtab, 100, &str);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_OFFSET);

    g_test.strtab[11] = 'a';
    ret = bfelf_string_table_entry(&m_test_elf, m_test_elf.strtab, 6, &str);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_STRING_TABLE);
    g_test.strtab[11] = '\0';

    ret = bfelf_string_table_entry(&m_test_elf, m_test_elf.strtab, 0, &str);
    ASSERT_TRUE(ret == BFELF_SUCCESS);
    ASSERT_TRUE(str.buf[0] == 'h');
    ASSERT_TRUE(str.len == 5);

    ret = bfelf_string_table_entry(&m_test_elf, m_test_elf.strtab, 6, &str);
    ASSERT_TRUE(ret == BFELF_SUCCESS);
    ASSERT_TRUE(str.buf[0] == 'w');
    ASSERT_TRUE(str.len == 5);
}

void bfelf_loader_ut::test_bfelf_section_name_string()
{
    auto ret = 0;
    struct e_string_t str = {};

    ret = bfelf_section_name_string(NULL, &g_test.shdr1, &str);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_ARG);

    ret = bfelf_section_name_string(&m_test_elf, NULL, &str);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_ARG);

    ret = bfelf_section_name_string(&m_test_elf, &g_test.shdr1, NULL);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_ARG);

    m_test_elf.valid = BFELF_FALSE;
    ret = bfelf_section_name_string(&m_test_elf, &g_test.shdr1, &str);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_FILE);
    m_test_elf.valid = BFELF_TRUE;

    ret = bfelf_section_name_string(&m_test_elf, &g_test.shdr1, &str);
    ASSERT_TRUE(ret == BFELF_SUCCESS);
    ASSERT_TRUE(str.buf[0] == 'h');
}

void bfelf_loader_ut::test_bfelf_symbol_by_index()
{
    auto ret = 0;
    struct bfelf_sym *sym = 0;

    ret = bfelf_symbol_by_index(NULL, 0, &sym);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_ARG);

    ret = bfelf_symbol_by_index(&m_test_elf, 0, NULL);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_ARG);

    ret = bfelf_symbol_by_index(&m_test_elf, 3, &sym);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_INDEX);

    m_test_elf.valid = BFELF_FALSE;
    ret = bfelf_symbol_by_index(&m_test_elf, 0, &sym);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_FILE);
    m_test_elf.valid = BFELF_TRUE;

    ret = bfelf_symbol_by_index(&m_test_elf, 0, &sym);
    ASSERT_TRUE(ret == BFELF_SUCCESS);
}

void bfelf_loader_ut::test_bfelf_symbol_by_name()
{
    auto ret = 0;
    struct bfelf_sym *sym = 0;
    struct e_string_t str = {};

    ret = bfelf_symbol_by_name(NULL, &str, &sym);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_ARG);

    ret = bfelf_symbol_by_name(&m_test_elf, NULL, &sym);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_ARG);

    ret = bfelf_symbol_by_name(&m_test_elf, &str, NULL);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_ARG);

    m_test_elf.valid = BFELF_FALSE;
    ret = bfelf_symbol_by_name(&m_test_elf, &str, &sym);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_FILE);
    m_test_elf.valid = BFELF_TRUE;

    ret = bfelf_symbol_by_name(&m_test_elf, &str, &sym);
    ASSERT_TRUE(ret == BFELF_ERROR_NO_SUCH_SYMBOL);

    ret = bfelf_string_table_entry(&m_test_elf, m_test_elf.strtab, 0, &str);
    ASSERT_TRUE(ret == BFELF_SUCCESS);

    ret = bfelf_symbol_by_name(&m_test_elf, &str, &sym);
    ASSERT_TRUE(ret == BFELF_SUCCESS);
}

void bfelf_loader_ut::test_bfelf_symbol_by_name_global()
{
    auto ret = 0;
    struct bfelf_sym *sym = 0;
    struct e_string_t str = {};
    struct bfelf_file_t *efr = 0;

    ret = bfelf_symbol_by_name_global(NULL, &str, &efr, &sym);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_ARG);

    ret = bfelf_symbol_by_name_global(&m_test_elf, NULL, &efr, &sym);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_ARG);

    ret = bfelf_symbol_by_name_global(&m_test_elf, &str, NULL, &sym);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_ARG);

    ret = bfelf_symbol_by_name_global(&m_test_elf, &str, &efr, NULL);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_ARG);

    m_test_elf.valid = BFELF_FALSE;
    ret = bfelf_symbol_by_name_global(&m_test_elf, &str, &efr, &sym);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_FILE);
    m_test_elf.valid = BFELF_TRUE;

    ret = bfelf_symbol_by_name_global(&m_test_elf, &str, &efr, &sym);
    ASSERT_TRUE(ret == BFELF_ERROR_NO_SUCH_SYMBOL);

    ret = bfelf_string_table_entry(&m_test_elf, m_test_elf.strtab, 0, &str);
    ASSERT_TRUE(ret == BFELF_SUCCESS);

    g_test.symtab[0].st_value = 0x0;
    ret = bfelf_symbol_by_name_global(&m_test_elf, &str, &efr, &sym);
    ASSERT_TRUE(ret == BFELF_ERROR_NO_SUCH_SYMBOL);
    g_test.symtab[0].st_value = 0x10;

    ret = bfelf_symbol_by_name_global(&m_test_elf, &str, &efr, &sym);
    ASSERT_TRUE(ret == BFELF_SUCCESS);
    ASSERT_TRUE(efr == &m_test_elf);
}

void bfelf_loader_ut::test_bfelf_resolve_symbol()
{
    auto ret = 0;
    void *addr = 0;
    struct e_string_t str = {};

    ret = bfelf_resolve_symbol(NULL, &str, &addr);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_ARG);

    ret = bfelf_resolve_symbol(&m_test_elf, NULL, &addr);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_ARG);

    ret = bfelf_resolve_symbol(&m_test_elf, &str, NULL);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_ARG);

    m_test_elf.valid = BFELF_FALSE;
    ret = bfelf_resolve_symbol(&m_test_elf, &str, &addr);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_FILE);
    m_test_elf.valid = BFELF_TRUE;

    ret = bfelf_resolve_symbol(&m_test_elf, &str, &addr);
    ASSERT_TRUE(ret == BFELF_ERROR_NO_SUCH_SYMBOL);

    ret = bfelf_string_table_entry(&m_test_elf, m_test_elf.strtab, 0, &str);
    ASSERT_TRUE(ret == BFELF_SUCCESS);

    ret = bfelf_resolve_symbol(&m_test_elf, &str, &addr);
    ASSERT_TRUE(ret == BFELF_SUCCESS);
}

void bfelf_loader_ut::test_bfelf_relocate_symbol()
{
    auto ret = 0;

    ret = bfelf_relocate_symbol(NULL, &(g_test.reltab[0]));
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_ARG);

    ret = bfelf_relocate_symbol(&m_test_elf, NULL);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_ARG);

    m_test_elf.valid = BFELF_FALSE;
    ret = bfelf_relocate_symbol(&m_test_elf, &(g_test.reltab[0]));
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_FILE);
    m_test_elf.valid = BFELF_TRUE;

    g_test.reltab[0].r_info = 0xFFFFFFFFFFFFFFFF;
    ret = bfelf_relocate_symbol(&m_test_elf, &(g_test.reltab[0]));
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_INDEX);
    g_test.reltab[0].r_info = 0;

    g_test.reltab[0].r_offset = 1000000;
    ret = bfelf_relocate_symbol(&m_test_elf, &(g_test.reltab[0]));
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_FILE);
    g_test.reltab[0].r_offset = (bfelf64_addr)g_test.tmp - (bfelf64_addr)&g_test;

    g_test.reltab[0].r_info = 100;
    ret = bfelf_relocate_symbol(&m_test_elf, &(g_test.reltab[0]));
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_RELOCATION_TYPE);
    g_test.reltab[0].r_info = BFR_X86_64_GLOB_DAT;

    ret = bfelf_relocate_symbol(&m_test_elf, &(g_test.reltab[0]));
    ASSERT_TRUE(ret == BFELF_SUCCESS);
}

void bfelf_loader_ut::test_bfelf_relocate_symbol_addend()
{
    auto ret = 0;

    ret = bfelf_relocate_symbol_addend(NULL, &(g_test.relatab[0]));
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_ARG);

    ret = bfelf_relocate_symbol_addend(&m_test_elf, NULL);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_ARG);

    m_test_elf.valid = BFELF_FALSE;
    ret = bfelf_relocate_symbol_addend(&m_test_elf, &(g_test.relatab[0]));
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_FILE);
    m_test_elf.valid = BFELF_TRUE;

    g_test.relatab[0].r_info = 0xFFFFFFFFFFFFFFFF;
    ret = bfelf_relocate_symbol_addend(&m_test_elf, &(g_test.relatab[0]));
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_INDEX);
    g_test.relatab[0].r_info = 0;

    g_test.relatab[0].r_offset = 1000000;
    ret = bfelf_relocate_symbol_addend(&m_test_elf, &(g_test.relatab[0]));
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_FILE);
    g_test.relatab[0].r_offset = (bfelf64_addr)g_test.tmp - (bfelf64_addr)&g_test;

    g_test.relatab[0].r_info = 100;
    ret = bfelf_relocate_symbol_addend(&m_test_elf, &(g_test.relatab[0]));
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_RELOCATION_TYPE);
    g_test.relatab[0].r_info = BFR_X86_64_GLOB_DAT;

    ret = bfelf_relocate_symbol_addend(&m_test_elf, &(g_test.relatab[0]));
    ASSERT_TRUE(ret == BFELF_SUCCESS);
}

void bfelf_loader_ut::test_bfelf_relocate_symbols()
{
    auto ret = 0;

    ret = bfelf_relocate_symbols(NULL);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_ARG);

    m_test_elf.valid = BFELF_FALSE;
    ret = bfelf_relocate_symbols(&m_test_elf);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_FILE);
    m_test_elf.valid = BFELF_TRUE;

    ret = bfelf_relocate_symbols(&m_test_elf);
    ASSERT_TRUE(ret == BFELF_SUCCESS);
}

void bfelf_loader_ut::test_bfelf_program_header()
{
    auto ret = 0;
    struct bfelf_phdr *phdr = 0;
    struct bfelf_file_t tmp_elf = {};

    ret = bfelf_program_header(NULL, 0, &phdr);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_ARG);

    ret = bfelf_program_header(&m_test_elf, 0, NULL);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_ARG);

    ret = bfelf_program_header(&tmp_elf, 0, NULL);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_ARG);

    tmp_elf.ehdr = m_test_elf.ehdr;
    ret = bfelf_program_header(&tmp_elf, 0, NULL);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_ARG);

    ret = bfelf_program_header(&m_test_elf, 100, &phdr);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_INDEX);

    ret = bfelf_program_header(&m_test_elf, 0, &phdr);
    ASSERT_TRUE(ret == BFELF_SUCCESS);
}

void bfelf_loader_ut::test_bfelf_load_segments()
{
    auto ret = 0;

    ret = bfelf_load_segments(NULL);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_ARG);

    m_test_elf.valid = BFELF_FALSE;
    ret = bfelf_load_segments(&m_test_elf);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_FILE);
    m_test_elf.valid = BFELF_TRUE;

    ret = bfelf_load_segments(&m_test_elf);
    ASSERT_TRUE(ret == BFELF_SUCCESS);
}

void bfelf_loader_ut::test_bfelf_load_segment()
{
    auto ret = 0;

    ret = bfelf_load_segment(NULL, &g_test.phdr1);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_ARG);

    ret = bfelf_load_segment(&m_test_elf, NULL);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_ARG);

    m_test_elf.valid = BFELF_FALSE;
    ret = bfelf_load_segment(&m_test_elf, &g_test.phdr1);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_FILE);
    m_test_elf.valid = BFELF_TRUE;

    g_test.phdr1.p_memsz = 1000000;
    ret = bfelf_load_segment(&m_test_elf, &g_test.phdr1);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_PH_MEMSZ);
    g_test.phdr1.p_memsz = g_test.phdr1.p_filesz;

    ret = bfelf_load_segment(&m_test_elf, &g_test.phdr1);
    ASSERT_TRUE(ret == BFELF_SUCCESS);
}

void bfelf_loader_ut::test_bfelf_file_print_header()
{
    auto ret = 0;

    ret = bfelf_file_print_header(&m_dummy3_ef);
    ASSERT_TRUE(ret == BFELF_SUCCESS);
}

void bfelf_loader_ut::test_bfelf_print_section_header_table()
{
    auto ret = 0;

    ret = bfelf_print_section_header_table(&m_dummy3_ef);
    ASSERT_TRUE(ret == BFELF_SUCCESS);
}

void bfelf_loader_ut::test_bfelf_print_program_header_table()
{
    auto ret = 0;

    ret = bfelf_print_program_header_table(&m_dummy3_ef);
    ASSERT_TRUE(ret == BFELF_SUCCESS);
}

void bfelf_loader_ut::test_bfelf_print_sym_table()
{
    auto ret = 0;

    ret = bfelf_print_sym_table(&m_dummy1_ef);
    ASSERT_TRUE(ret == BFELF_SUCCESS);

    ret = bfelf_print_sym_table(&m_dummy2_ef);
    ASSERT_TRUE(ret == BFELF_SUCCESS);

    ret = bfelf_print_sym_table(&m_dummy3_ef);
    ASSERT_TRUE(ret == BFELF_SUCCESS);
}

void bfelf_loader_ut::test_bfelf_print_relocations()
{
    auto ret = 0;

    ret = bfelf_print_relocations(&m_dummy1_ef);
    ASSERT_TRUE(ret == BFELF_SUCCESS);

    ret = bfelf_print_relocations(&m_dummy2_ef);
    ASSERT_TRUE(ret == BFELF_SUCCESS);

    ret = bfelf_print_relocations(&m_dummy3_ef);
    ASSERT_TRUE(ret == BFELF_SUCCESS);
}

void bfelf_loader_ut::test_resolve()
{
    auto ret = 0;
    void *entry1 = 0;
    void *entry2 = 0;
    struct e_string_t str1 = {"exec_ms64tosv64", 15};
    struct e_string_t str2 = {"_Z12dummy3_test2i", 17};

    ret = bfelf_resolve_symbol(&m_dummy3_ef, &str1, &entry1);
    EXPECT_TRUE(ret == BFELF_SUCCESS);

    if (ret != BFELF_SUCCESS)
    {
        std::cout << std::endl;
        std::cout << "Error: " << bfelf_error(ret) << std::endl;
        std::cout << std::endl;

        return;
    }

    ret = bfelf_resolve_symbol(&m_dummy3_ef, &str2, &entry2);
    EXPECT_TRUE(ret == BFELF_SUCCESS);

    if (ret != BFELF_SUCCESS)
    {
        std::cout << std::endl;
        std::cout << "Error: " << bfelf_error(ret) << std::endl;
        std::cout << std::endl;

        return;
    }

#if defined(__CYGWIN__) && !defined(_WIN32)

    exec_ms64tosv64_t exec_ms64tosv64 = (exec_ms64tosv64_t)entry1;

    std::cout << std::endl;
    std::cout << "Result: " << exec_ms64tosv64(entry2, 5) << std::endl;
    std::cout << std::endl;

#else

    entry_point_t entry_point = (entry_point_t)entry2;

    std::cout << std::endl;
    std::cout << "Result: " << entry_point(5) << std::endl;
    std::cout << std::endl;

#endif

}

int
main(int argc, char *argv[])
{
    return RUN_ALL_TESTS(bfelf_loader_ut);
}
