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

const auto c_dummy_misc_filename = "../cross/libdummy_misc.so";
const auto c_dummy_code_filename = "../cross/libdummy_code.so";

struct bfelf_test
{
    bfelf64_ehdr header;
    bfelf_phdr phdr1;
    bfelf_phdr phdr2;
    char tmp[16];
    char strtab[12];
    void *ctors[2];
    void *dtors[2];
    void *init_array[2];
    void *fini_array[2];
    bfelf_sym symtab[2];
    bfelf_rel reltab[2];
    bfelf_rela relatab[2];
    bfelf_shdr shdr1;
    bfelf_shdr shdr2;
    bfelf_shdr shdr3;
    bfelf_shdr shdr4;
    bfelf_shdr shdr5;
    bfelf_shdr shdr6;
};

bfelf_test g_test = {};

bfelf_loader_ut::bfelf_loader_ut() :
    m_dummy_misc(0),
    m_dummy_code(0),
    m_dummy_misc_length(0),
    m_dummy_code_length(0),
    m_dummy_misc_exec(0),
    m_dummy_code_exec(0),
    m_dummy_misc_esize(0),
    m_dummy_code_esize(0),
    m_test_exec(0),
    m_test_esize(0)
{
}

bool bfelf_loader_ut::init()
{
    auto result = false;

    std::ifstream dummy_misc_ifs(c_dummy_misc_filename, std::ifstream::ate);
    std::ifstream dummy_code_ifs(c_dummy_code_filename, std::ifstream::ate);

    if (dummy_misc_ifs.is_open() == false ||
        dummy_code_ifs.is_open() == false)
    {
        std::cout << "unable to open one or more dummy libraries: " << std::endl;
        std::cout << "    - dummy_misc: " << dummy_misc_ifs.is_open() << std::endl;
        std::cout << "    - dummy_code: " << dummy_code_ifs.is_open() << std::endl;
        goto close;
    }

    m_dummy_misc_length = dummy_misc_ifs.tellg();
    m_dummy_code_length = dummy_code_ifs.tellg();

    if (m_dummy_misc_length == 0 ||
        m_dummy_code_length == 0)
    {
        std::cout << "one or more of the dummy libraries is empty: " << std::endl;
        std::cout << "    - dummy_misc: " << m_dummy_misc_length << std::endl;
        std::cout << "    - dummy_code: " << m_dummy_code_length << std::endl;
        goto close;
    }

    m_dummy_misc = new char[dummy_misc_ifs.tellg()];
    m_dummy_code = new char[dummy_code_ifs.tellg()];

    if (m_dummy_misc == NULL ||
        m_dummy_code == NULL)
    {
        std::cout << "unable to allocate space for one or more of the dummy libraries: " << std::endl;
        std::cout << "    - dummy_misc: " << (void *)m_dummy_misc << std::endl;
        std::cout << "    - dummy_code: " << (void *)m_dummy_code << std::endl;
        goto close;
    }

    dummy_misc_ifs.seekg(0);
    dummy_code_ifs.seekg(0);

    dummy_misc_ifs.read(m_dummy_misc, m_dummy_misc_length);
    dummy_code_ifs.read(m_dummy_code, m_dummy_code_length);

    if (dummy_misc_ifs.fail() == true ||
        dummy_code_ifs.fail() == true)
    {
        std::cout << "unable to load one or more dummy libraries into memory: " << std::endl;
        std::cout << "    - dummy_misc: " << dummy_misc_ifs.fail() << std::endl;
        std::cout << "    - dummy_code: " << dummy_code_ifs.fail() << std::endl;
        goto close;
    }

    result = true;

close:

    dummy_misc_ifs.close();
    dummy_code_ifs.close();

    return result;
}

bool bfelf_loader_ut::fini()
{
    if (m_dummy_misc != NULL)
        delete[] m_dummy_misc;

    if (m_dummy_code != NULL)
        delete[] m_dummy_code;

    if (m_dummy_misc_exec != NULL)
        munmap(m_dummy_misc_exec, m_dummy_misc_esize);

    if (m_dummy_code_exec != NULL)
        munmap(m_dummy_code_exec, m_dummy_code_esize);

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
    this->test_bfelf_ctor_num();
    this->test_bfelf_dtor_num();
    this->test_bfelf_resolve_ctor();
    this->test_bfelf_resolve_dtor();
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
    g_test.header.e_shnum = 6;

    g_test.header.e_shstrndx = 10;
    ret = bfelf_file_init((char *)&g_test, sizeof(g_test), &m_test_elf);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_E_SHSTRNDX);
    g_test.header.e_shstrndx = 0;

    g_test.header.e_phnum = 16000;
    ret = bfelf_file_init((char *)&g_test, sizeof(g_test), &m_test_elf);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_PHT);
    g_test.header.e_phnum = 2;

    g_test.header.e_shnum = 7;
    ret = bfelf_file_init((char *)&g_test, sizeof(g_test), &m_test_elf);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_SHT);
    g_test.header.e_shnum = 6;

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

    ret = bfelf_file_init(m_dummy_misc, m_dummy_misc_length, &m_dummy_misc_ef);
    ASSERT_TRUE(ret == BFELF_SUCCESS);
    ret = bfelf_file_init(m_dummy_code, m_dummy_code_length, &m_dummy_code_ef);
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

    m_dummy_misc_esize = bfelf_total_exec_size(&m_dummy_misc_ef);
    ASSERT_TRUE(m_dummy_misc_esize > BFELF_SUCCESS);
    m_dummy_code_esize = bfelf_total_exec_size(&m_dummy_code_ef);
    ASSERT_TRUE(m_dummy_code_esize > BFELF_SUCCESS);

    m_dummy_misc_exec = alloc_exec(m_dummy_misc_esize);
    ASSERT_TRUE(m_dummy_misc_exec != NULL);
    m_dummy_code_exec = alloc_exec(m_dummy_code_esize);
    ASSERT_TRUE(m_dummy_code_exec != NULL);
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

    ret = bfelf_file_load(&m_dummy_misc_ef, m_dummy_misc_exec, m_dummy_misc_esize);
    ASSERT_TRUE(ret == BFELF_SUCCESS);
    ret = bfelf_file_load(&m_dummy_code_ef, m_dummy_code_exec, m_dummy_code_esize);
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

    ret = bfelf_loader_add(NULL, &m_dummy_misc_ef);
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

    ret = bfelf_loader_add(&m_loader, &m_dummy_misc_ef);
    ASSERT_TRUE(ret == BFELF_SUCCESS);
    ret = bfelf_loader_add(&m_loader, &m_dummy_code_ef);
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

void bfelf_loader_ut::test_bfelf_ctor_num()
{
    auto ret = 0;

    ret = bfelf_ctor_num(NULL);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_ARG);

    m_test_elf.valid = BFELF_FALSE;
    ret = bfelf_ctor_num(&m_test_elf);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_FILE);
    m_test_elf.valid = BFELF_TRUE;

    ret = bfelf_ctor_num(&m_test_elf);
    ASSERT_TRUE(ret == 0);

    m_test_elf.ctors = &g_test.shdr5;
    g_test.shdr5.sh_size = 16;
    g_test.shdr5.sh_offset = (bfelf64_off)&g_test.ctors - (bfelf64_off)&g_test;
    g_test.ctors[0] = (void *)0x10;
    g_test.ctors[1] = (void *)0x20;

    ret = bfelf_ctor_num(&m_test_elf);
    ASSERT_TRUE(ret == 2);
}

void bfelf_loader_ut::test_bfelf_dtor_num()
{
    auto ret = 0;

    ret = bfelf_dtor_num(NULL);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_ARG);

    m_test_elf.valid = BFELF_FALSE;
    ret = bfelf_dtor_num(&m_test_elf);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_FILE);
    m_test_elf.valid = BFELF_TRUE;

    ret = bfelf_dtor_num(&m_test_elf);
    ASSERT_TRUE(ret == 0);

    m_test_elf.dtors = &g_test.shdr6;
    g_test.shdr6.sh_size = 16;
    g_test.shdr6.sh_offset = (bfelf64_off)&g_test.dtors - (bfelf64_off)&g_test;
    g_test.dtors[0] = (void *)0x10;
    g_test.dtors[1] = (void *)0x20;

    ret = bfelf_dtor_num(&m_test_elf);
    ASSERT_TRUE(ret == 2);
}

void bfelf_loader_ut::test_bfelf_resolve_ctor()
{
    auto ret = 0;
    void *addr = 0;

    ret = bfelf_resolve_ctor(NULL, 0, &addr);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_ARG);

    ret = bfelf_resolve_ctor(&m_test_elf, 0, 0);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_ARG);

    m_test_elf.valid = BFELF_FALSE;
    ret = bfelf_resolve_ctor(&m_test_elf, 0, &addr);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_FILE);
    m_test_elf.valid = BFELF_TRUE;

    ret = bfelf_resolve_ctor(&m_test_elf, 0, &addr);
    ASSERT_TRUE(ret == BFELF_SUCCESS);
    ASSERT_TRUE(addr == m_test_exec + 0x10);
}

void bfelf_loader_ut::test_bfelf_resolve_dtor()
{
    auto ret = 0;
    void *addr = 0;

    ret = bfelf_resolve_dtor(NULL, 0, &addr);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_ARG);

    ret = bfelf_resolve_dtor(&m_test_elf, 0, 0);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_ARG);

    m_test_elf.valid = BFELF_FALSE;
    ret = bfelf_resolve_dtor(&m_test_elf, 0, &addr);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_FILE);
    m_test_elf.valid = BFELF_TRUE;

    ret = bfelf_resolve_dtor(&m_test_elf, 0, &addr);
    ASSERT_TRUE(ret == BFELF_SUCCESS);
    ASSERT_TRUE(addr == m_test_exec + 0x10);
}

void bfelf_loader_ut::test_bfelf_init_num()
{
    auto ret = 0;

    ret = bfelf_init_num(NULL);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_ARG);

    m_test_elf.valid = BFELF_FALSE;
    ret = bfelf_init_num(&m_test_elf);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_FILE);
    m_test_elf.valid = BFELF_TRUE;

    ret = bfelf_init_num(&m_test_elf);
    ASSERT_TRUE(ret == 0);

    m_test_elf.init_array = &g_test.shdr5;
    g_test.shdr5.sh_size = 16;
    g_test.shdr5.sh_offset = (bfelf64_off)&g_test.init_array - (bfelf64_off)&g_test;
    g_test.init_array[0] = (void *)0x10;
    g_test.init_array[1] = (void *)0x20;

    ret = bfelf_init_num(&m_test_elf);
    ASSERT_TRUE(ret == 2);
}

void bfelf_loader_ut::test_bfelf_fini_num()
{
    auto ret = 0;

    ret = bfelf_fini_num(NULL);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_ARG);

    m_test_elf.valid = BFELF_FALSE;
    ret = bfelf_fini_num(&m_test_elf);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_FILE);
    m_test_elf.valid = BFELF_TRUE;

    ret = bfelf_fini_num(&m_test_elf);
    ASSERT_TRUE(ret == 0);

    m_test_elf.fini_array = &g_test.shdr6;
    g_test.shdr6.sh_size = 16;
    g_test.shdr6.sh_offset = (bfelf64_off)&g_test.fini_array - (bfelf64_off)&g_test;
    g_test.fini_array[0] = (void *)0x10;
    g_test.fini_array[1] = (void *)0x20;

    ret = bfelf_fini_num(&m_test_elf);
    ASSERT_TRUE(ret == 2);
}

void bfelf_loader_ut::test_bfelf_resolve_init()
{
    auto ret = 0;
    void *addr = 0;

    ret = bfelf_resolve_init(NULL, 0, &addr);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_ARG);

    ret = bfelf_resolve_init(&m_test_elf, 0, 0);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_ARG);

    m_test_elf.valid = BFELF_FALSE;
    ret = bfelf_resolve_init(&m_test_elf, 0, &addr);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_FILE);
    m_test_elf.valid = BFELF_TRUE;

    ret = bfelf_resolve_init(&m_test_elf, 0, &addr);
    ASSERT_TRUE(ret == BFELF_SUCCESS);
    ASSERT_TRUE(addr == m_test_exec + 0x10);
}

void bfelf_loader_ut::test_bfelf_resolve_fini()
{
    auto ret = 0;
    void *addr = 0;

    ret = bfelf_resolve_fini(NULL, 0, &addr);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_ARG);

    ret = bfelf_resolve_fini(&m_test_elf, 0, 0);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_ARG);

    m_test_elf.valid = BFELF_FALSE;
    ret = bfelf_resolve_fini(&m_test_elf, 0, &addr);
    ASSERT_TRUE(ret == BFELF_ERROR_INVALID_FILE);
    m_test_elf.valid = BFELF_TRUE;

    ret = bfelf_resolve_fini(&m_test_elf, 0, &addr);
    ASSERT_TRUE(ret == BFELF_SUCCESS);
    ASSERT_TRUE(addr == m_test_exec + 0x10);
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

    ret = bfelf_file_print_header(&m_dummy_misc_ef);
    ASSERT_TRUE(ret == BFELF_SUCCESS);

    ret = bfelf_file_print_header(&m_dummy_code_ef);
    ASSERT_TRUE(ret == BFELF_SUCCESS);
}

void bfelf_loader_ut::test_bfelf_print_section_header_table()
{
    auto ret = 0;

    ret = bfelf_print_section_header_table(&m_dummy_misc_ef);
    ASSERT_TRUE(ret == BFELF_SUCCESS);

    ret = bfelf_print_section_header_table(&m_dummy_code_ef);
    ASSERT_TRUE(ret == BFELF_SUCCESS);
}

void bfelf_loader_ut::test_bfelf_print_program_header_table()
{
    auto ret = 0;

    ret = bfelf_print_program_header_table(&m_dummy_misc_ef);
    ASSERT_TRUE(ret == BFELF_SUCCESS);

    ret = bfelf_print_program_header_table(&m_dummy_code_ef);
    ASSERT_TRUE(ret == BFELF_SUCCESS);
}

void bfelf_loader_ut::test_bfelf_print_sym_table()
{
    auto ret = 0;

    ret = bfelf_print_sym_table(&m_dummy_misc_ef);
    ASSERT_TRUE(ret == BFELF_SUCCESS);

    ret = bfelf_print_sym_table(&m_dummy_code_ef);
    ASSERT_TRUE(ret == BFELF_SUCCESS);
}

void bfelf_loader_ut::test_bfelf_print_relocations()
{
    auto ret = 0;

    ret = bfelf_print_relocations(&m_dummy_misc_ef);
    ASSERT_TRUE(ret == BFELF_SUCCESS);

    ret = bfelf_print_relocations(&m_dummy_code_ef);
    ASSERT_TRUE(ret == BFELF_SUCCESS);
}

void bfelf_loader_ut::test_resolve()
{
    auto ret = 0;
    entry_point_t entry_point;
    struct e_string_t str = {"foo", 3};

    for (auto i = 0; i < bfelf_ctor_num(&m_dummy_misc_ef); i++)
    {
        ctor_func func;

        ret = bfelf_resolve_ctor(&m_dummy_misc_ef, i, (void **)&func);
        ASSERT_TRUE(ret == BFELF_SUCCESS);

        func();
    }

    for (auto i = 0; i < bfelf_init_num(&m_dummy_misc_ef); i++)
    {
        init_func func;

        ret = bfelf_resolve_init(&m_dummy_misc_ef, i, (void **)&func);
        ASSERT_TRUE(ret == BFELF_SUCCESS);

        func();
    }

    ret = bfelf_resolve_symbol(&m_dummy_misc_ef, &str, (void **)&entry_point);
    EXPECT_TRUE(ret == BFELF_SUCCESS);

    if (ret != BFELF_SUCCESS)
    {
        std::cout << std::endl;
        std::cout << "Error: " << bfelf_error(ret) << std::endl;
        std::cout << std::endl;

        return;
    }

    std::cout << std::endl;
    std::cout << "Result: " << entry_point(5) << std::endl;
    std::cout << std::endl;

    for (auto i = 0; i < bfelf_fini_num(&m_dummy_misc_ef); i++)
    {
        fini_func func;

        ret = bfelf_resolve_fini(&m_dummy_misc_ef, i, (void **)&func);
        ASSERT_TRUE(ret == BFELF_SUCCESS);

        func();
    }

    for (auto i = 0; i < bfelf_dtor_num(&m_dummy_misc_ef); i++)
    {
        dtor_func func;

        ret = bfelf_resolve_dtor(&m_dummy_misc_ef, i, (void **)&func);
        ASSERT_TRUE(ret == BFELF_SUCCESS);

        func();
    }
}

int
main(int argc, char *argv[])
{
    return RUN_ALL_TESTS(bfelf_loader_ut);
}
