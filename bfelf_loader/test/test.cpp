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
#include <sys/mman.h>

const auto c_dummy_misc_filename = "../cross/libdummy_misc.so";
const auto c_dummy_code_filename = "../cross/libdummy_code.so";

bfelf_loader_ut::bfelf_loader_ut() :
    m_dummy_misc_length(0),
    m_dummy_code_length(0)
{
}

bool bfelf_loader_ut::init()
{
    std::ifstream dummy_misc_ifs(c_dummy_misc_filename, std::ifstream::ate);
    std::ifstream dummy_code_ifs(c_dummy_code_filename, std::ifstream::ate);

    m_dummy_misc_length = static_cast<uint64_t>(dummy_misc_ifs.tellg());
    m_dummy_code_length = static_cast<uint64_t>(dummy_code_ifs.tellg());

    m_dummy_misc = std::make_unique<char[]>(m_dummy_misc_length);
    m_dummy_code = std::make_unique<char[]>(m_dummy_code_length);

    dummy_misc_ifs.seekg(0);
    dummy_code_ifs.seekg(0);

    dummy_misc_ifs.read(m_dummy_misc.get(), static_cast<int64_t>(m_dummy_misc_length));
    dummy_code_ifs.read(m_dummy_code.get(), static_cast<int64_t>(m_dummy_code_length));

    return true;
}

bool bfelf_loader_ut::fini()
{
    return true;
}

bool bfelf_loader_ut::list()
{
    this->test_bfelf_file_init_success();
    this->test_bfelf_file_init_invalid_file_arg();
    this->test_bfelf_file_init_invalid_file_size_arg();
    this->test_bfelf_file_init_invalid_elf_file();
    this->test_bfelf_file_init_invalid_magic_0();
    this->test_bfelf_file_init_invalid_magic_1();
    this->test_bfelf_file_init_invalid_magic_2();
    this->test_bfelf_file_init_invalid_magic_3();
    this->test_bfelf_file_init_invalid_class();
    this->test_bfelf_file_init_invalid_data();
    this->test_bfelf_file_init_invalid_ident_version();
    this->test_bfelf_file_init_invalid_osabi();
    this->test_bfelf_file_init_invalid_abiversion();
    this->test_bfelf_file_init_invalid_type();
    this->test_bfelf_file_init_invalid_machine();
    this->test_bfelf_file_init_invalid_version();
    this->test_bfelf_file_init_invalid_flags();
    this->test_bfelf_file_init_invalid_header_size();
    this->test_bfelf_file_init_invalid_program_header_size();
    this->test_bfelf_file_init_invalid_section_header_size();
    this->test_bfelf_file_init_invalid_program_header_offset();
    this->test_bfelf_file_init_invalid_section_header_offset();
    this->test_bfelf_file_init_invalid_program_header_num();
    this->test_bfelf_file_init_invalid_section_header_num();
    this->test_bfelf_file_init_invalid_section_header_string_table_index();
    this->test_bfelf_file_init_invalid_segment_file_size();
    this->test_bfelf_file_init_invalid_segment_addresses();
    this->test_bfelf_file_init_invalid_segment_alignment();
    this->test_bfelf_file_init_invalid_segment_offset();
    this->test_bfelf_file_init_invalid_section_offset();
    this->test_bfelf_file_init_invalid_section_size();
    this->test_bfelf_file_init_invalid_section_name();
    this->test_bfelf_file_init_invalid_section_link();
    this->test_bfelf_file_init_invalid_segment_address();
    this->test_bfelf_file_init_invalid_segment_size();
    this->test_bfelf_file_init_invalid_entry();
    this->test_bfelf_file_init_invalid_section_type();
    this->test_bfelf_file_init_invalid_section_flags();
    this->test_bfelf_file_init_invalid_section_address_alignment();
    this->test_bfelf_file_init_invalid_section_entry_size();
    this->test_bfelf_file_init_missing_dynsym();
    this->test_bfelf_file_init_too_many_program_segments();
    this->test_bfelf_file_init_too_many_relocation_tables();
    this->test_bfelf_file_init_invalid_hash_table_size1();
    this->test_bfelf_file_init_invalid_hash_table_size2();
    this->test_bfelf_file_init_invalid_hash_table_size3();

    this->test_bfelf_file_num_segments_invalid_ef();
    this->test_bfelf_file_num_segments_uninitalized();
    this->test_bfelf_file_num_segments_success();

    this->test_bfelf_file_get_segment_invalid_ef();
    this->test_bfelf_file_get_segment_invalid_index();
    this->test_bfelf_file_get_segment_invalid_phdr();
    this->test_bfelf_file_get_segment_success();

    this->test_bfelf_file_resolve_symbol_invalid_loader();
    this->test_bfelf_file_resolve_symbol_invalid_name();
    this->test_bfelf_file_resolve_symbol_invalid_addr();
    this->test_bfelf_file_resolve_symbol_no_relocation();
    this->test_bfelf_file_resolve_no_such_symbol();
    this->test_bfelf_file_resolve_zero_length_symbol();
    this->test_bfelf_file_resolve_invalid_symbol_length();
    this->test_bfelf_file_resolve_symbol_length_too_large();
    this->test_bfelf_file_resolve_symbol_success();
    this->test_bfelf_file_resolve_no_such_symbol_no_hash();
    this->test_bfelf_file_resolve_zero_length_symbol_no_hash();
    this->test_bfelf_file_resolve_invalid_symbol_length_no_hash();
    this->test_bfelf_file_resolve_symbol_length_too_large_no_hash();
    this->test_bfelf_file_resolve_symbol_success_no_hash();

    this->test_bfelf_loader_add_invalid_loader();
    this->test_bfelf_loader_add_invalid_elf_file();
    this->test_bfelf_loader_add_too_many_files();

    this->test_bfelf_loader_resolve_symbol_invalid_loader();
    this->test_bfelf_loader_resolve_symbol_invalid_name();
    this->test_bfelf_loader_resolve_symbol_invalid_addr();
    this->test_bfelf_loader_resolve_symbol_no_relocation();
    this->test_bfelf_loader_resolve_symbol_no_files_added();
    this->test_bfelf_loader_resolve_symbol_uninitialized_files();
    this->test_bfelf_loader_resolve_no_such_symbol();
    this->test_bfelf_loader_resolve_zero_length_symbol();
    this->test_bfelf_loader_resolve_invalid_symbol_length();
    this->test_bfelf_loader_resolve_symbol_length_too_large();
    this->test_bfelf_loader_resolve_symbol_success();
    this->test_bfelf_loader_resolve_no_such_symbol_no_hash();
    this->test_bfelf_loader_resolve_zero_length_symbol_no_hash();
    this->test_bfelf_loader_resolve_invalid_symbol_length_no_hash();
    this->test_bfelf_loader_resolve_symbol_length_too_large_no_hash();
    this->test_bfelf_loader_resolve_symbol_success_no_hash();
    this->test_bfelf_loader_resolve_symbol_real_test();
    this->test_bfelf_file_resolve_symbol_resolve_fail();
    this->test_bfelf_loader_resolve_symbol_resolve_fail();

    this->test_bfelf_loader_relocate_invalid_loader();
    this->test_bfelf_loader_relocate_no_files_added();
    this->test_bfelf_loader_relocate_uninitialized_files();
    this->test_bfelf_loader_relocate_twice();

    this->test_bfelf_loader_get_info_invalid_loader();
    this->test_bfelf_loader_get_info_invalid_elf_file();
    this->test_bfelf_loader_get_info_invalid_info();
    this->test_bfelf_loader_get_info_no_relocation();
    this->test_bfelf_loader_get_info_expected_misc_resources();
    this->test_bfelf_loader_get_info_expected_code_resources();
    this->test_bfelf_loader_get_info_get_section_name_failure_ctors();
    this->test_bfelf_loader_get_info_check_section_name_failure_ctors();
    this->test_bfelf_loader_get_info_get_section_name_failure_dtors();
    this->test_bfelf_loader_get_info_check_section_name_failure_dtors();
    this->test_bfelf_loader_get_info_get_section_name_failure_init_array();
    this->test_bfelf_loader_get_info_check_section_name_failure_init_array();
    this->test_bfelf_loader_get_info_get_section_name_failure_fini_array();
    this->test_bfelf_loader_get_info_check_section_name_failure_fini_array();
    this->test_bfelf_loader_get_info_get_section_name_failure_eh_frame();
    this->test_bfelf_loader_get_info_check_section_name_failure_eh_frame();
    this->test_bfelf_loader_get_info_all();

    this->test_private_bfelf_error();
    this->test_private_invalid_symbol_index();
    this->test_private_corrupt_symbol_table();
    this->test_private_relocate_invalid_index();
    this->test_private_relocate_invalid_name();
    this->test_private_relocate_invalid_relocation();
    this->test_private_get_section_invalid_name();
    this->test_private_symbol_table_sections_invalid_dynsym();
    this->test_private_symbol_table_sections_invalid_hash();
    this->test_private_string_table_sections_invalid();
    this->test_private_get_relocation_tables_invalid_type();
    this->test_private_get_relocation_tables_invalid_section();
    this->test_private_hash();

    return true;
}

void *
alloc_exec(size_t size)
{
    auto addr = mmap(nullptr, size, PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANON, -1, 0);

    return memset(addr, 0, size);
}

std::shared_ptr<char>
bfelf_loader_ut::load_elf_file(bfelf_file_t *ef)
{
    bfelf64_xword total = 0;
    int64_t num_segments = bfelf_file_num_segments(ef);

    for (auto i = 0; i < num_segments; i++)
    {
        int64_t ret = 0;
        bfelf_phdr *phdr = nullptr;

        ret = bfelf_file_get_segment(ef, i, &phdr);
        if (ret == BFELF_SUCCESS)
        {
            if (total < phdr->p_vaddr + phdr->p_memsz)
                total = phdr->p_vaddr + phdr->p_memsz;
        }
    }

    auto exec = static_cast<char *>(alloc_exec(total));

    if (exec != nullptr)
    {
        memset(exec, 0, total);

        for (auto i = 0U; i < num_segments; i++)
        {
            int64_t ret = 0;
            bfelf_phdr *phdr = nullptr;

            ret = bfelf_file_get_segment(ef, i, &phdr);
            if (ret == BFELF_SUCCESS)
            {
                auto exec_p = exec + phdr->p_vaddr;
                auto file_p = reinterpret_cast<uintptr_t>(ef->file) + phdr->p_offset;

                memcpy(exec_p, reinterpret_cast<void *>(file_p), phdr->p_filesz);
            }
        }
    }

    return std::shared_ptr<char>(exec, [](void *) {});
}

#define offset(a,b) ( (reinterpret_cast<uintptr_t>(&(a))) - (reinterpret_cast<uintptr_t>(&(b))) )

bfelf_test
bfelf_loader_ut::get_test() const
{
    bfelf_test test;

    memset(&test, 0, sizeof(test));

    test.header.e_ident[bfei_mag0] = 0x7F;
    test.header.e_ident[bfei_mag1] = 'E';
    test.header.e_ident[bfei_mag2] = 'L';
    test.header.e_ident[bfei_mag3] = 'F';
    test.header.e_ident[bfei_class] = bfelfclass64;
    test.header.e_ident[bfei_data] = bfelfdata2lsb;
    test.header.e_ident[bfei_version] = bfev_current;
    test.header.e_ident[bfei_osabi] = bfelfosabi_sysv;
    test.header.e_ident[bfei_abiversion] = 0;
    test.header.e_type = bfet_dyn;
    test.header.e_machine = bfem_x86_64;
    test.header.e_version = bfev_current;
    test.header.e_entry = 0x150;
    test.header.e_phoff = offset(test.phdrtab, test);
    test.header.e_shoff = offset(test.shdrtab, test);
    test.header.e_flags = 0;
    test.header.e_ehsize = sizeof(bfelf64_ehdr);
    test.header.e_phentsize = sizeof(bfelf_phdr);
    test.header.e_phnum = sizeof(test_phdrtab) / sizeof(bfelf_phdr);
    test.header.e_shentsize = sizeof(bfelf_shdr);
    test.header.e_shnum = sizeof(test_shdrtab) / sizeof(bfelf_shdr);
    test.header.e_shstrndx = 3;

    test.phdrtab.re_segment1.p_type = bfpt_load;
    test.phdrtab.re_segment1.p_flags = bfpf_r | bfpf_x;
    test.phdrtab.re_segment1.p_offset = 0;
    test.phdrtab.re_segment1.p_vaddr = 0;
    test.phdrtab.re_segment1.p_paddr = 0;
    test.phdrtab.re_segment1.p_filesz = 0x500;
    test.phdrtab.re_segment1.p_memsz = 0x500;
    test.phdrtab.re_segment1.p_align = 0x1000;

    test.phdrtab.re_segment2.p_type = bfpt_load;
    test.phdrtab.re_segment2.p_flags = bfpf_r | bfpf_x;
    test.phdrtab.re_segment2.p_offset = 10;
    test.phdrtab.re_segment2.p_vaddr = 0x500;
    test.phdrtab.re_segment2.p_paddr = 0x500;
    test.phdrtab.re_segment2.p_filesz = 0x500;
    test.phdrtab.re_segment2.p_memsz = 0x500;
    test.phdrtab.re_segment2.p_align = 0x1000;

    test.phdrtab.rw_segment1.p_type = bfpt_load;
    test.phdrtab.rw_segment1.p_flags = bfpf_r | bfpf_w;
    test.phdrtab.rw_segment1.p_offset = 10;
    test.phdrtab.rw_segment1.p_vaddr = 0x1000;
    test.phdrtab.rw_segment1.p_paddr = 0x1000;
    test.phdrtab.rw_segment1.p_filesz = 0x500;
    test.phdrtab.rw_segment1.p_memsz = 0x500;
    test.phdrtab.rw_segment1.p_align = 0x1000;

    test.phdrtab.rw_segment2.p_type = bfpt_load;
    test.phdrtab.rw_segment2.p_flags = bfpf_r | bfpf_w;
    test.phdrtab.rw_segment2.p_offset = 10;
    test.phdrtab.rw_segment2.p_vaddr = 0x1500;
    test.phdrtab.rw_segment2.p_paddr = 0x1500;
    test.phdrtab.rw_segment2.p_filesz = 0x500;
    test.phdrtab.rw_segment2.p_memsz = 0x500;
    test.phdrtab.rw_segment2.p_align = 0x1000;

    test.shdrtab.shstrtab.sh_name = static_cast<bfelf64_word>(offset(test.shstrtab.name4, test.shstrtab));
    test.shdrtab.shstrtab.sh_type = bfsht_strtab;
    test.shdrtab.shstrtab.sh_flags = 0;
    test.shdrtab.shstrtab.sh_addr = 0x250;
    test.shdrtab.shstrtab.sh_offset = offset(test.shstrtab, test);
    test.shdrtab.shstrtab.sh_size = sizeof(test_shstrtab);
    test.shdrtab.shstrtab.sh_link = 0;
    test.shdrtab.shstrtab.sh_addralign = 1;
    test.shdrtab.shstrtab.sh_entsize = 0;

    test.shdrtab.dynsym.sh_name = static_cast<bfelf64_word>(offset(test.shstrtab.name1, test.shstrtab));
    test.shdrtab.dynsym.sh_type = bfsht_dynsym;
    test.shdrtab.dynsym.sh_flags = bfshf_a;
    test.shdrtab.dynsym.sh_addr = 0x250;
    test.shdrtab.dynsym.sh_offset = offset(test.dynsym, test);
    test.shdrtab.dynsym.sh_size = sizeof(test_dynsym);
    test.shdrtab.dynsym.sh_link = 2;
    test.shdrtab.dynsym.sh_addralign = 8;
    test.shdrtab.dynsym.sh_entsize = sizeof(bfelf_sym);

    test.shdrtab.hashtab.sh_name = static_cast<bfelf64_word>(offset(test.shstrtab.name2, test.shstrtab));
    test.shdrtab.hashtab.sh_type = bfsht_hash;
    test.shdrtab.hashtab.sh_flags = bfshf_a;
    test.shdrtab.hashtab.sh_addr = 0x250;
    test.shdrtab.hashtab.sh_offset = offset(test.hashtab, test);
    test.shdrtab.hashtab.sh_size = sizeof(test_hashtab);
    test.shdrtab.hashtab.sh_link = 0;
    test.shdrtab.hashtab.sh_addralign = 8;
    test.shdrtab.hashtab.sh_entsize = 0x4;

    test.shdrtab.strtab.sh_name = static_cast<bfelf64_word>(offset(test.shstrtab.name3, test.shstrtab));
    test.shdrtab.strtab.sh_type = bfsht_strtab;
    test.shdrtab.strtab.sh_flags = bfshf_a;
    test.shdrtab.strtab.sh_addr = 0x250;
    test.shdrtab.strtab.sh_offset = offset(test.strtab, test);
    test.shdrtab.strtab.sh_size = sizeof(test_strtab);
    test.shdrtab.strtab.sh_link = 0;
    test.shdrtab.strtab.sh_addralign = 1;
    test.shdrtab.strtab.sh_entsize = 0;

    test.shdrtab.relatab1.sh_name = static_cast<bfelf64_word>(offset(test.shstrtab.name5, test.shstrtab));
    test.shdrtab.relatab1.sh_type = bfsht_rela;
    test.shdrtab.relatab1.sh_flags = bfshf_ai;
    test.shdrtab.relatab1.sh_addr = 0x250;
    test.shdrtab.relatab1.sh_offset = offset(test.relatab, test);
    test.shdrtab.relatab1.sh_size = sizeof(test_relatab);
    test.shdrtab.relatab1.sh_link = 0;
    test.shdrtab.relatab1.sh_addralign = 8;
    test.shdrtab.relatab1.sh_entsize = sizeof(bfelf_rela);

    test.shdrtab.relatab2.sh_name = static_cast<bfelf64_word>(offset(test.shstrtab.name5, test.shstrtab));
    test.shdrtab.relatab2.sh_type = bfsht_rela;
    test.shdrtab.relatab2.sh_flags = bfshf_ai;
    test.shdrtab.relatab2.sh_addr = 0x250;
    test.shdrtab.relatab2.sh_offset = offset(test.relatab, test);
    test.shdrtab.relatab2.sh_size = sizeof(test_relatab);
    test.shdrtab.relatab2.sh_link = 0;
    test.shdrtab.relatab2.sh_addralign = 8;
    test.shdrtab.relatab2.sh_entsize = sizeof(bfelf_rela);

    test.shdrtab.relatab3.sh_name = static_cast<bfelf64_word>(offset(test.shstrtab.name5, test.shstrtab));
    test.shdrtab.relatab3.sh_type = bfsht_rela;
    test.shdrtab.relatab3.sh_flags = bfshf_ai;
    test.shdrtab.relatab3.sh_addr = 0x250;
    test.shdrtab.relatab3.sh_offset = offset(test.relatab, test);
    test.shdrtab.relatab3.sh_size = sizeof(test_relatab);
    test.shdrtab.relatab3.sh_link = 0;
    test.shdrtab.relatab3.sh_addralign = 8;
    test.shdrtab.relatab3.sh_entsize = sizeof(bfelf_rela);

    test.shdrtab.relatab4.sh_name = static_cast<bfelf64_word>(offset(test.shstrtab.name5, test.shstrtab));
    test.shdrtab.relatab4.sh_type = bfsht_rela;
    test.shdrtab.relatab4.sh_flags = bfshf_ai;
    test.shdrtab.relatab4.sh_addr = 0x250;
    test.shdrtab.relatab4.sh_offset = offset(test.relatab, test);
    test.shdrtab.relatab4.sh_size = sizeof(test_relatab);
    test.shdrtab.relatab4.sh_link = 0;
    test.shdrtab.relatab4.sh_addralign = 8;
    test.shdrtab.relatab4.sh_entsize = sizeof(bfelf_rela);

    test.shdrtab.relatab5.sh_name = static_cast<bfelf64_word>(offset(test.shstrtab.name5, test.shstrtab));
    test.shdrtab.relatab5.sh_type = bfsht_rela;
    test.shdrtab.relatab5.sh_flags = bfshf_ai;
    test.shdrtab.relatab5.sh_addr = 0x250;
    test.shdrtab.relatab5.sh_offset = offset(test.relatab, test);
    test.shdrtab.relatab5.sh_size = sizeof(test_relatab);
    test.shdrtab.relatab5.sh_link = 0;
    test.shdrtab.relatab5.sh_addralign = 8;
    test.shdrtab.relatab5.sh_entsize = sizeof(bfelf_rela);

    test.shdrtab.relatab6.sh_name = static_cast<bfelf64_word>(offset(test.shstrtab.name5, test.shstrtab));
    test.shdrtab.relatab6.sh_type = bfsht_rela;
    test.shdrtab.relatab6.sh_flags = bfshf_ai;
    test.shdrtab.relatab6.sh_addr = 0x250;
    test.shdrtab.relatab6.sh_offset = offset(test.relatab, test);
    test.shdrtab.relatab6.sh_size = sizeof(test_relatab);
    test.shdrtab.relatab6.sh_link = 0;
    test.shdrtab.relatab6.sh_addralign = 8;
    test.shdrtab.relatab6.sh_entsize = sizeof(bfelf_rela);

    test.shdrtab.relatab7.sh_name = static_cast<bfelf64_word>(offset(test.shstrtab.name5, test.shstrtab));
    test.shdrtab.relatab7.sh_type = bfsht_rela;
    test.shdrtab.relatab7.sh_flags = bfshf_ai;
    test.shdrtab.relatab7.sh_addr = 0x250;
    test.shdrtab.relatab7.sh_offset = offset(test.relatab, test);
    test.shdrtab.relatab7.sh_size = sizeof(test_relatab);
    test.shdrtab.relatab7.sh_link = 0;
    test.shdrtab.relatab7.sh_addralign = 8;
    test.shdrtab.relatab7.sh_entsize = sizeof(bfelf_rela);

    test.shdrtab.relatab8.sh_name = static_cast<bfelf64_word>(offset(test.shstrtab.name5, test.shstrtab));
    test.shdrtab.relatab8.sh_type = bfsht_rela;
    test.shdrtab.relatab8.sh_flags = bfshf_ai;
    test.shdrtab.relatab8.sh_addr = 0x250;
    test.shdrtab.relatab8.sh_offset = offset(test.relatab, test);
    test.shdrtab.relatab8.sh_size = sizeof(test_relatab);
    test.shdrtab.relatab8.sh_link = 0;
    test.shdrtab.relatab8.sh_addralign = 8;
    test.shdrtab.relatab8.sh_entsize = sizeof(bfelf_rela);

    test.hashtab.nbucket = 2;
    test.hashtab.nchain = 2;

    return test;
}

int
main(int argc, char *argv[])
{
    return RUN_ALL_TESTS(bfelf_loader_ut);
}
