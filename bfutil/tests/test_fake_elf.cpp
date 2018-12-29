//
// Bareflank Hypervisor
// Copyright (C) 2015 Assured Information Security, Inc.
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

// TIDY_EXCLUSION=-cppcoreguidelines-pro-type-reinterpret-cast
//
// Reason:
//     Although in general this is a good rule, for hypervisor level code that
//     interfaces with the kernel, and raw hardware, this rule is
//     impractical.
//

#include <cstdint>
#include <cstring>
#include <test_fake_elf.h>

#define offset(a, b) ((reinterpret_cast<uintptr_t>(&(a))) - (reinterpret_cast<uintptr_t>(&(b))))

std::pair<std::unique_ptr<char[]>, uint64_t>
get_fake_elf()
{
    auto &&size = sizeof(bfelf_test);
    auto &&buff = std::make_unique<char[]>(size);
    auto &&test = reinterpret_cast<bfelf_test *>(buff.get());

    test->header.e_ident[bfei_mag0] = 0x7F;
    test->header.e_ident[bfei_mag1] = 'E';
    test->header.e_ident[bfei_mag2] = 'L';
    test->header.e_ident[bfei_mag3] = 'F';
    test->header.e_ident[bfei_class] = bfelfclass64;
    test->header.e_ident[bfei_data] = bfelfdata2lsb;
    test->header.e_ident[bfei_version] = bfev_current;
    test->header.e_ident[bfei_osabi] = bfelfosabi_sysv;
    test->header.e_ident[bfei_abiversion] = 0;
    test->header.e_type = bfet_dyn;
    test->header.e_machine = bfem_x86_64;
    test->header.e_version = bfev_current;
    test->header.e_entry = 0x150;
    test->header.e_phoff = offset(test->phdrtab, *test);
    test->header.e_shoff = offset(test->shdrtab, *test);
    test->header.e_flags = 0;
    test->header.e_ehsize = sizeof(bfelf_ehdr);
    test->header.e_phentsize = sizeof(bfelf_phdr);
    test->header.e_phnum = sizeof(test_phdrtab) / sizeof(bfelf_phdr);
    test->header.e_shentsize = sizeof(bfelf_shdr);
    test->header.e_shnum = sizeof(test_shdrtab) / sizeof(bfelf_shdr);
    test->header.e_shstrndx = 2;

    test->phdrtab.re_segment.p_type = bfpt_load;
    test->phdrtab.re_segment.p_flags = bfpf_r | bfpf_x;
    test->phdrtab.re_segment.p_offset = 0;
    test->phdrtab.re_segment.p_vaddr = 0;
    test->phdrtab.re_segment.p_paddr = 0;
    test->phdrtab.re_segment.p_filesz = 0x500;
    test->phdrtab.re_segment.p_memsz = 0x500;
    test->phdrtab.re_segment.p_align = 0x1000;

    test->phdrtab.rw_segment.p_type = bfpt_load;
    test->phdrtab.rw_segment.p_flags = bfpf_r | bfpf_w;
    test->phdrtab.rw_segment.p_offset = 0x500;
    test->phdrtab.rw_segment.p_vaddr = 0x500;
    test->phdrtab.rw_segment.p_paddr = 0x500;
    test->phdrtab.rw_segment.p_filesz = 0x500;
    test->phdrtab.rw_segment.p_memsz = 0x500;
    test->phdrtab.rw_segment.p_align = 0x1000;

    test->phdrtab.dyn_segment.p_type = bfpt_dynamic;
    test->phdrtab.dyn_segment.p_flags = bfpf_r | bfpf_w;
    test->phdrtab.dyn_segment.p_offset = offset(test->dynamic, *test);
    test->phdrtab.dyn_segment.p_vaddr = 0x0;
    test->phdrtab.dyn_segment.p_paddr = 0x0;
    test->phdrtab.dyn_segment.p_filesz = sizeof(test_dynamic);
    test->phdrtab.dyn_segment.p_memsz = sizeof(test_dynamic);
    test->phdrtab.dyn_segment.p_align = 0x1000;

    test->phdrtab.stack_segment.p_type = bfpt_gnu_stack;
    test->phdrtab.stack_segment.p_flags = bfpf_r | bfpf_w;
    test->phdrtab.stack_segment.p_offset = 0x0;
    test->phdrtab.stack_segment.p_vaddr = 0x0;
    test->phdrtab.stack_segment.p_paddr = 0x0;
    test->phdrtab.stack_segment.p_filesz = 0x0;
    test->phdrtab.stack_segment.p_memsz = 0x0;
    test->phdrtab.stack_segment.p_align = 0x0;

    test->phdrtab.relro_segment.p_type = bfpt_gnu_relro;
    test->phdrtab.relro_segment.p_flags = bfpf_r;
    test->phdrtab.relro_segment.p_offset = 0x0;
    test->phdrtab.relro_segment.p_vaddr = 0x0;
    test->phdrtab.relro_segment.p_paddr = 0x0;
    test->phdrtab.relro_segment.p_filesz = 0x500;
    test->phdrtab.relro_segment.p_memsz = 0x500;
    test->phdrtab.relro_segment.p_align = 0x1000;

    test->dynamic.needed1.d_tag = bfdt_needed;
    test->dynamic.needed2.d_tag = bfdt_needed;
    test->dynamic.pltgot.d_tag = bfdt_pltgot;
    test->dynamic.strtab.d_tag = bfdt_strtab;
    test->dynamic.strtab.d_val = offset(test->dynstr, *test);
    test->dynamic.symtab.d_tag = bfdt_symtab;
    test->dynamic.symtab.d_val = offset(test->dynsym, *test);
    test->dynamic.rela.d_tag = bfdt_rela;
    test->dynamic.rela.d_val = offset(test->relatab, *test);
    test->dynamic.relasz.d_tag = bfdt_relasz;
    test->dynamic.relasz.d_val = sizeof(test_relatab);
    test->dynamic.relaent.d_tag = bfdt_relaent;
    test->dynamic.relaent.d_val = sizeof(bfelf_rela);
    test->dynamic.strsz.d_tag = bfdt_strsz;
    test->dynamic.strsz.d_val = sizeof(test_dynstr);
    test->dynamic.init.d_tag = bfdt_init;
    test->dynamic.init.d_val = offset(test->init_array, *test);
    test->dynamic.fini.d_tag = bfdt_fini;
    test->dynamic.fini.d_val = offset(test->fini_array, *test);
    test->dynamic.init_array.d_tag = bfdt_init_array;
    test->dynamic.init_array.d_val = offset(test->init_array, *test);
    test->dynamic.fini_array.d_tag = bfdt_fini_array;
    test->dynamic.fini_array.d_val = offset(test->fini_array, *test);
    test->dynamic.init_arraysz.d_tag = bfdt_init_arraysz;
    test->dynamic.init_arraysz.d_val = sizeof(test_init_array);
    test->dynamic.fini_arraysz.d_tag = bfdt_fini_arraysz;
    test->dynamic.fini_arraysz.d_val = sizeof(test_fini_array);
    test->dynamic.flags_1.d_tag = bfdt_flags_1;
    test->dynamic.last.d_tag = bfdt_null;

    test->shdrtab.eh_frame.sh_name = 0x0;
    test->shdrtab.eh_frame.sh_type = bfsht_strtab;
    test->shdrtab.eh_frame.sh_flags = 0;
    test->shdrtab.eh_frame.sh_addr = 0x250;
    test->shdrtab.eh_frame.sh_offset = offset(test->eh_frame, *test);
    test->shdrtab.eh_frame.sh_size = sizeof(test_eh_frame);
    test->shdrtab.eh_frame.sh_link = 0;
    test->shdrtab.eh_frame.sh_addralign = 1;
    test->shdrtab.eh_frame.sh_entsize = 0;

    test->shdrtab.dynstr.sh_offset = offset(test->dynstr, *test);

    test->shdrtab.eh_frame.sh_name = 10;
    test->shdrtab.ctors.sh_name = 20;
    test->shdrtab.dtors.sh_name = 30;

    strncpy(static_cast<char *>(test->dynstr.str2), ".eh_frame", 10);
    strncpy(static_cast<char *>(test->dynstr.str3), ".ctors", 10);
    strncpy(static_cast<char *>(test->dynstr.str4), ".dtors", 10);

    return {std::move(buff), size};
}
