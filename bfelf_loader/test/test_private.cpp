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

void
bfelf_loader_ut::test_private_hash()
{
    auto &&str = "strange char here: \200";
    this->expect_true(private_hash(static_cast<const char *>(str)) != 0);
}

void
bfelf_loader_ut::test_private_relocate_invalid_relocation_dyn()
{
    bfelf_file_t ef;
    auto &&data = get_test();
    auto &&buff = std::get<0>(data);
    auto &&size = std::get<1>(data);

    auto ret = bfelf_file_init(buff.get(), size, &ef);
    this->expect_true(ret == BFELF_SUCCESS);

    bfelf_rela relatab_dyn[1] = {};
    bfelf_loader_t loader = {};
    bfelf_sym symtab[1] = {};

    auto file = "hello";
    auto exec = std::make_unique<char[]>(100);

    ef.exec_addr = exec.get();
    ef.exec_virt = exec.get();
    ef.file = file;
    ef.symtab = static_cast<bfelf_sym *>(symtab);
    ef.symnum = 1;
    ef.relatab_dyn = static_cast<bfelf_rela *>(relatab_dyn);
    ef.relanum_dyn = 1;
    ef.relanum_plt = 0;

    gsl::at(relatab_dyn, 0).r_info = 0xFFFFFFFF;
    gsl::at(relatab_dyn, 0).r_offset = 0x0;

    gsl::at(symtab, 0).st_name = 0xFFFFF;
    gsl::at(symtab, 0).st_value = 0x1;

    this->expect_true(private_relocate_symbols(&loader, &ef) == BFELF_ERROR_UNSUPPORTED_RELA);
}

void
bfelf_loader_ut::test_private_relocate_invalid_relocation_plt()
{
    bfelf_file_t ef;
    auto &&data = get_test();
    auto &&buff = std::get<0>(data);
    auto &&size = std::get<1>(data);

    auto ret = bfelf_file_init(buff.get(), size, &ef);
    this->expect_true(ret == BFELF_SUCCESS);

    bfelf_rela relatab_plt[1] = {};
    bfelf_loader_t loader = {};
    bfelf_sym symtab[1] = {};

    auto file = "hello";
    auto exec = std::make_unique<char[]>(100);

    ef.exec_addr = exec.get();
    ef.exec_virt = exec.get();
    ef.file = file;
    ef.symtab = static_cast<bfelf_sym *>(symtab);
    ef.symnum = 1;
    ef.relatab_plt = static_cast<bfelf_rela *>(relatab_plt);
    ef.relanum_dyn = 0;
    ef.relanum_plt = 1;

    gsl::at(relatab_plt, 0).r_info = 0xFFFFFFFF;
    gsl::at(relatab_plt, 0).r_offset = 0x0;

    gsl::at(symtab, 0).st_name = 0xFFFFF;
    gsl::at(symtab, 0).st_value = 0x1;

    this->expect_true(private_relocate_symbols(&loader, &ef) == BFELF_ERROR_UNSUPPORTED_RELA);
}

void
bfelf_loader_ut::test_private_process_dynamic_section()
{
    bfelf_file_t ef;
    auto &&data = get_test();
    auto &&buff = std::get<0>(data);
    auto &&size = std::get<1>(data);

    auto ret = bfelf_file_init(buff.get(), size, &ef);
    this->expect_true(ret == BFELF_SUCCESS);

    private_process_dynamic_section(&ef);

    ef.dynnum = 0;
    private_process_dynamic_section(&ef);

    ef.dynoff = 0;
    private_process_dynamic_section(&ef);
}
