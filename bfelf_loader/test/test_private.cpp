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
bfelf_loader_ut::test_private_relocate_invalid_relocation()
{
    bfelf_loader_t loader = {};
    bfelf_file_t ef = {};
    bfelf_rela rela = {};
    bfelf_sym symtab[1] = {};

    auto file = "hello";
    auto exec = std::make_unique<char[]>(1);

    ef.exec_addr = exec.get();
    ef.exec_virt = exec.get();
    ef.file = file;
    ef.symtab = static_cast<bfelf_sym *>(symtab);
    ef.symnum = 1;

    rela.r_info = 0xFFFFFFFF;
    rela.r_offset = 0x0;

    gsl::at(symtab, 0).st_name = 0xFFFFF;
    gsl::at(symtab, 0).st_value = 0x1;

    this->expect_true(private_relocate_symbol(&loader, &ef, &rela) == BFELF_ERROR_UNSUPPORTED_RELA);
}
