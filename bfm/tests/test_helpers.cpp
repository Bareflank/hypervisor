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

#define CATCH_CONFIG_MAIN
#include <catch/catch.hpp>

#include <gsl/gsl>
#include <bfelf_loader.h>
#include <test_fake_elf.h>
#include <test_real_elf.h>

TEST_CASE("get_real_elf: invalid file")
{
    CHECK_THROWS(get_real_elf("blah"));
}

TEST_CASE("private_hash: strange characters")
{
    auto &&str = "strange char here: \200";
    CHECK(private_hash(static_cast<const char *>(str)) != 0);
}

TEST_CASE("private_relocate_symbol: invalid relocation")
{
    bfelf_loader_t loader = {};
    bfelf_file_t ef = {};
    bfelf_rela rela = {};
    bfelf_sym symtab[1] = {};

    auto file = "hello";
    auto exec = std::make_unique<char[]>(100);

    ef.exec_addr = exec.get();
    ef.exec_virt = exec.get();
    ef.file = file;
    ef.symtab = static_cast<bfelf_sym *>(symtab);
    ef.symnum = 1;

    rela.r_info = 0xFFFFFFFF;
    rela.r_offset = 0x0;

    gsl::at(symtab, 0).st_name = 0xFFFFF;
    gsl::at(symtab, 0).st_value = 0x1;

    CHECK(private_relocate_symbol(&loader, &ef, &rela) == BFELF_ERROR_UNSUPPORTED_RELA);
}

TEST_CASE("private_process_dynamic_section: test all")
{
    auto ret = 0LL;
    bfelf_file_t ef = {};

    auto &&data = get_fake_elf();
    auto &&buff = std::get<0>(data);
    auto &&size = std::get<1>(data);

    ret = bfelf_file_init(buff.get(), size, &ef);
    CHECK(ret == BFELF_SUCCESS);

    private_process_dynamic_section(&ef);

    ef.dynnum = 0;
    private_process_dynamic_section(&ef);

    ef.dynoff = 0;
    private_process_dynamic_section(&ef);
}
