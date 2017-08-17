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

#include <bfelf_loader.h>

TEST_CASE("bfelf_file_get_relro: invalid elf file")
{
    bfelf64_addr addr = 0;
    bfelf64_xword size = 0;

    auto ret = bfelf_file_get_relro(nullptr, &addr, &size);
    CHECK(ret == BFELF_ERROR_INVALID_ARG);
}

TEST_CASE("bfelf_file_get_relro: invalid addr")
{
    auto ret = 0LL;
    bfelf_file_t ef = {};
    bfelf64_xword size = 0;

    ret = bfelf_file_get_relro(&ef, nullptr, &size);
    CHECK(ret == BFELF_ERROR_INVALID_ARG);
}

TEST_CASE("bfelf_file_get_relro: invalid size")
{
    auto ret = 0LL;
    bfelf_file_t ef = {};
    bfelf64_addr addr = 0;

    ret = bfelf_file_get_relro(&ef, &addr, nullptr);
    CHECK(ret == BFELF_ERROR_INVALID_ARG);
}

TEST_CASE("bfelf_file_get_relro: success")
{
    auto ret = 0LL;
    bfelf_file_t ef = {};
    bfelf64_addr addr = 0;
    bfelf64_xword size = 0;

    ret = bfelf_file_get_relro(&ef, &addr, &size);
    CHECK(ret == BFELF_SUCCESS);
}
