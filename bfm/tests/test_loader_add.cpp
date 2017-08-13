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
#include <test_real_elf.h>
#include <test_fake_elf.h>

char dummy[10];

TEST_CASE("bfelf_loader_add: invalid loader")
{
    auto ret = 0LL;
    bfelf_file_t dummy_misc_ef = {};

    ret = bfelf_loader_add(nullptr, &dummy_misc_ef, dummy, dummy);
    CHECK(ret == BFELF_ERROR_INVALID_ARG);
}

TEST_CASE("bfelf_loader_add: invalid elf file")
{
    bfelf_loader_t loader = {};

    auto ret = bfelf_loader_add(&loader, nullptr, dummy, dummy);
    CHECK(ret == BFELF_ERROR_INVALID_ARG);
}

TEST_CASE("bfelf_loader_add: invalid addr")
{
    auto ret = 0LL;
    bfelf_loader_t loader = {};
    bfelf_file_t dummy_misc_ef = {};

    ret = bfelf_loader_add(&loader, &dummy_misc_ef, nullptr, dummy);
    CHECK(ret == BFELF_ERROR_INVALID_ARG);
}

TEST_CASE("bfelf_loader_add: too many files")
{
    auto ret = 0LL;
    bfelf_loader_t loader = {};

    for (auto i = 0; i < MAX_NUM_MODULES + 1; i++) {
        bfelf_file_t dummy_misc_ef = {};
        auto &&exec = add_elf_to_loader("/lib/libdummy_lib1.so", &dummy_misc_ef, &loader);

        if (i < MAX_NUM_MODULES) {
            CHECK(exec);
        }
        else {
            CHECK(!exec);
        }
    }
}

TEST_CASE("bfelf_loader_add: add fake")
{
    auto ret = 0LL;
    bfelf_file_t ef = {};
    bfelf_loader_t loader = {};

    auto &&data = get_fake_elf();
    auto &&buff = std::get<0>(data);
    auto &&size = std::get<1>(data);

    ret = bfelf_file_init(buff.get(), size, &ef);
    CHECK(ret == BFELF_SUCCESS);

    ret = bfelf_loader_add(&loader, &ef, dummy, dummy);
    CHECK(ret == BFELF_SUCCESS);
}
