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

#include <catch/catch.hpp>

#include <fstream>
#include <test_real_elf.h>
#include <test_fake_elf.h>

char dummy[10];

TEST_CASE("bfelf_loader_add: invalid loader")
{
    bfelf_file_t dummy_misc_ef = {};

    auto ret = bfelf_loader_add(nullptr, &dummy_misc_ef, static_cast<char *>(dummy), static_cast<char *>(dummy));
    CHECK(ret == BFELF_ERROR_INVALID_ARG);
}

TEST_CASE("bfelf_loader_add: invalid elf file")
{
    bfelf_loader_t loader = {};

    auto ret = bfelf_loader_add(&loader, nullptr, static_cast<char *>(dummy), static_cast<char *>(dummy));
    CHECK(ret == BFELF_ERROR_INVALID_ARG);
}

TEST_CASE("bfelf_loader_add: invalid addr")
{
    bfelf_loader_t loader = {};
    bfelf_file_t dummy_misc_ef = {};

    auto ret = bfelf_loader_add(&loader, &dummy_misc_ef, nullptr, static_cast<char *>(dummy));
    CHECK(ret == BFELF_ERROR_INVALID_ARG);
}

// TEST_CASE("bfelf_loader_add: too many files")
// {
//     int64_t ret = 0;
//     bfelf_file_t ef = {};
//     bfelf_loader_t loader = {};

//     auto data = get_fake_elf();
//     auto &buf = std::get<0>(data);
//     auto size = std::get<1>(data);

//     for (auto i = 0; i < MAX_NUM_MODULES + 1; i++) {

//         bfelf_file_t dummy_misc_ef = {};

//         ret = bfelf_file_init(buf.get(), size, &ef);
//         REQUIRE(ret == BFELF_SUCCESS);

//         ret = bfelf_loader_add(&loader, &ef, dummy, dummy);

//         if (i < MAX_NUM_MODULES) {
//             CHECK(ret == BF_SUCCESS);
//         }
//         else {
//             CHECK(ret == BFELF_ERROR_LOADER_FULL);
//         }
//     }
// }

TEST_CASE("bfelf_loader_add: add fake")
{
    int64_t ret = 0;
    bfelf_file_t ef = {};
    bfelf_loader_t loader = {};

    auto data = get_fake_elf();
    auto &buf = std::get<0>(data);
    auto size = std::get<1>(data);

    ret = bfelf_file_init(buf.get(), size, &ef);
    CHECK(ret == BFELF_SUCCESS);

    ret = bfelf_loader_add(&loader, &ef, static_cast<char *>(dummy), static_cast<char *>(dummy));
    CHECK(ret == BFELF_SUCCESS);
}
