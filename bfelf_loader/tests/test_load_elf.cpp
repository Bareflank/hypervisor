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

#include <hippomocks.h>
#include <catch/catch.hpp>

#include <bfgsl.h>
#include <bfplatform.h>

#include <fstream>
#include <test_real_elf.h>

TEST_CASE("bfelf_load_elf: invalid file")
{
    // char *exec = nullptr;
    // bfelf_file_t ef = {};

    // auto file = g_file.read_binary(BAREFLANK_SYSROOT_PATH "/bin/dummy_main");
    // auto size = file.size();

    // auto ret = bfelf_load_elf(nullptr, size, &ef, &exec);
    // CHECK(ret == BFELF_ERROR_INVALID_ARG);
}

// TEST_CASE("bfelf_load_elf: invalid size")
// {
//     char *exec = nullptr;
//     bfelf_file_t ef = {};

//     auto file = g_file.read_binary(BAREFLANK_SYSROOT_PATH "/bin/dummy_main");
//     auto size = 0ULL;

//     auto ret = bfelf_load_elf(file.data(), size, &ef, &exec);
//     CHECK(ret == BFELF_ERROR_INVALID_ARG);
// }

// TEST_CASE("bfelf_load_elf: invalid elf")
// {
//     char *exec = nullptr;

//     auto file = g_file.read_binary(BAREFLANK_SYSROOT_PATH "/bin/dummy_main");
//     auto size = file.size();

//     auto ret = bfelf_load_elf(file.data(), size, nullptr, &exec);
//     CHECK(ret == BFELF_ERROR_INVALID_ARG);
// }

// TEST_CASE("bfelf_load_elf: invalid exec")
// {
//     bfelf_file_t ef = {};

//     auto file = g_file.read_binary(BAREFLANK_SYSROOT_PATH "/bin/dummy_main");
//     auto size = file.size();

//     auto ret = bfelf_load_elf(file.data(), size, &ef, nullptr);
//     CHECK(ret == BFELF_ERROR_INVALID_ARG);
// }

// TEST_CASE("bfelf_load_elf: bfelf_file_init fails")
// {
//     char *exec = nullptr;
//     bfelf_file_t ef = {};

//     auto file = g_file.read_binary(BAREFLANK_SYSROOT_PATH "/bin/dummy_main");
//     auto size = file.size();

//     auto span = gsl::string_span<>(file);
//     span[0] = 0;

//     auto ret = bfelf_load_elf(file.data(), size, &ef, &exec);
//     CHECK(ret == BFELF_ERROR_INVALID_SIGNATURE);
// }

// TEST_CASE("bfelf_load_elf: platform_alloc_rwe fails")
// {
//     char *exec = nullptr;
//     bfelf_file_t ef = {};

//     auto file = g_file.read_binary(BAREFLANK_SYSROOT_PATH "/bin/dummy_main");
//     auto size = file.size();

//     MockRepository mocks;
//     mocks.OnCallFunc(platform_alloc_rwe).Return(nullptr);

//     auto ret = bfelf_load_elf(file.data(), size, &ef, &exec);
//     CHECK(ret == BFELF_ERROR_OUT_OF_MEMORY);
// }

// TEST_CASE("bfelf_load_elf: success")
// {
//     char *exec = nullptr;
//     bfelf_file_t ef = {};

//     auto file = g_file.read_binary(BAREFLANK_SYSROOT_PATH "/bin/dummy_main");
//     auto size = file.size();

//     auto ret = bfelf_load_elf(file.data(), size, &ef, &exec);
//     CHECK(ret == BF_SUCCESS);

//     std::unique_ptr<char, decltype(free) *> {exec, free};
// }
