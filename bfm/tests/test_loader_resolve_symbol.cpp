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

#include <bfgsl.h>
#include <bfelf_loader.h>

#include <test_real_elf.h>

using func_t = void (*)();

TEST_CASE("bfelf_loader_resolve_symbol: invalid loader")
{
    func_t func;

    auto ret = bfelf_loader_resolve_symbol(nullptr, "abort", reinterpret_cast<void **>(&func));
    CHECK(ret == BFELF_ERROR_INVALID_ARG);
}

TEST_CASE("bfelf_loader_resolve_symbol: invalid name")
{
    func_t func;
    bfelf_loader_t loader = {};

    auto ret = bfelf_loader_resolve_symbol(&loader, nullptr, reinterpret_cast<void **>(&func));
    CHECK(ret == BFELF_ERROR_INVALID_ARG);
}

TEST_CASE("bfelf_loader_resolve_symbol: invalid addr")
{
    bfelf_loader_t loader = {};

    auto ret = bfelf_loader_resolve_symbol(&loader, "abort", nullptr);
    CHECK(ret == BFELF_ERROR_INVALID_ARG);
}

TEST_CASE("bfelf_loader_resolve_symbol: no files added")
{
    auto ret = 0LL;
    bfelf_loader_t loader = {};

    ret = bfelf_loader_relocate(&loader);
    CHECK(ret == BFELF_SUCCESS);

    func_t func;

    ret = bfelf_loader_resolve_symbol(&loader, "abort", reinterpret_cast<void **>(&func));
    CHECK(ret == BFELF_ERROR_NO_SUCH_SYMBOL);
}

TEST_CASE("bfelf_loader_resolve_symbol: no such symbol")
{
    auto ret = 0LL;
    bfelf_loader_t loader = {};

    auto &&details = load_libraries(&loader, g_filenames);
    ignored(details);

    ret = bfelf_loader_relocate(&loader);
    CHECK(ret == BFELF_SUCCESS);

    func_t func;

    ret = bfelf_loader_resolve_symbol(&loader, "invalid_sym", reinterpret_cast<void **>(&func));
    CHECK(ret == BFELF_ERROR_NO_SUCH_SYMBOL);
}

TEST_CASE("bfelf_loader_resolve_symbol: success")
{
    auto ret = 0LL;
    bfelf_loader_t loader = {};

    auto &&details = load_libraries(&loader, g_filenames);
    ignored(details);

    ret = bfelf_loader_relocate(&loader);
    CHECK(ret == BFELF_SUCCESS);

    func_t func;

    ret = bfelf_loader_resolve_symbol(&loader, "abort", reinterpret_cast<void **>(&func));
    CHECK(ret == BFELF_SUCCESS);
}

TEST_CASE("bfelf_loader_resolve_symbol: no such symbol no hash")
{
    auto ret = 0LL;
    bfelf_loader_t loader = {};

    auto &&details = load_libraries(&loader, g_filenames);

    auto &&lib1_details = details.at(0);
    auto &&lib2_details = details.at(1);

    lib1_details.first.hash = nullptr;
    lib2_details.first.hash = nullptr;

    ret = bfelf_loader_relocate(&loader);
    CHECK(ret == BFELF_SUCCESS);

    func_t func;

    ret = bfelf_loader_resolve_symbol(&loader, "invalid_sym", reinterpret_cast<void **>(&func));
    CHECK(ret == BFELF_ERROR_NO_SUCH_SYMBOL);
}

TEST_CASE("bfelf_loader_resolve_symbol: success no hash")
{
    auto ret = 0LL;
    bfelf_loader_t loader = {};

    auto &&details = load_libraries(&loader, g_filenames);

    auto &&lib1_details = details.at(0);
    auto &&lib2_details = details.at(1);

    lib1_details.first.hash = nullptr;
    lib2_details.first.hash = nullptr;

    ret = bfelf_loader_relocate(&loader);
    CHECK(ret == BFELF_SUCCESS);

    func_t func;

    ret = bfelf_loader_resolve_symbol(&loader, "abort", reinterpret_cast<void **>(&func));
    CHECK(ret == BFELF_SUCCESS);
}
