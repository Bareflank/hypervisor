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

#include <catch/catch.hpp>
#include <test_real_elf.h>

using func_t = void (*)();

TEST_CASE("bfelf_loader_resolve_symbol: invalid loader")
{
    func_t func;

    auto ret = bfelf_loader_resolve_symbol(nullptr, "lib1_foo", reinterpret_cast<void **>(&func));
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

    auto ret = bfelf_loader_resolve_symbol(&loader, "lib1_foo", nullptr);
    CHECK(ret == BFELF_ERROR_INVALID_ARG);
}

TEST_CASE("bfelf_loader_resolve_symbol: no files added")
{
    int64_t ret = 0;
    bfelf_loader_t loader = {};

    ret = bfelf_loader_relocate(&loader);
    CHECK(ret == BFELF_SUCCESS);

    func_t func;

    ret = bfelf_loader_resolve_symbol(&loader, "lib1_foo", reinterpret_cast<void **>(&func));
    CHECK(ret == BFELF_ERROR_NO_SUCH_SYMBOL);
}

TEST_CASE("bfelf_loader_resolve_symbol: no such symbol")
{
    int64_t ret = 0;
    binaries_info binaries{&g_file, g_filenames};

    func_t func;

    ret = bfelf_loader_resolve_symbol(&binaries.loader(), "invalid_sym", reinterpret_cast<void **>(&func));
    CHECK(ret == BFELF_ERROR_NO_SUCH_SYMBOL);
}

TEST_CASE("bfelf_loader_resolve_symbol: success")
{
    int64_t ret = 0;
    binaries_info binaries{&g_file, g_filenames};

    func_t func;

    ret = bfelf_loader_resolve_symbol(&binaries.loader(), "lib1_foo", reinterpret_cast<void **>(&func));
    CHECK(ret == BFELF_SUCCESS);
}

TEST_CASE("bfelf_loader_resolve_symbol: no such symbol no hash")
{
    int64_t ret = 0;
    binaries_info binaries{&g_file, g_filenames};

    binaries.ef(0).hash = nullptr;
    binaries.ef(1).hash = nullptr;

    func_t func;

    ret = bfelf_loader_resolve_symbol(&binaries.loader(), "invalid_sym", reinterpret_cast<void **>(&func));
    CHECK(ret == BFELF_ERROR_NO_SUCH_SYMBOL);
}

TEST_CASE("bfelf_loader_resolve_symbol: success no hash")
{
    int64_t ret = 0;
    binaries_info binaries{&g_file, g_filenames};

    binaries.ef(0).hash = nullptr;
    binaries.ef(1).hash = nullptr;

    func_t func;

    ret = bfelf_loader_resolve_symbol(&binaries.loader(), "lib1_foo", reinterpret_cast<void **>(&func));
    CHECK(ret == BFELF_SUCCESS);
}
