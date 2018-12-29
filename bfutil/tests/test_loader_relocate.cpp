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

#include <catch/catch.hpp>
#include <test_real_elf.h>

TEST_CASE("bfelf_loader_relocate: invalid loader")
{
    auto ret = bfelf_loader_relocate(nullptr);
    CHECK(ret == BFELF_ERROR_INVALID_ARG);
}

TEST_CASE("bfelf_loader_relocate: no files added")
{
    bfelf_loader_t loader = {};

    auto ret = bfelf_loader_relocate(&loader);
    CHECK(ret == BFELF_SUCCESS);
}

TEST_CASE("bfelf_loader_relocate: success")
{
    binaries_info binaries{&g_file, g_filenames};
}

TEST_CASE("bfelf_loader_relocate: twice")
{
    int64_t ret = 0;
    binaries_info binaries{&g_file, g_filenames};

    ret = bfelf_loader_relocate(&binaries.loader());
    CHECK(ret == BFELF_SUCCESS);
}

#ifndef WIN64

TEST_CASE("bfelf_loader_relocate: no such symbol")
{
    int64_t ret = 0;
    binaries_info binaries{&g_file, g_filenames};

    binaries.ef(0) = {};
    binaries.loader().relocated = 0;

    ret = bfelf_loader_relocate(&binaries.loader());
    CHECK(ret == BFELF_ERROR_NO_SUCH_SYMBOL);
}

TEST_CASE("bfelf_loader_relocate: no such symbol in plt")
{
    int64_t ret = 0;
    binaries_info binaries{&g_file, g_filenames};

    binaries.ef(0) = {};
    binaries.loader().relocated = 0;

    for (auto i = 0ULL; i < 9; i++) {
        binaries.ef(i).relanum_dyn = 0;
    }

    ret = bfelf_loader_relocate(&binaries.loader());
    CHECK(ret == BFELF_ERROR_NO_SUCH_SYMBOL);
}

#endif
