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

TEST_CASE("bfelf_load_binaries: invalid file")
{
    // file *f = nullptr;
    // bfelf_loader_t loader = {};

    // CHECK_THROWS(bfelf_load_binaries(f, g_filenames, &loader));
}

// TEST_CASE("bfelf_load_binaries: invalid loader")
// {
//     bfelf_loader_t *loader = nullptr;
//     CHECK_THROWS(bfelf_load_binaries(&g_file, g_filenames, loader));
// }

// TEST_CASE("bfelf_load_binaries: no files")
// {
//     bfelf_loader_t loader = {};
//     CHECK_NOTHROW(bfelf_load_binaries(&g_file, {}, &loader));
// }

// TEST_CASE("bfelf_load_binaries: invalid filename")
// {
//     bfelf_loader_t loader = {};
//     CHECK_THROWS(bfelf_load_binaries(&g_file, {"bad_file_name"_s}, &loader));
// }

// TEST_CASE("bfelf_load_binaries: success")
// {
//     bfelf_loader_t loader = {};
//     CHECK_NOTHROW(bfelf_load_binaries(&g_file, g_filenames, &loader));
// }
