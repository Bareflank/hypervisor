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

TEST_CASE("bfelf_file_get_needed_list: invalid file")
{
    // bfelf_file_t *ef = nullptr;
    // CHECK_THROWS(bfelf_file_get_needed_list(ef));
}

// TEST_CASE("bfelf_file_get_needed_list: no needed")
// {
//     binaries_info binaries{&g_file, g_filenames};

//     auto needed_list = bfelf_file_get_needed_list(&binaries.ef(0));
//     CHECK(needed_list.empty());
// }

// TEST_CASE("bfelf_file_get_needed_list: success")
// {
//     binaries_info binaries{&g_file, g_filenames};

//     auto needed_list = bfelf_file_get_needed_list(&binaries.ef());
//     CHECK(needed_list.size() == g_filenames.size() - 1);
// }
