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
#include <test_fake_elf.h>

TEST_CASE("bfelf_file_get_num_load_instrs: invalid elf file")
{
    auto ret = bfelf_file_get_num_load_instrs(nullptr);
    CHECK(ret == BFELF_ERROR_INVALID_ARG);
}

TEST_CASE("bfelf_file_get_num_load_instrs: uninitialized")
{
    bfelf_file_t ef = {};

    auto ret = bfelf_file_get_num_load_instrs(&ef);
    CHECK(ret == 0);
}

TEST_CASE("bfelf_file_get_num_load_instrs: success")
{
    int64_t ret = 0;
    bfelf_file_t ef = {};

    auto data = get_fake_elf();
    auto &buf = std::get<0>(data);
    auto size = std::get<1>(data);

    ret = bfelf_file_init(buf.get(), size, &ef);
    CHECK(ret == BFELF_SUCCESS);

    ret = bfelf_file_get_num_load_instrs(&ef);
    CHECK(ret > 0);
}
