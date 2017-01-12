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

#include <test.h>

void
bfelf_loader_ut::test_bfelf_file_num_load_instrs_invalid_ef()
{
    auto ret = bfelf_file_num_load_instrs(nullptr);
    this->expect_true(ret == BFELF_ERROR_INVALID_ARG);
}

void
bfelf_loader_ut::test_bfelf_file_num_load_instrs_uninitalized()
{
    bfelf_file_t ef = {};

    auto ret = bfelf_file_num_load_instrs(&ef);
    this->expect_true(ret == 0);
}

void
bfelf_loader_ut::test_bfelf_file_num_load_instrs_success()
{
    auto ret = 0LL;

    bfelf_file_t ef;
    auto &&data = get_test();
    auto &&buff = std::get<0>(data);
    auto &&size = std::get<1>(data);

    ret = bfelf_file_init(buff.get(), size, &ef);
    this->expect_true(ret == BFELF_SUCCESS);

    ret = bfelf_file_num_load_instrs(&ef);
    this->expect_true(ret > 0);
}
