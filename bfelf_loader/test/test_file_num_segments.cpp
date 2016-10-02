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
bfelf_loader_ut::test_bfelf_file_num_segments_invalid_ef()
{
    auto ret = bfelf_file_num_segments(nullptr);
    this->expect_true(ret == BFELF_ERROR_INVALID_ARG);
}

void
bfelf_loader_ut::test_bfelf_file_num_segments_uninitalized()
{
    bfelf_file_t ef;
    memset(&ef, 0, sizeof(ef));

    auto ret = bfelf_file_num_segments(&ef);
    this->expect_true(ret == 0);
}

void
bfelf_loader_ut::test_bfelf_file_num_segments_success()
{
    auto ret = 0LL;
    bfelf_file_t ef;
    auto test = get_test();

    ret = bfelf_file_init(reinterpret_cast<char *>(&test), sizeof(test), &ef);
    this->expect_true(ret == BFELF_SUCCESS);

    ret = bfelf_file_num_segments(&ef);
    this->expect_true(ret > 0);
}
