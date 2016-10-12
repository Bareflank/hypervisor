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
bfelf_loader_ut::test_bfelf_loader_relocate_invalid_loader()
{
    auto ret = bfelf_loader_relocate(nullptr);
    this->expect_true(ret == BFELF_ERROR_INVALID_ARG);
}

void
bfelf_loader_ut::test_bfelf_loader_relocate_no_files_added()
{
    bfelf_loader_t loader;
    memset(&loader, 0, sizeof(loader));

    auto ret = bfelf_loader_relocate(&loader);
    this->expect_true(ret == BFELF_SUCCESS);
}

void
bfelf_loader_ut::test_bfelf_loader_relocate_uninitialized_files()
{
    auto ret = 0LL;
    bfelf_file_t ef1;
    bfelf_file_t ef2;
    bfelf_loader_t loader;

    memset(&ef1, 0, sizeof(ef1));
    memset(&ef2, 0, sizeof(ef2));
    memset(&loader, 0, sizeof(loader));

    ret = bfelf_loader_add(&loader, &ef1, nullptr);
    this->expect_true(ret == BFELF_SUCCESS);

    ret = bfelf_loader_add(&loader, &ef2, nullptr);
    this->expect_true(ret == BFELF_SUCCESS);

    ret = bfelf_loader_relocate(&loader);
    this->expect_true(ret == BFELF_SUCCESS);
}

void
bfelf_loader_ut::test_bfelf_loader_relocate_twice()
{
    auto ret = 0LL;
    bfelf_file_t ef1;
    bfelf_file_t ef2;
    bfelf_loader_t loader;

    memset(&ef1, 0, sizeof(ef1));
    memset(&ef2, 0, sizeof(ef2));
    memset(&loader, 0, sizeof(loader));

    ret = bfelf_loader_add(&loader, &ef1, nullptr);
    this->expect_true(ret == BFELF_SUCCESS);

    ret = bfelf_loader_add(&loader, &ef2, nullptr);
    this->expect_true(ret == BFELF_SUCCESS);

    ret = bfelf_loader_relocate(&loader);
    this->expect_true(ret == BFELF_SUCCESS);

    ret = bfelf_loader_relocate(&loader);
    this->expect_true(ret == BFELF_SUCCESS);
}
