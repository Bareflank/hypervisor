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
bfelf_loader_ut::test_bfelf_loader_add_invalid_loader()
{
    auto ret = 0LL;
    bfelf_file_t dummy_misc_ef;

    ret = bfelf_file_init(m_dummy_misc.get(), m_dummy_misc_length, &dummy_misc_ef);
    this->expect_true(ret == BFELF_SUCCESS);

    ret = bfelf_loader_add(nullptr, &dummy_misc_ef, m_dummy_misc_exec.get(), m_dummy_misc_exec.get());
    this->expect_true(ret == BFELF_ERROR_INVALID_ARG);
}

void
bfelf_loader_ut::test_bfelf_loader_add_invalid_elf_file()
{
    bfelf_loader_t loader;
    memset(&loader, 0, sizeof(loader));

    auto ret = bfelf_loader_add(&loader, nullptr, m_dummy_misc_exec.get(), m_dummy_misc_exec.get());
    this->expect_true(ret == BFELF_ERROR_INVALID_ARG);
}

void
bfelf_loader_ut::test_bfelf_loader_add_invalid_addr()
{
    auto ret = 0LL;

    bfelf_loader_t loader;
    memset(&loader, 0, sizeof(loader));

    bfelf_file_t dummy_misc_ef;

    ret = bfelf_file_init(m_dummy_misc.get(), m_dummy_misc_length, &dummy_misc_ef);
    this->expect_true(ret == BFELF_SUCCESS);

    ret = bfelf_loader_add(&loader, &dummy_misc_ef, nullptr, m_dummy_misc_exec.get());
    this->expect_true(ret == BFELF_ERROR_INVALID_ARG);
}

void
bfelf_loader_ut::test_bfelf_loader_add_too_many_files()
{
    auto ret = 0LL;

    bfelf_loader_t loader;
    memset(&loader, 0, sizeof(loader));

    for (auto i = 0; i < MAX_NUM_MODULES + 1; i++)
    {
        bfelf_file_t dummy_misc_ef;

        ret = bfelf_file_init(m_dummy_misc.get(), m_dummy_misc_length, &dummy_misc_ef);
        this->expect_true(ret == BFELF_SUCCESS);

        auto &&dummy_misc_pair = get_elf_exec(&dummy_misc_ef);
        auto &&dummy_misc_exec = std::move(std::get<0>(dummy_misc_pair));

        ret = bfelf_loader_add(&loader, &dummy_misc_ef, dummy_misc_exec.get(), dummy_misc_exec.get());

        if (i < MAX_NUM_MODULES)
        {
            this->expect_true(ret == BFELF_SUCCESS);
        }
        else
        {
            this->expect_true(ret == BFELF_ERROR_LOADER_FULL);
        }
    }
}

void
bfelf_loader_ut::test_bfelf_loader_add_fake()
{
    auto ret = 0LL;
    bfelf_file_t ef;

    auto &&data = get_test();
    auto &&buff = std::get<0>(data);
    auto &&size = std::get<1>(data);

    ret = bfelf_file_init(buff.get(), size, &ef);
    this->expect_true(ret == BFELF_SUCCESS);

    bfelf_loader_t loader;
    memset(&loader, 0, sizeof(loader));

    char nothing[10] = {};

    ret = bfelf_loader_add(&loader, &ef, static_cast<char *>(nothing), static_cast<char *>(nothing));
    this->expect_true(ret == BFELF_SUCCESS);
}
