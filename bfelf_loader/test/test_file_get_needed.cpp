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
bfelf_loader_ut::test_bfelf_file_get_needed_invalid_ef()
{
    char *needed;
    uint64_t index = 0;

    auto ret = bfelf_file_get_needed(nullptr, index, &needed);
    this->expect_true(ret == BFELF_ERROR_INVALID_ARG);
}

void
bfelf_loader_ut::test_bfelf_file_get_needed_invalid_index()
{
    char *needed;
    uint64_t index = 0;
    bfelf_file_t ef = {};

    auto ret = bfelf_file_get_needed(&ef, index, &needed);
    this->expect_true(ret == BFELF_ERROR_INVALID_INDEX);
}

void
bfelf_loader_ut::test_bfelf_file_get_needed_invalid_size()
{
    uint64_t index = 0;
    bfelf_file_t ef = {};

    auto ret = bfelf_file_get_needed(&ef, index, nullptr);
    this->expect_true(ret == BFELF_ERROR_INVALID_ARG);
}

void
bfelf_loader_ut::test_bfelf_file_get_needed_success()
{
    auto ret = 0LL;
    bfelf_file_t dummy_misc_ef;
    bfelf_file_t dummy_code_ef;

    ret = bfelf_file_init(m_dummy_misc.get(), m_dummy_misc_length, &dummy_misc_ef);
    this->expect_true(ret == BFELF_SUCCESS);
    ret = bfelf_file_init(m_dummy_code.get(), m_dummy_code_length, &dummy_code_ef);
    this->expect_true(ret == BFELF_SUCCESS);

    auto &&dummy_misc_pair = get_elf_exec(&dummy_misc_ef);
    auto &&dummy_code_pair = get_elf_exec(&dummy_code_ef);

    m_dummy_misc_exec = std::move(std::get<0>(dummy_misc_pair));
    m_dummy_code_exec = std::move(std::get<0>(dummy_code_pair));

    bfelf_loader_t loader;
    memset(&loader, 0, sizeof(loader));

    ret = bfelf_loader_add(&loader, &dummy_misc_ef, m_dummy_misc_exec.get(), m_dummy_misc_exec.get());
    this->expect_true(ret == BFELF_SUCCESS);
    ret = bfelf_loader_add(&loader, &dummy_code_ef, m_dummy_code_exec.get(), m_dummy_code_exec.get());
    this->expect_true(ret == BFELF_SUCCESS);

    ret = bfelf_loader_relocate(&loader);
    this->expect_true(ret == BFELF_SUCCESS);

    char *needed;
    uint64_t index = 0;
    \
    ret = bfelf_file_get_needed(&dummy_misc_ef, index, &needed);
    this->expect_true(ret == BFELF_SUCCESS);
}
