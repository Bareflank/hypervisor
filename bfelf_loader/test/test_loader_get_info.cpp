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
bfelf_loader_ut::test_bfelf_loader_get_info_invalid_loader()
{
    bfelf_file_t ef;
    section_info_t info;

    auto ret = bfelf_loader_get_info(0, &ef, &info);
    EXPECT_TRUE(ret == BFELF_ERROR_INVALID_ARG);
}

void
bfelf_loader_ut::test_bfelf_loader_get_info_invalid_elf_file()
{
    section_info_t info;
    bfelf_loader_t loader;

    memset(&loader, 0, sizeof(loader));

    auto ret = bfelf_loader_get_info(&loader, 0, &info);
    EXPECT_TRUE(ret == BFELF_ERROR_INVALID_ARG);
}

void
bfelf_loader_ut::test_bfelf_loader_get_info_invalid_info()
{
    bfelf_file_t ef;
    bfelf_loader_t loader;

    memset(&loader, 0, sizeof(loader));

    auto ret = bfelf_loader_get_info(&loader, &ef, 0);
    EXPECT_TRUE(ret == BFELF_ERROR_INVALID_ARG);
}

void
bfelf_loader_ut::test_bfelf_loader_get_info_no_relocation()
{
    bfelf_file_t ef;
    section_info_t info;
    bfelf_loader_t loader;

    memset(&loader, 0, sizeof(loader));

    auto ret = bfelf_loader_get_info(&loader, &ef, &info);
    EXPECT_TRUE(ret == BFELF_ERROR_OUT_OF_ORDER);
}

void
bfelf_loader_ut::test_bfelf_loader_get_info_expected_misc_resources()
{
    auto ret = 0;
    bfelf_file_t dummy_misc_ef;
    bfelf_file_t dummy_code_ef;

    ret = bfelf_file_init(m_dummy_misc.get(), m_dummy_misc_length, &dummy_misc_ef);
    ASSERT_TRUE(ret == BFELF_SUCCESS);
    ret = bfelf_file_init(m_dummy_code.get(), m_dummy_code_length, &dummy_code_ef);
    ASSERT_TRUE(ret == BFELF_SUCCESS);

    m_dummy_misc_exec = load_elf_file(&dummy_misc_ef);
    ASSERT_TRUE(m_dummy_misc_exec.get() != 0);
    m_dummy_code_exec = load_elf_file(&dummy_code_ef);
    ASSERT_TRUE(m_dummy_code_exec.get() != 0);

    bfelf_loader_t loader;
    memset(&loader, 0, sizeof(loader));

    ret = bfelf_loader_add(&loader, &dummy_misc_ef, m_dummy_misc_exec.get());
    ASSERT_TRUE(ret == BFELF_SUCCESS);
    ret = bfelf_loader_add(&loader, &dummy_code_ef, m_dummy_code_exec.get());
    ASSERT_TRUE(ret == BFELF_SUCCESS);

    ret = bfelf_loader_relocate(&loader);
    EXPECT_TRUE(ret == BFELF_SUCCESS);

    section_info_t info;

    ret = bfelf_loader_get_info(&loader, &dummy_misc_ef, &info);
    ASSERT_TRUE(ret == BFELF_SUCCESS);

    EXPECT_TRUE(info.ctors_addr != 0);
    EXPECT_TRUE(info.ctors_size != 0);

    EXPECT_TRUE(info.dtors_addr != 0);
    EXPECT_TRUE(info.dtors_size != 0);

    EXPECT_TRUE(info.eh_frame_addr != 0);
    EXPECT_TRUE(info.eh_frame_size != 0);
}

void
bfelf_loader_ut::test_bfelf_loader_get_info_expected_code_resources()
{
    auto ret = 0;
    bfelf_file_t dummy_misc_ef;
    bfelf_file_t dummy_code_ef;

    ret = bfelf_file_init(m_dummy_misc.get(), m_dummy_misc_length, &dummy_misc_ef);
    ASSERT_TRUE(ret == BFELF_SUCCESS);
    ret = bfelf_file_init(m_dummy_code.get(), m_dummy_code_length, &dummy_code_ef);
    ASSERT_TRUE(ret == BFELF_SUCCESS);

    m_dummy_misc_exec = load_elf_file(&dummy_misc_ef);
    ASSERT_TRUE(m_dummy_misc_exec.get() != 0);
    m_dummy_code_exec = load_elf_file(&dummy_code_ef);
    ASSERT_TRUE(m_dummy_code_exec.get() != 0);

    bfelf_loader_t loader;
    memset(&loader, 0, sizeof(loader));

    ret = bfelf_loader_add(&loader, &dummy_misc_ef, m_dummy_misc_exec.get());
    ASSERT_TRUE(ret == BFELF_SUCCESS);
    ret = bfelf_loader_add(&loader, &dummy_code_ef, m_dummy_code_exec.get());
    ASSERT_TRUE(ret == BFELF_SUCCESS);

    ret = bfelf_loader_relocate(&loader);
    EXPECT_TRUE(ret == BFELF_SUCCESS);

    section_info_t info;
    memset(&info, 0, sizeof(info));

    ret = bfelf_loader_get_info(&loader, &dummy_code_ef, &info);
    ASSERT_TRUE(ret == BFELF_SUCCESS);

    EXPECT_TRUE(info.ctors_addr == 0);
    EXPECT_TRUE(info.ctors_size == 0);

    EXPECT_TRUE(info.dtors_addr == 0);
    EXPECT_TRUE(info.dtors_size == 0);

    EXPECT_TRUE(info.eh_frame_addr != 0);
    EXPECT_TRUE(info.eh_frame_size != 0);
}
