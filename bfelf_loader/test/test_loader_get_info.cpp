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

// -----------------------------------------------------------------------------
// Expose Private Functions
// -----------------------------------------------------------------------------

extern "C"
{
    int64_t
    private_get_section_by_name(struct bfelf_file_t *ef,
                                struct e_string_t *name,
                                struct bfelf_shdr **shdr);

    int64_t
    private_check_section(struct bfelf_shdr *shdr,
                          bfelf64_word type,
                          bfelf64_xword flags,
                          bfelf64_xword addralign,
                          bfelf64_xword entsize);
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

void
bfelf_loader_ut::test_bfelf_loader_get_info_invalid_loader()
{
    bfelf_file_t ef;
    section_info_t info;

    auto ret = bfelf_loader_get_info(nullptr, &ef, &info);
    this->expect_true(ret == BFELF_ERROR_INVALID_ARG);
}

void
bfelf_loader_ut::test_bfelf_loader_get_info_invalid_elf_file()
{
    section_info_t info;
    bfelf_loader_t loader;

    memset(&loader, 0, sizeof(loader));

    auto ret = bfelf_loader_get_info(&loader, nullptr, &info);
    this->expect_true(ret == BFELF_ERROR_INVALID_ARG);
}

void
bfelf_loader_ut::test_bfelf_loader_get_info_invalid_info()
{
    bfelf_file_t ef;
    bfelf_loader_t loader;

    memset(&loader, 0, sizeof(loader));

    auto ret = bfelf_loader_get_info(&loader, &ef, nullptr);
    this->expect_true(ret == BFELF_ERROR_INVALID_ARG);
}

void
bfelf_loader_ut::test_bfelf_loader_get_info_no_relocation()
{
    bfelf_file_t ef;
    section_info_t info;
    bfelf_loader_t loader;

    memset(&loader, 0, sizeof(loader));

    auto ret = bfelf_loader_get_info(&loader, &ef, &info);
    this->expect_true(ret == BFELF_ERROR_OUT_OF_ORDER);
}

void
bfelf_loader_ut::test_bfelf_loader_get_info_expected_misc_resources()
{
    auto ret = 0LL;
    bfelf_file_t dummy_misc_ef;
    bfelf_file_t dummy_code_ef;

    ret = bfelf_file_init(m_dummy_misc.get(), m_dummy_misc_length, &dummy_misc_ef);
    this->expect_true(ret == BFELF_SUCCESS);
    ret = bfelf_file_init(m_dummy_code.get(), m_dummy_code_length, &dummy_code_ef);
    this->expect_true(ret == BFELF_SUCCESS);

    m_dummy_misc_exec = load_elf_file(&dummy_misc_ef);
    m_dummy_code_exec = load_elf_file(&dummy_code_ef);

    bfelf_loader_t loader;
    memset(&loader, 0, sizeof(loader));

    ret = bfelf_loader_add(&loader, &dummy_misc_ef, m_dummy_misc_exec.get());
    this->expect_true(ret == BFELF_SUCCESS);
    ret = bfelf_loader_add(&loader, &dummy_code_ef, m_dummy_code_exec.get());
    this->expect_true(ret == BFELF_SUCCESS);

    ret = bfelf_loader_relocate(&loader);
    this->expect_true(ret == BFELF_SUCCESS);

    section_info_t info;

    ret = bfelf_loader_get_info(&loader, &dummy_misc_ef, &info);
    this->expect_true(ret == BFELF_SUCCESS);

    this->expect_true(info.ctors_addr != nullptr || info.init_array_addr != nullptr);
    this->expect_true(info.ctors_size != 0 || info.init_array_size != 0);

    this->expect_true(info.dtors_addr != nullptr || info.init_array_addr != nullptr);
    this->expect_true(info.dtors_size != 0 || info.init_array_size != 0);

    this->expect_true(info.eh_frame_addr != nullptr);
    this->expect_true(info.eh_frame_size != 0);
}

void
bfelf_loader_ut::test_bfelf_loader_get_info_expected_code_resources()
{
    auto ret = 0LL;
    bfelf_file_t dummy_misc_ef;
    bfelf_file_t dummy_code_ef;

    ret = bfelf_file_init(m_dummy_misc.get(), m_dummy_misc_length, &dummy_misc_ef);
    this->expect_true(ret == BFELF_SUCCESS);
    ret = bfelf_file_init(m_dummy_code.get(), m_dummy_code_length, &dummy_code_ef);
    this->expect_true(ret == BFELF_SUCCESS);

    m_dummy_misc_exec = load_elf_file(&dummy_misc_ef);
    m_dummy_code_exec = load_elf_file(&dummy_code_ef);

    bfelf_loader_t loader;
    memset(&loader, 0, sizeof(loader));

    ret = bfelf_loader_add(&loader, &dummy_misc_ef, m_dummy_misc_exec.get());
    this->expect_true(ret == BFELF_SUCCESS);
    ret = bfelf_loader_add(&loader, &dummy_code_ef, m_dummy_code_exec.get());
    this->expect_true(ret == BFELF_SUCCESS);

    ret = bfelf_loader_relocate(&loader);
    this->expect_true(ret == BFELF_SUCCESS);

    section_info_t info;
    memset(&info, 0, sizeof(info));

    ret = bfelf_loader_get_info(&loader, &dummy_code_ef, &info);
    this->expect_true(ret == BFELF_SUCCESS);

    this->expect_true(info.ctors_addr == nullptr);
    this->expect_true(info.ctors_size == 0);

    this->expect_true(info.dtors_addr == nullptr);
    this->expect_true(info.dtors_size == 0);

    this->expect_true(info.eh_frame_addr != nullptr);
    this->expect_true(info.eh_frame_size != 0);
}

void
bfelf_loader_ut::test_bfelf_loader_get_info_get_section_name_failure_ctors()
{
    auto ret = 0LL;
    bfelf_file_t dummy_misc_ef;
    bfelf_file_t dummy_code_ef;

    ret = bfelf_file_init(m_dummy_misc.get(), m_dummy_misc_length, &dummy_misc_ef);
    this->expect_true(ret == BFELF_SUCCESS);
    ret = bfelf_file_init(m_dummy_code.get(), m_dummy_code_length, &dummy_code_ef);
    this->expect_true(ret == BFELF_SUCCESS);

    m_dummy_misc_exec = load_elf_file(&dummy_misc_ef);
    m_dummy_code_exec = load_elf_file(&dummy_code_ef);

    bfelf_loader_t loader;
    memset(&loader, 0, sizeof(loader));

    ret = bfelf_loader_add(&loader, &dummy_misc_ef, m_dummy_misc_exec.get());
    this->expect_true(ret == BFELF_SUCCESS);
    ret = bfelf_loader_add(&loader, &dummy_code_ef, m_dummy_code_exec.get());
    this->expect_true(ret == BFELF_SUCCESS);

    ret = bfelf_loader_relocate(&loader);
    this->expect_true(ret == BFELF_SUCCESS);

    section_info_t info;
    memset(&info, 0, sizeof(info));

    MockRepository mocks;
    mocks.ExpectCallFunc(private_get_section_by_name).Return(-1);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        ret = bfelf_loader_get_info(&loader, &dummy_code_ef, &info);
        this->expect_true(ret == -1);
    });
}

void
bfelf_loader_ut::test_bfelf_loader_get_info_check_section_name_failure_ctors()
{
    auto ret = 0LL;
    bfelf_file_t dummy_misc_ef;
    bfelf_file_t dummy_code_ef;

    ret = bfelf_file_init(m_dummy_misc.get(), m_dummy_misc_length, &dummy_misc_ef);
    this->expect_true(ret == BFELF_SUCCESS);
    ret = bfelf_file_init(m_dummy_code.get(), m_dummy_code_length, &dummy_code_ef);
    this->expect_true(ret == BFELF_SUCCESS);

    m_dummy_misc_exec = load_elf_file(&dummy_misc_ef);
    m_dummy_code_exec = load_elf_file(&dummy_code_ef);

    bfelf_loader_t loader;
    memset(&loader, 0, sizeof(loader));

    ret = bfelf_loader_add(&loader, &dummy_misc_ef, m_dummy_misc_exec.get());
    this->expect_true(ret == BFELF_SUCCESS);
    ret = bfelf_loader_add(&loader, &dummy_code_ef, m_dummy_code_exec.get());
    this->expect_true(ret == BFELF_SUCCESS);

    ret = bfelf_loader_relocate(&loader);
    this->expect_true(ret == BFELF_SUCCESS);

    section_info_t info;
    memset(&info, 0, sizeof(info));

    MockRepository mocks;
    mocks.ExpectCallFunc(private_get_section_by_name).Do([&](auto, auto, auto * shdr)
    {
        *shdr = reinterpret_cast<bfelf_shdr *>(shdr);
        return BFELF_SUCCESS;
    });
    mocks.ExpectCallFunc(private_check_section).Return(-1);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        ret = bfelf_loader_get_info(&loader, &dummy_code_ef, &info);
        this->expect_true(ret == -1);
    });
}

void
bfelf_loader_ut::test_bfelf_loader_get_info_get_section_name_failure_dtors()
{
    auto ret = 0LL;
    bfelf_file_t dummy_misc_ef;
    bfelf_file_t dummy_code_ef;

    ret = bfelf_file_init(m_dummy_misc.get(), m_dummy_misc_length, &dummy_misc_ef);
    this->expect_true(ret == BFELF_SUCCESS);
    ret = bfelf_file_init(m_dummy_code.get(), m_dummy_code_length, &dummy_code_ef);
    this->expect_true(ret == BFELF_SUCCESS);

    m_dummy_misc_exec = load_elf_file(&dummy_misc_ef);
    m_dummy_code_exec = load_elf_file(&dummy_code_ef);

    bfelf_loader_t loader;
    memset(&loader, 0, sizeof(loader));

    ret = bfelf_loader_add(&loader, &dummy_misc_ef, m_dummy_misc_exec.get());
    this->expect_true(ret == BFELF_SUCCESS);
    ret = bfelf_loader_add(&loader, &dummy_code_ef, m_dummy_code_exec.get());
    this->expect_true(ret == BFELF_SUCCESS);

    ret = bfelf_loader_relocate(&loader);
    this->expect_true(ret == BFELF_SUCCESS);

    section_info_t info;
    memset(&info, 0, sizeof(info));

    MockRepository mocks;
    mocks.ExpectCallFunc(private_get_section_by_name).Do([&](auto, auto, auto * shdr)
    {
        *shdr = nullptr;
        return BFELF_SUCCESS;
    });
    mocks.ExpectCallFunc(private_get_section_by_name).Return(-1);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        ret = bfelf_loader_get_info(&loader, &dummy_code_ef, &info);
        this->expect_true(ret == -1);
    });
}

void
bfelf_loader_ut::test_bfelf_loader_get_info_check_section_name_failure_dtors()
{
    auto ret = 0LL;
    bfelf_file_t dummy_misc_ef;
    bfelf_file_t dummy_code_ef;

    ret = bfelf_file_init(m_dummy_misc.get(), m_dummy_misc_length, &dummy_misc_ef);
    this->expect_true(ret == BFELF_SUCCESS);
    ret = bfelf_file_init(m_dummy_code.get(), m_dummy_code_length, &dummy_code_ef);
    this->expect_true(ret == BFELF_SUCCESS);

    m_dummy_misc_exec = load_elf_file(&dummy_misc_ef);
    m_dummy_code_exec = load_elf_file(&dummy_code_ef);

    bfelf_loader_t loader;
    memset(&loader, 0, sizeof(loader));

    ret = bfelf_loader_add(&loader, &dummy_misc_ef, m_dummy_misc_exec.get());
    this->expect_true(ret == BFELF_SUCCESS);
    ret = bfelf_loader_add(&loader, &dummy_code_ef, m_dummy_code_exec.get());
    this->expect_true(ret == BFELF_SUCCESS);

    ret = bfelf_loader_relocate(&loader);
    this->expect_true(ret == BFELF_SUCCESS);

    section_info_t info;
    memset(&info, 0, sizeof(info));

    MockRepository mocks;
    mocks.ExpectCallFunc(private_get_section_by_name).Do([&](auto, auto, auto * shdr)
    {
        *shdr = nullptr;
        return BFELF_SUCCESS;
    });
    mocks.ExpectCallFunc(private_get_section_by_name).Do([&](auto, auto, auto * shdr)
    {
        *shdr = reinterpret_cast<bfelf_shdr *>(shdr);
        return BFELF_SUCCESS;
    });
    mocks.ExpectCallFunc(private_check_section).Return(-1);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        ret = bfelf_loader_get_info(&loader, &dummy_code_ef, &info);
        this->expect_true(ret == -1);
    });
}

void
bfelf_loader_ut::test_bfelf_loader_get_info_get_section_name_failure_init_array()
{
    auto ret = 0LL;
    bfelf_file_t dummy_misc_ef;
    bfelf_file_t dummy_code_ef;

    ret = bfelf_file_init(m_dummy_misc.get(), m_dummy_misc_length, &dummy_misc_ef);
    this->expect_true(ret == BFELF_SUCCESS);
    ret = bfelf_file_init(m_dummy_code.get(), m_dummy_code_length, &dummy_code_ef);
    this->expect_true(ret == BFELF_SUCCESS);

    m_dummy_misc_exec = load_elf_file(&dummy_misc_ef);
    m_dummy_code_exec = load_elf_file(&dummy_code_ef);

    bfelf_loader_t loader;
    memset(&loader, 0, sizeof(loader));

    ret = bfelf_loader_add(&loader, &dummy_misc_ef, m_dummy_misc_exec.get());
    this->expect_true(ret == BFELF_SUCCESS);
    ret = bfelf_loader_add(&loader, &dummy_code_ef, m_dummy_code_exec.get());
    this->expect_true(ret == BFELF_SUCCESS);

    ret = bfelf_loader_relocate(&loader);
    this->expect_true(ret == BFELF_SUCCESS);

    section_info_t info;
    memset(&info, 0, sizeof(info));

    MockRepository mocks;
    mocks.ExpectCallFunc(private_get_section_by_name).Do([&](auto, auto, auto * shdr)
    {
        *shdr = nullptr;
        return BFELF_SUCCESS;
    });
    mocks.ExpectCallFunc(private_get_section_by_name).Do([&](auto, auto, auto * shdr)
    {
        *shdr = nullptr;
        return BFELF_SUCCESS;
    });
    mocks.ExpectCallFunc(private_get_section_by_name).Return(-1);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        ret = bfelf_loader_get_info(&loader, &dummy_code_ef, &info);
        this->expect_true(ret == -1);
    });
}

void
bfelf_loader_ut::test_bfelf_loader_get_info_check_section_name_failure_init_array()
{
    auto ret = 0LL;
    bfelf_file_t dummy_misc_ef;
    bfelf_file_t dummy_code_ef;

    ret = bfelf_file_init(m_dummy_misc.get(), m_dummy_misc_length, &dummy_misc_ef);
    this->expect_true(ret == BFELF_SUCCESS);
    ret = bfelf_file_init(m_dummy_code.get(), m_dummy_code_length, &dummy_code_ef);
    this->expect_true(ret == BFELF_SUCCESS);

    m_dummy_misc_exec = load_elf_file(&dummy_misc_ef);
    m_dummy_code_exec = load_elf_file(&dummy_code_ef);

    bfelf_loader_t loader;
    memset(&loader, 0, sizeof(loader));

    ret = bfelf_loader_add(&loader, &dummy_misc_ef, m_dummy_misc_exec.get());
    this->expect_true(ret == BFELF_SUCCESS);
    ret = bfelf_loader_add(&loader, &dummy_code_ef, m_dummy_code_exec.get());
    this->expect_true(ret == BFELF_SUCCESS);

    ret = bfelf_loader_relocate(&loader);
    this->expect_true(ret == BFELF_SUCCESS);

    section_info_t info;
    memset(&info, 0, sizeof(info));

    MockRepository mocks;
    mocks.ExpectCallFunc(private_get_section_by_name).Do([&](auto, auto, auto * shdr)
    {
        *shdr = nullptr;
        return BFELF_SUCCESS;
    });
    mocks.ExpectCallFunc(private_get_section_by_name).Do([&](auto, auto, auto * shdr)
    {
        *shdr = nullptr;
        return BFELF_SUCCESS;
    });
    mocks.ExpectCallFunc(private_get_section_by_name).Do([&](auto, auto, auto * shdr)
    {
        *shdr = reinterpret_cast<bfelf_shdr *>(shdr);
        return BFELF_SUCCESS;
    });
    mocks.ExpectCallFunc(private_check_section).Return(-1);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        ret = bfelf_loader_get_info(&loader, &dummy_code_ef, &info);
        this->expect_true(ret == -1);
    });
}

void
bfelf_loader_ut::test_bfelf_loader_get_info_get_section_name_failure_fini_array()
{
    auto ret = 0LL;
    bfelf_file_t dummy_misc_ef;
    bfelf_file_t dummy_code_ef;

    ret = bfelf_file_init(m_dummy_misc.get(), m_dummy_misc_length, &dummy_misc_ef);
    this->expect_true(ret == BFELF_SUCCESS);
    ret = bfelf_file_init(m_dummy_code.get(), m_dummy_code_length, &dummy_code_ef);
    this->expect_true(ret == BFELF_SUCCESS);

    m_dummy_misc_exec = load_elf_file(&dummy_misc_ef);
    m_dummy_code_exec = load_elf_file(&dummy_code_ef);

    bfelf_loader_t loader;
    memset(&loader, 0, sizeof(loader));

    ret = bfelf_loader_add(&loader, &dummy_misc_ef, m_dummy_misc_exec.get());
    this->expect_true(ret == BFELF_SUCCESS);
    ret = bfelf_loader_add(&loader, &dummy_code_ef, m_dummy_code_exec.get());
    this->expect_true(ret == BFELF_SUCCESS);

    ret = bfelf_loader_relocate(&loader);
    this->expect_true(ret == BFELF_SUCCESS);

    section_info_t info;
    memset(&info, 0, sizeof(info));

    MockRepository mocks;
    mocks.ExpectCallFunc(private_get_section_by_name).Do([&](auto, auto, auto * shdr)
    {
        *shdr = nullptr;
        return BFELF_SUCCESS;
    });
    mocks.ExpectCallFunc(private_get_section_by_name).Do([&](auto, auto, auto * shdr)
    {
        *shdr = nullptr;
        return BFELF_SUCCESS;
    });
    mocks.ExpectCallFunc(private_get_section_by_name).Do([&](auto, auto, auto * shdr)
    {
        *shdr = nullptr;
        return BFELF_SUCCESS;
    });
    mocks.ExpectCallFunc(private_get_section_by_name).Return(-1);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        ret = bfelf_loader_get_info(&loader, &dummy_code_ef, &info);
        this->expect_true(ret == -1);
    });
}

void
bfelf_loader_ut::test_bfelf_loader_get_info_check_section_name_failure_fini_array()
{
    auto ret = 0LL;
    bfelf_file_t dummy_misc_ef;
    bfelf_file_t dummy_code_ef;

    ret = bfelf_file_init(m_dummy_misc.get(), m_dummy_misc_length, &dummy_misc_ef);
    this->expect_true(ret == BFELF_SUCCESS);
    ret = bfelf_file_init(m_dummy_code.get(), m_dummy_code_length, &dummy_code_ef);
    this->expect_true(ret == BFELF_SUCCESS);

    m_dummy_misc_exec = load_elf_file(&dummy_misc_ef);
    m_dummy_code_exec = load_elf_file(&dummy_code_ef);

    bfelf_loader_t loader;
    memset(&loader, 0, sizeof(loader));

    ret = bfelf_loader_add(&loader, &dummy_misc_ef, m_dummy_misc_exec.get());
    this->expect_true(ret == BFELF_SUCCESS);
    ret = bfelf_loader_add(&loader, &dummy_code_ef, m_dummy_code_exec.get());
    this->expect_true(ret == BFELF_SUCCESS);

    ret = bfelf_loader_relocate(&loader);
    this->expect_true(ret == BFELF_SUCCESS);

    section_info_t info;
    memset(&info, 0, sizeof(info));

    MockRepository mocks;
    mocks.ExpectCallFunc(private_get_section_by_name).Do([&](auto, auto, auto * shdr)
    {
        *shdr = nullptr;
        return BFELF_SUCCESS;
    });
    mocks.ExpectCallFunc(private_get_section_by_name).Do([&](auto, auto, auto * shdr)
    {
        *shdr = nullptr;
        return BFELF_SUCCESS;
    });
    mocks.ExpectCallFunc(private_get_section_by_name).Do([&](auto, auto, auto * shdr)
    {
        *shdr = nullptr;
        return BFELF_SUCCESS;
    });
    mocks.ExpectCallFunc(private_get_section_by_name).Do([&](auto, auto, auto * shdr)
    {
        *shdr = reinterpret_cast<bfelf_shdr *>(shdr);
        return BFELF_SUCCESS;
    });
    mocks.ExpectCallFunc(private_check_section).Return(-1);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        ret = bfelf_loader_get_info(&loader, &dummy_code_ef, &info);
        this->expect_true(ret == -1);
    });
}

void
bfelf_loader_ut::test_bfelf_loader_get_info_get_section_name_failure_eh_frame()
{
    auto ret = 0LL;
    bfelf_file_t dummy_misc_ef;
    bfelf_file_t dummy_code_ef;

    ret = bfelf_file_init(m_dummy_misc.get(), m_dummy_misc_length, &dummy_misc_ef);
    this->expect_true(ret == BFELF_SUCCESS);
    ret = bfelf_file_init(m_dummy_code.get(), m_dummy_code_length, &dummy_code_ef);
    this->expect_true(ret == BFELF_SUCCESS);

    m_dummy_misc_exec = load_elf_file(&dummy_misc_ef);
    m_dummy_code_exec = load_elf_file(&dummy_code_ef);

    bfelf_loader_t loader;
    memset(&loader, 0, sizeof(loader));

    ret = bfelf_loader_add(&loader, &dummy_misc_ef, m_dummy_misc_exec.get());
    this->expect_true(ret == BFELF_SUCCESS);
    ret = bfelf_loader_add(&loader, &dummy_code_ef, m_dummy_code_exec.get());
    this->expect_true(ret == BFELF_SUCCESS);

    ret = bfelf_loader_relocate(&loader);
    this->expect_true(ret == BFELF_SUCCESS);

    section_info_t info;
    memset(&info, 0, sizeof(info));

    MockRepository mocks;
    mocks.ExpectCallFunc(private_get_section_by_name).Do([&](auto, auto, auto * shdr)
    {
        *shdr = nullptr;
        return BFELF_SUCCESS;
    });
    mocks.ExpectCallFunc(private_get_section_by_name).Do([&](auto, auto, auto * shdr)
    {
        *shdr = nullptr;
        return BFELF_SUCCESS;
    });
    mocks.ExpectCallFunc(private_get_section_by_name).Do([&](auto, auto, auto * shdr)
    {
        *shdr = nullptr;
        return BFELF_SUCCESS;
    });
    mocks.ExpectCallFunc(private_get_section_by_name).Do([&](auto, auto, auto * shdr)
    {
        *shdr = nullptr;
        return BFELF_SUCCESS;
    });
    mocks.ExpectCallFunc(private_get_section_by_name).Return(-1);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        ret = bfelf_loader_get_info(&loader, &dummy_code_ef, &info);
        this->expect_true(ret == -1);
    });
}

void
bfelf_loader_ut::test_bfelf_loader_get_info_check_section_name_failure_eh_frame()
{
    auto ret = 0LL;
    bfelf_file_t dummy_misc_ef;
    bfelf_file_t dummy_code_ef;

    ret = bfelf_file_init(m_dummy_misc.get(), m_dummy_misc_length, &dummy_misc_ef);
    this->expect_true(ret == BFELF_SUCCESS);
    ret = bfelf_file_init(m_dummy_code.get(), m_dummy_code_length, &dummy_code_ef);
    this->expect_true(ret == BFELF_SUCCESS);

    m_dummy_misc_exec = load_elf_file(&dummy_misc_ef);
    m_dummy_code_exec = load_elf_file(&dummy_code_ef);

    bfelf_loader_t loader;
    memset(&loader, 0, sizeof(loader));

    ret = bfelf_loader_add(&loader, &dummy_misc_ef, m_dummy_misc_exec.get());
    this->expect_true(ret == BFELF_SUCCESS);
    ret = bfelf_loader_add(&loader, &dummy_code_ef, m_dummy_code_exec.get());
    this->expect_true(ret == BFELF_SUCCESS);

    ret = bfelf_loader_relocate(&loader);
    this->expect_true(ret == BFELF_SUCCESS);

    section_info_t info;
    memset(&info, 0, sizeof(info));

    MockRepository mocks;
    mocks.ExpectCallFunc(private_get_section_by_name).Do([&](auto, auto, auto * shdr)
    {
        *shdr = nullptr;
        return BFELF_SUCCESS;
    });
    mocks.ExpectCallFunc(private_get_section_by_name).Do([&](auto, auto, auto * shdr)
    {
        *shdr = nullptr;
        return BFELF_SUCCESS;
    });
    mocks.ExpectCallFunc(private_get_section_by_name).Do([&](auto, auto, auto * shdr)
    {
        *shdr = nullptr;
        return BFELF_SUCCESS;
    });
    mocks.ExpectCallFunc(private_get_section_by_name).Do([&](auto, auto, auto * shdr)
    {
        *shdr = nullptr;
        return BFELF_SUCCESS;
    });
    mocks.ExpectCallFunc(private_get_section_by_name).Do([&](auto, auto, auto * shdr)
    {
        *shdr = reinterpret_cast<bfelf_shdr *>(shdr);
        return BFELF_SUCCESS;
    });
    mocks.ExpectCallFunc(private_check_section).Return(-1);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        ret = bfelf_loader_get_info(&loader, &dummy_code_ef, &info);
        this->expect_true(ret == -1);
    });
}

void
bfelf_loader_ut::test_bfelf_loader_get_info_all()
{
    auto ret = 0LL;
    bfelf_file_t dummy_misc_ef;
    bfelf_file_t dummy_code_ef;

    ret = bfelf_file_init(m_dummy_misc.get(), m_dummy_misc_length, &dummy_misc_ef);
    this->expect_true(ret == BFELF_SUCCESS);
    ret = bfelf_file_init(m_dummy_code.get(), m_dummy_code_length, &dummy_code_ef);
    this->expect_true(ret == BFELF_SUCCESS);

    m_dummy_misc_exec = load_elf_file(&dummy_misc_ef);
    m_dummy_code_exec = load_elf_file(&dummy_code_ef);

    bfelf_loader_t loader;
    memset(&loader, 0, sizeof(loader));

    ret = bfelf_loader_add(&loader, &dummy_misc_ef, m_dummy_misc_exec.get());
    this->expect_true(ret == BFELF_SUCCESS);
    ret = bfelf_loader_add(&loader, &dummy_code_ef, m_dummy_code_exec.get());
    this->expect_true(ret == BFELF_SUCCESS);

    ret = bfelf_loader_relocate(&loader);
    this->expect_true(ret == BFELF_SUCCESS);

    section_info_t info;
    memset(&info, 0, sizeof(info));

    MockRepository mocks;
    mocks.ExpectCallFunc(private_get_section_by_name).Do([&](auto, auto, auto * shdr)
    {
        *shdr = reinterpret_cast<bfelf_shdr *>(shdr);
        return BFELF_SUCCESS;
    });
    mocks.ExpectCallFunc(private_check_section).Return(BFELF_SUCCESS);
    mocks.ExpectCallFunc(private_get_section_by_name).Do([&](auto, auto, auto * shdr)
    {
        *shdr = reinterpret_cast<bfelf_shdr *>(shdr);
        return BFELF_SUCCESS;
    });
    mocks.ExpectCallFunc(private_check_section).Return(BFELF_SUCCESS);
    mocks.ExpectCallFunc(private_get_section_by_name).Do([&](auto, auto, auto * shdr)
    {
        *shdr = reinterpret_cast<bfelf_shdr *>(shdr);
        return BFELF_SUCCESS;
    });
    mocks.ExpectCallFunc(private_check_section).Return(BFELF_SUCCESS);
    mocks.ExpectCallFunc(private_get_section_by_name).Do([&](auto, auto, auto * shdr)
    {
        *shdr = reinterpret_cast<bfelf_shdr *>(shdr);
        return BFELF_SUCCESS;
    });
    mocks.ExpectCallFunc(private_check_section).Return(BFELF_SUCCESS);
    mocks.ExpectCallFunc(private_get_section_by_name).Do([&](auto, auto, auto * shdr)
    {
        *shdr = reinterpret_cast<bfelf_shdr *>(shdr);
        return BFELF_SUCCESS;
    });
    mocks.ExpectCallFunc(private_check_section).Return(BFELF_SUCCESS);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        ret = bfelf_loader_get_info(&loader, &dummy_code_ef, &info);
        this->expect_true(ret == BFELF_SUCCESS);
    });
}
