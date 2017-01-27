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

typedef int (*func_t)(int);

void
bfelf_loader_ut::test_bfelf_loader_resolve_symbol_invalid_loader()
{
    func_t func;

    auto ret = bfelf_loader_resolve_symbol(nullptr, "foo", reinterpret_cast<void **>(&func));
    this->expect_true(ret == BFELF_ERROR_INVALID_ARG);
}

void
bfelf_loader_ut::test_bfelf_loader_resolve_symbol_invalid_name()
{
    func_t func;

    bfelf_loader_t loader;
    memset(&loader, 0, sizeof(loader));

    auto ret = bfelf_loader_resolve_symbol(&loader, nullptr, reinterpret_cast<void **>(&func));
    this->expect_true(ret == BFELF_ERROR_INVALID_ARG);
}

void
bfelf_loader_ut::test_bfelf_loader_resolve_symbol_invalid_addr()
{
    bfelf_loader_t loader;
    memset(&loader, 0, sizeof(loader));

    auto ret = bfelf_loader_resolve_symbol(&loader, "foo", nullptr);
    this->expect_true(ret == BFELF_ERROR_INVALID_ARG);
}

void
bfelf_loader_ut::test_bfelf_loader_resolve_symbol_no_files_added()
{
    auto ret = 0LL;

    bfelf_loader_t loader;
    memset(&loader, 0, sizeof(loader));

    ret = bfelf_loader_relocate(&loader);
    this->expect_true(ret == BFELF_SUCCESS);

    func_t func;

    ret = bfelf_loader_resolve_symbol(&loader, "foo", reinterpret_cast<void **>(&func));
    this->expect_true(ret == BFELF_ERROR_NO_SUCH_SYMBOL);
}

void
bfelf_loader_ut::test_bfelf_loader_resolve_symbol_uninitialized_files()
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

    memset(&dummy_misc_ef, 0, sizeof(dummy_misc_ef));
    memset(&dummy_code_ef, 0, sizeof(dummy_code_ef));

    ret = bfelf_loader_relocate(&loader);
    this->expect_true(ret == BFELF_SUCCESS);

    func_t func;

    ret = bfelf_loader_resolve_symbol(&loader, "foo", reinterpret_cast<void **>(&func));
    this->expect_true(ret == BFELF_ERROR_NO_SUCH_SYMBOL);
}

void
bfelf_loader_ut::test_bfelf_loader_resolve_no_such_symbol()
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

    func_t func;

    ret = bfelf_loader_resolve_symbol(&loader, "invalid_sym", reinterpret_cast<void **>(&func));
    this->expect_true(ret == BFELF_ERROR_NO_SUCH_SYMBOL);
}

void
bfelf_loader_ut::test_bfelf_loader_resolve_symbol_success()
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

    func_t func;

    ret = bfelf_loader_resolve_symbol(&loader, "foo", reinterpret_cast<void **>(&func));
    this->expect_true(ret == BFELF_SUCCESS);
}

void
bfelf_loader_ut::test_bfelf_loader_resolve_no_such_symbol_no_hash()
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

    dummy_misc_ef.hash = nullptr;
    dummy_code_ef.hash = nullptr;

    ret = bfelf_loader_relocate(&loader);
    this->expect_true(ret == BFELF_SUCCESS);

    func_t func;

    ret = bfelf_loader_resolve_symbol(&loader, "invalid_sym", reinterpret_cast<void **>(&func));
    this->expect_true(ret == BFELF_ERROR_NO_SUCH_SYMBOL);
}

void
bfelf_loader_ut::test_bfelf_loader_resolve_symbol_success_no_hash()
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

    dummy_misc_ef.hash = nullptr;
    dummy_code_ef.hash = nullptr;

    ret = bfelf_loader_relocate(&loader);
    this->expect_true(ret == BFELF_SUCCESS);

    func_t func;

    ret = bfelf_loader_resolve_symbol(&loader, "foo", reinterpret_cast<void **>(&func));
    this->expect_true(ret == BFELF_SUCCESS);
}

void
bfelf_loader_ut::test_bfelf_loader_resolve_symbol_real_test()
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

    {
        section_info_t info;
        local_init_t local_init;

        ret = bfelf_file_get_section_info(&dummy_misc_ef, &info);
        this->expect_true(ret == BFELF_SUCCESS);

        ret = bfelf_file_resolve_symbol(&dummy_misc_ef, "local_init", reinterpret_cast<void **>(&local_init));
        this->expect_true(ret == BFELF_SUCCESS);

        local_init(&info);

        ret = bfelf_file_get_section_info(&dummy_code_ef, &info);
        this->expect_true(ret == BFELF_SUCCESS);

        ret = bfelf_file_resolve_symbol(&dummy_misc_ef, "local_init", reinterpret_cast<void **>(&local_init));
        this->expect_true(ret == BFELF_SUCCESS);

        local_init(&info);
    }

    {
        func_t func;

        ret = bfelf_loader_resolve_symbol(&loader, "foo", reinterpret_cast<void **>(&func));
        this->expect_true(ret == BFELF_SUCCESS);

        this->expect_true(func(5) == 1005);
    }

    {
        section_info_t info;
        local_fini_t local_fini;

        ret = bfelf_file_get_section_info(&dummy_misc_ef, &info);
        this->expect_true(ret == BFELF_SUCCESS);

        ret = bfelf_file_resolve_symbol(&dummy_misc_ef, "local_fini", reinterpret_cast<void **>(&local_fini));
        this->expect_true(ret == BFELF_SUCCESS);

        local_fini(&info);

        ret = bfelf_file_get_section_info(&dummy_code_ef, &info);
        this->expect_true(ret == BFELF_SUCCESS);

        ret = bfelf_file_resolve_symbol(&dummy_misc_ef, "local_fini", reinterpret_cast<void **>(&local_fini));
        this->expect_true(ret == BFELF_SUCCESS);

        local_fini(&info);
    }
}
