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
bfelf_loader_ut::test_bfelf_file_resolve_symbol_invalid_loader()
{
    func_t func;
    e_string_t name = {"foo", 3};

    auto ret = bfelf_file_resolve_symbol(nullptr, &name, reinterpret_cast<void **>(&func));
    this->expect_true(ret == BFELF_ERROR_INVALID_ARG);
}

void
bfelf_loader_ut::test_bfelf_file_resolve_symbol_invalid_name()
{
    func_t func;
    bfelf_file_t ef;

    memset(&ef, 0, sizeof(ef));

    auto ret = bfelf_file_resolve_symbol(&ef, nullptr, reinterpret_cast<void **>(&func));
    this->expect_true(ret == BFELF_ERROR_INVALID_ARG);
}

void
bfelf_loader_ut::test_bfelf_file_resolve_symbol_invalid_addr()
{
    bfelf_file_t ef;
    e_string_t name = {"foo", 3};

    memset(&ef, 0, sizeof(ef));

    auto ret = bfelf_file_resolve_symbol(&ef, &name, nullptr);
    this->expect_true(ret == BFELF_ERROR_INVALID_ARG);
}

void
bfelf_loader_ut::test_bfelf_file_resolve_symbol_no_relocation()
{
    auto ret = 0LL;
    bfelf_file_t ef;

    memset(&ef, 0, sizeof(ef));

    func_t func;
    e_string_t name = {"foo", 3};

    ret = bfelf_file_resolve_symbol(&ef, &name, reinterpret_cast<void **>(&func));
    this->expect_true(ret == BFELF_ERROR_OUT_OF_ORDER);
}

void
bfelf_loader_ut::test_bfelf_file_resolve_no_such_symbol()
{
    auto ret = 0LL;
    bfelf_file_t dummy_misc_ef;
    bfelf_file_t dummy_code_ef;

    ret = bfelf_file_init(m_dummy_misc.get(), m_dummy_misc_length, &dummy_misc_ef);
    ASSERT_TRUE(ret == BFELF_SUCCESS);
    ret = bfelf_file_init(m_dummy_code.get(), m_dummy_code_length, &dummy_code_ef);
    ASSERT_TRUE(ret == BFELF_SUCCESS);

    m_dummy_misc_exec = load_elf_file(&dummy_misc_ef);
    ASSERT_TRUE(m_dummy_misc_exec);
    m_dummy_code_exec = load_elf_file(&dummy_code_ef);
    ASSERT_TRUE(m_dummy_code_exec);

    bfelf_loader_t loader;
    memset(&loader, 0, sizeof(loader));

    ret = bfelf_loader_add(&loader, &dummy_misc_ef, m_dummy_misc_exec.get());
    ASSERT_TRUE(ret == BFELF_SUCCESS);
    ret = bfelf_loader_add(&loader, &dummy_code_ef, m_dummy_code_exec.get());
    ASSERT_TRUE(ret == BFELF_SUCCESS);

    ret = bfelf_loader_relocate(&loader);
    this->expect_true(ret == BFELF_SUCCESS);

    func_t func;
    e_string_t name = {"fighters", 8};

    ret = bfelf_file_resolve_symbol(&dummy_misc_ef, &name, reinterpret_cast<void **>(&func));
    this->expect_true(ret == BFELF_ERROR_NO_SUCH_SYMBOL);
}

void
bfelf_loader_ut::test_bfelf_file_resolve_zero_length_symbol()
{
    auto ret = 0LL;
    bfelf_file_t dummy_misc_ef;
    bfelf_file_t dummy_code_ef;

    ret = bfelf_file_init(m_dummy_misc.get(), m_dummy_misc_length, &dummy_misc_ef);
    ASSERT_TRUE(ret == BFELF_SUCCESS);
    ret = bfelf_file_init(m_dummy_code.get(), m_dummy_code_length, &dummy_code_ef);
    ASSERT_TRUE(ret == BFELF_SUCCESS);

    m_dummy_misc_exec = load_elf_file(&dummy_misc_ef);
    ASSERT_TRUE(m_dummy_misc_exec);
    m_dummy_code_exec = load_elf_file(&dummy_code_ef);
    ASSERT_TRUE(m_dummy_code_exec);

    bfelf_loader_t loader;
    memset(&loader, 0, sizeof(loader));

    ret = bfelf_loader_add(&loader, &dummy_misc_ef, m_dummy_misc_exec.get());
    ASSERT_TRUE(ret == BFELF_SUCCESS);
    ret = bfelf_loader_add(&loader, &dummy_code_ef, m_dummy_code_exec.get());
    ASSERT_TRUE(ret == BFELF_SUCCESS);

    ret = bfelf_loader_relocate(&loader);
    this->expect_true(ret == BFELF_SUCCESS);

    func_t func;
    e_string_t name = {"foo", 0};

    ret = bfelf_file_resolve_symbol(&dummy_misc_ef, &name, reinterpret_cast<void **>(&func));
    this->expect_true(ret == BFELF_ERROR_NO_SUCH_SYMBOL);
}

void
bfelf_loader_ut::test_bfelf_file_resolve_invalid_symbol_length()
{
    auto ret = 0LL;
    bfelf_file_t dummy_misc_ef;
    bfelf_file_t dummy_code_ef;

    ret = bfelf_file_init(m_dummy_misc.get(), m_dummy_misc_length, &dummy_misc_ef);
    ASSERT_TRUE(ret == BFELF_SUCCESS);
    ret = bfelf_file_init(m_dummy_code.get(), m_dummy_code_length, &dummy_code_ef);
    ASSERT_TRUE(ret == BFELF_SUCCESS);

    m_dummy_misc_exec = load_elf_file(&dummy_misc_ef);
    ASSERT_TRUE(m_dummy_misc_exec);
    m_dummy_code_exec = load_elf_file(&dummy_code_ef);
    ASSERT_TRUE(m_dummy_code_exec);

    bfelf_loader_t loader;
    memset(&loader, 0, sizeof(loader));

    ret = bfelf_loader_add(&loader, &dummy_misc_ef, m_dummy_misc_exec.get());
    ASSERT_TRUE(ret == BFELF_SUCCESS);
    ret = bfelf_loader_add(&loader, &dummy_code_ef, m_dummy_code_exec.get());
    ASSERT_TRUE(ret == BFELF_SUCCESS);

    ret = bfelf_loader_relocate(&loader);
    this->expect_true(ret == BFELF_SUCCESS);

    func_t func;
    e_string_t name = {"foo", 2};

    ret = bfelf_file_resolve_symbol(&dummy_misc_ef, &name, reinterpret_cast<void **>(&func));
    this->expect_true(ret == BFELF_ERROR_NO_SUCH_SYMBOL);
}

void
bfelf_loader_ut::test_bfelf_file_resolve_symbol_length_too_large()
{
    auto ret = 0LL;
    bfelf_file_t dummy_misc_ef;
    bfelf_file_t dummy_code_ef;

    ret = bfelf_file_init(m_dummy_misc.get(), m_dummy_misc_length, &dummy_misc_ef);
    ASSERT_TRUE(ret == BFELF_SUCCESS);
    ret = bfelf_file_init(m_dummy_code.get(), m_dummy_code_length, &dummy_code_ef);
    ASSERT_TRUE(ret == BFELF_SUCCESS);

    m_dummy_misc_exec = load_elf_file(&dummy_misc_ef);
    ASSERT_TRUE(m_dummy_misc_exec);
    m_dummy_code_exec = load_elf_file(&dummy_code_ef);
    ASSERT_TRUE(m_dummy_code_exec);

    bfelf_loader_t loader;
    memset(&loader, 0, sizeof(loader));

    ret = bfelf_loader_add(&loader, &dummy_misc_ef, m_dummy_misc_exec.get());
    ASSERT_TRUE(ret == BFELF_SUCCESS);
    ret = bfelf_loader_add(&loader, &dummy_code_ef, m_dummy_code_exec.get());
    ASSERT_TRUE(ret == BFELF_SUCCESS);

    ret = bfelf_loader_relocate(&loader);
    this->expect_true(ret == BFELF_SUCCESS);

    func_t func;
    e_string_t name = {"foo", 1000};

    ret = bfelf_file_resolve_symbol(&dummy_misc_ef, &name, reinterpret_cast<void **>(&func));
    this->expect_true(ret == BFELF_ERROR_NO_SUCH_SYMBOL);
}

void
bfelf_loader_ut::test_bfelf_file_resolve_symbol_success()
{
    auto ret = 0LL;
    bfelf_file_t dummy_misc_ef;
    bfelf_file_t dummy_code_ef;

    ret = bfelf_file_init(m_dummy_misc.get(), m_dummy_misc_length, &dummy_misc_ef);
    ASSERT_TRUE(ret == BFELF_SUCCESS);
    ret = bfelf_file_init(m_dummy_code.get(), m_dummy_code_length, &dummy_code_ef);
    ASSERT_TRUE(ret == BFELF_SUCCESS);

    m_dummy_misc_exec = load_elf_file(&dummy_misc_ef);
    ASSERT_TRUE(m_dummy_misc_exec);
    m_dummy_code_exec = load_elf_file(&dummy_code_ef);
    ASSERT_TRUE(m_dummy_code_exec);

    bfelf_loader_t loader;
    memset(&loader, 0, sizeof(loader));

    ret = bfelf_loader_add(&loader, &dummy_misc_ef, m_dummy_misc_exec.get());
    ASSERT_TRUE(ret == BFELF_SUCCESS);
    ret = bfelf_loader_add(&loader, &dummy_code_ef, m_dummy_code_exec.get());
    ASSERT_TRUE(ret == BFELF_SUCCESS);

    ret = bfelf_loader_relocate(&loader);
    this->expect_true(ret == BFELF_SUCCESS);

    func_t func;
    e_string_t name = {"foo", 3};

    ret = bfelf_file_resolve_symbol(&dummy_misc_ef, &name, reinterpret_cast<void **>(&func));
    this->expect_true(ret == BFELF_SUCCESS);
}

void
bfelf_loader_ut::test_bfelf_file_resolve_no_such_symbol_no_hash()
{
    auto ret = 0LL;
    bfelf_file_t dummy_misc_ef;
    bfelf_file_t dummy_code_ef;

    ret = bfelf_file_init(m_dummy_misc.get(), m_dummy_misc_length, &dummy_misc_ef);
    ASSERT_TRUE(ret == BFELF_SUCCESS);
    ret = bfelf_file_init(m_dummy_code.get(), m_dummy_code_length, &dummy_code_ef);
    ASSERT_TRUE(ret == BFELF_SUCCESS);

    dummy_misc_ef.hashtab = nullptr;
    dummy_code_ef.hashtab = nullptr;

    m_dummy_misc_exec = load_elf_file(&dummy_misc_ef);
    ASSERT_TRUE(m_dummy_misc_exec);
    m_dummy_code_exec = load_elf_file(&dummy_code_ef);
    ASSERT_TRUE(m_dummy_code_exec);

    bfelf_loader_t loader;
    memset(&loader, 0, sizeof(loader));

    ret = bfelf_loader_add(&loader, &dummy_misc_ef, m_dummy_misc_exec.get());
    ASSERT_TRUE(ret == BFELF_SUCCESS);
    ret = bfelf_loader_add(&loader, &dummy_code_ef, m_dummy_code_exec.get());
    ASSERT_TRUE(ret == BFELF_SUCCESS);

    ret = bfelf_loader_relocate(&loader);
    this->expect_true(ret == BFELF_SUCCESS);

    func_t func;
    e_string_t name = {"fighters", 8};

    ret = bfelf_file_resolve_symbol(&dummy_misc_ef, &name, reinterpret_cast<void **>(&func));
    this->expect_true(ret == BFELF_ERROR_NO_SUCH_SYMBOL);
}

void
bfelf_loader_ut::test_bfelf_file_resolve_zero_length_symbol_no_hash()
{
    auto ret = 0LL;
    bfelf_file_t dummy_misc_ef;
    bfelf_file_t dummy_code_ef;

    ret = bfelf_file_init(m_dummy_misc.get(), m_dummy_misc_length, &dummy_misc_ef);
    ASSERT_TRUE(ret == BFELF_SUCCESS);
    ret = bfelf_file_init(m_dummy_code.get(), m_dummy_code_length, &dummy_code_ef);
    ASSERT_TRUE(ret == BFELF_SUCCESS);

    dummy_misc_ef.hashtab = nullptr;
    dummy_code_ef.hashtab = nullptr;

    m_dummy_misc_exec = load_elf_file(&dummy_misc_ef);
    ASSERT_TRUE(m_dummy_misc_exec);
    m_dummy_code_exec = load_elf_file(&dummy_code_ef);
    ASSERT_TRUE(m_dummy_code_exec);

    bfelf_loader_t loader;
    memset(&loader, 0, sizeof(loader));

    ret = bfelf_loader_add(&loader, &dummy_misc_ef, m_dummy_misc_exec.get());
    ASSERT_TRUE(ret == BFELF_SUCCESS);
    ret = bfelf_loader_add(&loader, &dummy_code_ef, m_dummy_code_exec.get());
    ASSERT_TRUE(ret == BFELF_SUCCESS);

    ret = bfelf_loader_relocate(&loader);
    this->expect_true(ret == BFELF_SUCCESS);

    func_t func;
    e_string_t name = {"foo", 0};

    ret = bfelf_file_resolve_symbol(&dummy_misc_ef, &name, reinterpret_cast<void **>(&func));
    this->expect_true(ret == BFELF_ERROR_NO_SUCH_SYMBOL);
}

void
bfelf_loader_ut::test_bfelf_file_resolve_invalid_symbol_length_no_hash()
{
    auto ret = 0LL;
    bfelf_file_t dummy_misc_ef;
    bfelf_file_t dummy_code_ef;

    ret = bfelf_file_init(m_dummy_misc.get(), m_dummy_misc_length, &dummy_misc_ef);
    ASSERT_TRUE(ret == BFELF_SUCCESS);
    ret = bfelf_file_init(m_dummy_code.get(), m_dummy_code_length, &dummy_code_ef);
    ASSERT_TRUE(ret == BFELF_SUCCESS);

    dummy_misc_ef.hashtab = nullptr;
    dummy_code_ef.hashtab = nullptr;

    m_dummy_misc_exec = load_elf_file(&dummy_misc_ef);
    ASSERT_TRUE(m_dummy_misc_exec);
    m_dummy_code_exec = load_elf_file(&dummy_code_ef);
    ASSERT_TRUE(m_dummy_code_exec);

    bfelf_loader_t loader;
    memset(&loader, 0, sizeof(loader));

    ret = bfelf_loader_add(&loader, &dummy_misc_ef, m_dummy_misc_exec.get());
    ASSERT_TRUE(ret == BFELF_SUCCESS);
    ret = bfelf_loader_add(&loader, &dummy_code_ef, m_dummy_code_exec.get());
    ASSERT_TRUE(ret == BFELF_SUCCESS);

    ret = bfelf_loader_relocate(&loader);
    this->expect_true(ret == BFELF_SUCCESS);

    func_t func;
    e_string_t name = {"foo", 2};

    ret = bfelf_file_resolve_symbol(&dummy_misc_ef, &name, reinterpret_cast<void **>(&func));
    this->expect_true(ret == BFELF_ERROR_NO_SUCH_SYMBOL);
}

void
bfelf_loader_ut::test_bfelf_file_resolve_symbol_length_too_large_no_hash()
{
    auto ret = 0LL;
    bfelf_file_t dummy_misc_ef;
    bfelf_file_t dummy_code_ef;

    ret = bfelf_file_init(m_dummy_misc.get(), m_dummy_misc_length, &dummy_misc_ef);
    ASSERT_TRUE(ret == BFELF_SUCCESS);
    ret = bfelf_file_init(m_dummy_code.get(), m_dummy_code_length, &dummy_code_ef);
    ASSERT_TRUE(ret == BFELF_SUCCESS);

    dummy_misc_ef.hashtab = nullptr;
    dummy_code_ef.hashtab = nullptr;

    m_dummy_misc_exec = load_elf_file(&dummy_misc_ef);
    ASSERT_TRUE(m_dummy_misc_exec);
    m_dummy_code_exec = load_elf_file(&dummy_code_ef);
    ASSERT_TRUE(m_dummy_code_exec);

    bfelf_loader_t loader;
    memset(&loader, 0, sizeof(loader));

    ret = bfelf_loader_add(&loader, &dummy_misc_ef, m_dummy_misc_exec.get());
    ASSERT_TRUE(ret == BFELF_SUCCESS);
    ret = bfelf_loader_add(&loader, &dummy_code_ef, m_dummy_code_exec.get());
    ASSERT_TRUE(ret == BFELF_SUCCESS);

    ret = bfelf_loader_relocate(&loader);
    this->expect_true(ret == BFELF_SUCCESS);

    func_t func;
    e_string_t name = {"foo", 1000};

    ret = bfelf_file_resolve_symbol(&dummy_misc_ef, &name, reinterpret_cast<void **>(&func));
    this->expect_true(ret == BFELF_ERROR_NO_SUCH_SYMBOL);
}

void
bfelf_loader_ut::test_bfelf_file_resolve_symbol_success_no_hash()
{
    auto ret = 0LL;
    bfelf_file_t dummy_misc_ef;
    bfelf_file_t dummy_code_ef;

    ret = bfelf_file_init(m_dummy_misc.get(), m_dummy_misc_length, &dummy_misc_ef);
    ASSERT_TRUE(ret == BFELF_SUCCESS);
    ret = bfelf_file_init(m_dummy_code.get(), m_dummy_code_length, &dummy_code_ef);
    ASSERT_TRUE(ret == BFELF_SUCCESS);

    dummy_misc_ef.hashtab = nullptr;
    dummy_code_ef.hashtab = nullptr;

    m_dummy_misc_exec = load_elf_file(&dummy_misc_ef);
    ASSERT_TRUE(m_dummy_misc_exec);
    m_dummy_code_exec = load_elf_file(&dummy_code_ef);
    ASSERT_TRUE(m_dummy_code_exec);

    bfelf_loader_t loader;
    memset(&loader, 0, sizeof(loader));

    ret = bfelf_loader_add(&loader, &dummy_misc_ef, m_dummy_misc_exec.get());
    ASSERT_TRUE(ret == BFELF_SUCCESS);
    ret = bfelf_loader_add(&loader, &dummy_code_ef, m_dummy_code_exec.get());
    ASSERT_TRUE(ret == BFELF_SUCCESS);

    ret = bfelf_loader_relocate(&loader);
    this->expect_true(ret == BFELF_SUCCESS);

    func_t func;
    e_string_t name = {"foo", 3};

    ret = bfelf_file_resolve_symbol(&dummy_misc_ef, &name, reinterpret_cast<void **>(&func));
    this->expect_true(ret == BFELF_SUCCESS);
}
