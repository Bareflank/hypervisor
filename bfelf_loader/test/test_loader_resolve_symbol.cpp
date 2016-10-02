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

// -----------------------------------------------------------------------------
// Expose Private Functions
// -----------------------------------------------------------------------------

extern "C"
{
    int64_t
    private_resolve_symbol(struct bfelf_file_t *ef,
                           struct bfelf_sym *sym,
                           void **addr);
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

void
bfelf_loader_ut::test_bfelf_loader_resolve_symbol_invalid_loader()
{
    func_t func;
    e_string_t name = {"foo", 3};

    auto ret = bfelf_loader_resolve_symbol(nullptr, &name, reinterpret_cast<void **>(&func));
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
    e_string_t name = {"foo", 3};

    memset(&loader, 0, sizeof(loader));

    auto ret = bfelf_loader_resolve_symbol(&loader, &name, nullptr);
    this->expect_true(ret == BFELF_ERROR_INVALID_ARG);
}

void
bfelf_loader_ut::test_bfelf_loader_resolve_symbol_no_relocation()
{
    auto ret = 0LL;
    bfelf_loader_t loader;

    memset(&loader, 0, sizeof(loader));

    func_t func;
    e_string_t name = {"foo", 3};

    ret = bfelf_loader_resolve_symbol(&loader, &name, reinterpret_cast<void **>(&func));
    this->expect_true(ret == BFELF_ERROR_OUT_OF_ORDER);
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
    e_string_t name = {"foo", 3};

    ret = bfelf_loader_resolve_symbol(&loader, &name, reinterpret_cast<void **>(&func));
    this->expect_true(ret == BFELF_ERROR_NO_SUCH_SYMBOL);
}

void
bfelf_loader_ut::test_bfelf_loader_resolve_symbol_uninitialized_files()
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

    func_t func;
    e_string_t name = {"foo", 3};

    ret = bfelf_loader_resolve_symbol(&loader, &name, reinterpret_cast<void **>(&func));
    this->expect_true(ret == BFELF_ERROR_NO_SUCH_SYMBOL);
}

void
bfelf_loader_ut::test_bfelf_loader_resolve_no_such_symbol()
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

    ret = bfelf_loader_resolve_symbol(&loader, &name, reinterpret_cast<void **>(&func));
    this->expect_true(ret == BFELF_ERROR_NO_SUCH_SYMBOL);
}

void
bfelf_loader_ut::test_bfelf_loader_resolve_zero_length_symbol()
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

    ret = bfelf_loader_resolve_symbol(&loader, &name, reinterpret_cast<void **>(&func));
    this->expect_true(ret == BFELF_ERROR_NO_SUCH_SYMBOL);
}

void
bfelf_loader_ut::test_bfelf_loader_resolve_invalid_symbol_length()
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

    ret = bfelf_loader_resolve_symbol(&loader, &name, reinterpret_cast<void **>(&func));
    this->expect_true(ret == BFELF_ERROR_NO_SUCH_SYMBOL);
}

void
bfelf_loader_ut::test_bfelf_loader_resolve_symbol_length_too_large()
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

    ret = bfelf_loader_resolve_symbol(&loader, &name, reinterpret_cast<void **>(&func));
    this->expect_true(ret == BFELF_ERROR_NO_SUCH_SYMBOL);
}

void
bfelf_loader_ut::test_bfelf_loader_resolve_symbol_success()
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

    ret = bfelf_loader_resolve_symbol(&loader, &name, reinterpret_cast<void **>(&func));
    this->expect_true(ret == BFELF_SUCCESS);
}

void
bfelf_loader_ut::test_bfelf_loader_resolve_no_such_symbol_no_hash()
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

    ret = bfelf_loader_resolve_symbol(&loader, &name, reinterpret_cast<void **>(&func));
    this->expect_true(ret == BFELF_ERROR_NO_SUCH_SYMBOL);
}

void
bfelf_loader_ut::test_bfelf_loader_resolve_zero_length_symbol_no_hash()
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

    ret = bfelf_loader_resolve_symbol(&loader, &name, reinterpret_cast<void **>(&func));
    this->expect_true(ret == BFELF_ERROR_NO_SUCH_SYMBOL);
}

void
bfelf_loader_ut::test_bfelf_loader_resolve_invalid_symbol_length_no_hash()
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

    ret = bfelf_loader_resolve_symbol(&loader, &name, reinterpret_cast<void **>(&func));
    this->expect_true(ret == BFELF_ERROR_NO_SUCH_SYMBOL);
}

void
bfelf_loader_ut::test_bfelf_loader_resolve_symbol_length_too_large_no_hash()
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

    ret = bfelf_loader_resolve_symbol(&loader, &name, reinterpret_cast<void **>(&func));
    this->expect_true(ret == BFELF_ERROR_NO_SUCH_SYMBOL);
}

void
bfelf_loader_ut::test_bfelf_loader_resolve_symbol_success_no_hash()
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

    ret = bfelf_loader_resolve_symbol(&loader, &name, reinterpret_cast<void **>(&func));
    this->expect_true(ret == BFELF_SUCCESS);
}

void
bfelf_loader_ut::test_bfelf_loader_resolve_symbol_real_test()
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

    {
        section_info_t info;
        local_init_t local_init;
        e_string_t name = {"local_init", 10};

        ret = bfelf_loader_get_info(&loader, &dummy_misc_ef, &info);
        ASSERT_TRUE(ret == BFELF_SUCCESS);

        ret = bfelf_file_resolve_symbol(&dummy_misc_ef, &name, reinterpret_cast<void **>(&local_init));
        ASSERT_TRUE(ret == BFELF_SUCCESS);

        local_init(&info);

        ret = bfelf_loader_get_info(&loader, &dummy_code_ef, &info);
        ASSERT_TRUE(ret == BFELF_SUCCESS);

        ret = bfelf_file_resolve_symbol(&dummy_misc_ef, &name, reinterpret_cast<void **>(&local_init));
        ASSERT_TRUE(ret == BFELF_SUCCESS);

        local_init(&info);
    }

    {
        func_t func;
        e_string_t name = {"foo", 3};

        ret = bfelf_loader_resolve_symbol(&loader, &name, reinterpret_cast<void **>(&func));
        ASSERT_TRUE(ret == BFELF_SUCCESS);

        this->expect_true(func(5) == 1005);
    }

    {
        section_info_t info;
        local_fini_t local_fini;
        e_string_t name = {"local_fini", 10};

        ret = bfelf_loader_get_info(&loader, &dummy_misc_ef, &info);
        ASSERT_TRUE(ret == BFELF_SUCCESS);

        ret = bfelf_file_resolve_symbol(&dummy_misc_ef, &name, reinterpret_cast<void **>(&local_fini));
        ASSERT_TRUE(ret == BFELF_SUCCESS);

        local_fini(&info);

        ret = bfelf_loader_get_info(&loader, &dummy_code_ef, &info);
        ASSERT_TRUE(ret == BFELF_SUCCESS);

        ret = bfelf_file_resolve_symbol(&dummy_misc_ef, &name, reinterpret_cast<void **>(&local_fini));
        ASSERT_TRUE(ret == BFELF_SUCCESS);

        local_fini(&info);
    }
}

void
bfelf_loader_ut::test_bfelf_file_resolve_symbol_resolve_fail()
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

    MockRepository mocks;
    mocks.OnCallFunc(private_resolve_symbol).Return(-1);

    section_info_t info;
    local_init_t local_init;
    e_string_t name = {"local_init", 10};

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        ret = bfelf_loader_get_info(&loader, &dummy_misc_ef, &info);
        ASSERT_TRUE(ret == BFELF_SUCCESS);

        ret = bfelf_file_resolve_symbol(&dummy_misc_ef, &name, reinterpret_cast<void **>(&local_init));
        ASSERT_TRUE(ret == -1);
    });
}

void
bfelf_loader_ut::test_bfelf_loader_resolve_symbol_resolve_fail()
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

    MockRepository mocks;
    mocks.OnCallFunc(private_resolve_symbol).Return(-1);

    func_t func;
    e_string_t name = {"foo", 3};

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        ret = bfelf_loader_resolve_symbol(&loader, &name, reinterpret_cast<void **>(&func));
        ASSERT_TRUE(ret == -1);
    });
}
