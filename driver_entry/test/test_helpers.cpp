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

#include <entry.h>
#include <common.h>
#include <platform.h>
#include <bfelf_loader.h>

// =============================================================================
// Expose Private Functions
// =============================================================================

// In order to mock some of the C functions, we need to expose them. These are
// private, so there is no need to test these functions, but we do need access
// to them to mock them up to test the public functions.

extern "C"
{
    int64_t set_vmm_status(int64_t status);
    uint64_t vmm_status(void);
    struct bfelf_file_t *get_file(uint64_t index);
    struct bfelf_file_t *get_next_file(void);
    void *add_elf_file(uint64_t size);
    int64_t remove_elf_files(void);
    int64_t symbol_length(const char *sym);
    int64_t resolve_symbol(const char *name, void **sym);
    int64_t execute_symbol(const char *sym);
    int64_t allocate_page_pool(void);
    int64_t free_page_pool(void);
}

// =============================================================================
// Tests
// =============================================================================

void
driver_entry_ut::test_helper_set_vmm_status()
{
    EXPECT_TRUE(set_vmm_status(VMM_RUNNING) == VMM_UNLOADED);
    EXPECT_TRUE(set_vmm_status(VMM_UNLOADED) == VMM_RUNNING);
}

void
driver_entry_ut::test_helper_vmm_status()
{
    EXPECT_TRUE(vmm_status() == VMM_UNLOADED);
    EXPECT_TRUE(common_add_module(m_dummy1, m_dummy1_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy2, m_dummy2_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy3, m_dummy3_length) == BF_SUCCESS);
    EXPECT_TRUE(common_load_vmm() == BF_SUCCESS);
    EXPECT_TRUE(vmm_status() == VMM_LOADED);
    EXPECT_TRUE(common_start_vmm() == BF_SUCCESS);
    EXPECT_TRUE(vmm_status() == VMM_RUNNING);
    EXPECT_TRUE(common_stop_vmm() == BF_SUCCESS);
    EXPECT_TRUE(vmm_status() == VMM_LOADED);
    EXPECT_TRUE(common_unload_vmm() == BF_SUCCESS);
    EXPECT_TRUE(vmm_status() == VMM_UNLOADED);
}

void
driver_entry_ut::test_helper_get_file_invalid_index()
{
    EXPECT_TRUE(get_file(10000) == 0);
}

void
driver_entry_ut::test_helper_get_file_success()
{
    EXPECT_TRUE(common_add_module(m_dummy1, m_dummy1_length) == BF_SUCCESS);
    EXPECT_TRUE(get_file(0) != 0);
    EXPECT_TRUE(common_unload_vmm() == BF_SUCCESS);
}

void
driver_entry_ut::test_helper_get_next_file_too_man_files()
{
    for (auto i = 0; i < MAX_NUM_MODULES; i++)
        common_add_module(m_dummy1, m_dummy1_length);

    EXPECT_TRUE(get_next_file() == 0);
    EXPECT_TRUE(common_unload_vmm() == BF_SUCCESS);
}

void
driver_entry_ut::test_helper_get_next_file_success()
{
    EXPECT_TRUE(get_next_file() != 0);
    EXPECT_TRUE(common_unload_vmm() == BF_SUCCESS);
}

void
driver_entry_ut::test_helper_add_elf_file_invalid_size()
{
    EXPECT_TRUE(add_elf_file(0) == 0);
}

void
driver_entry_ut::test_helper_add_elf_file_()
{
    EXPECT_TRUE(add_elf_file(0) == 0);
}

void
driver_entry_ut::test_helper_add_elf_file_get_next_file_failed()
{
    MockRepository mocks;

    mocks.OnCallFunc(get_next_file).Return(0);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_TRUE(add_elf_file(100) == 0);
    });
}

void
driver_entry_ut::test_helper_add_elf_file_platform_alloc_exec_failed()
{
    MockRepository mocks;

    mocks.OnCallFunc(platform_alloc_exec).Return(0);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_TRUE(add_elf_file(100) == 0);
    });
}

void
driver_entry_ut::test_helper_add_elf_file_success()
{
    EXPECT_TRUE(add_elf_file(100) != 0);
    EXPECT_TRUE(remove_elf_files() == BF_SUCCESS);
}

void
driver_entry_ut::test_helper_add_elf_file_success_multiple_times()
{
    EXPECT_TRUE(add_elf_file(100) != 0);
    EXPECT_TRUE(add_elf_file(100) != 0);
    EXPECT_TRUE(add_elf_file(100) != 0);
    EXPECT_TRUE(remove_elf_files() == BF_SUCCESS);
    EXPECT_TRUE(remove_elf_files() == BF_SUCCESS);
    EXPECT_TRUE(remove_elf_files() == BF_SUCCESS);
}

void
driver_entry_ut::test_helper_symbol_length_null_symbol()
{
    EXPECT_TRUE(symbol_length(NULL) == 0);
}

void
driver_entry_ut::test_helper_symbol_length_success()
{
    EXPECT_TRUE(symbol_length("hello world") == 11);
}

void
driver_entry_ut::test_helper_resolve_symbol_invalid_name()
{
    void *sym;

    EXPECT_TRUE(resolve_symbol(0, &sym) == BF_ERROR_INVALID_ARG);
}

void
driver_entry_ut::test_helper_resolve_symbol_invalid_sym()
{
    EXPECT_TRUE(resolve_symbol("sym", 0) == BF_ERROR_INVALID_ARG);
}

void
driver_entry_ut::test_helper_resolve_symbol_resolve_symbol_failed()
{
    void *sym;
    MockRepository mocks;

    mocks.OnCallFunc(bfelf_resolve_symbol).Return(-1);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_TRUE(resolve_symbol("sym", &sym) == -1);
    });
}

void
driver_entry_ut::test_helper_resolve_symbol_success()
{
    void *sym;

    EXPECT_TRUE(common_add_module(m_dummy1, m_dummy1_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy2, m_dummy2_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy3, m_dummy3_length) == BF_SUCCESS);
    EXPECT_TRUE(common_load_vmm() == BF_SUCCESS);
    EXPECT_TRUE(resolve_symbol("start_vmm", &sym) == BF_SUCCESS);
    EXPECT_TRUE(common_unload_vmm() == BF_SUCCESS);
}

void
driver_entry_ut::test_helper_execute_symbol_invalid_arg()
{
    EXPECT_TRUE(execute_symbol(NULL) == BF_ERROR_INVALID_ARG);
}

void
driver_entry_ut::test_helper_execute_symbol_resolve_symbol_failed()
{
    MockRepository mocks;

    mocks.OnCallFunc(resolve_symbol).Return(-1);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_TRUE(execute_symbol("sym") == -1);
    });
}

void
driver_entry_ut::test_helper_execute_symbol_sym_failed()
{
    EXPECT_TRUE(common_add_module(m_dummy1, m_dummy1_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy2, m_dummy2_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy3, m_dummy3_length) == BF_SUCCESS);
    EXPECT_TRUE(common_load_vmm() == BF_SUCCESS);
    EXPECT_TRUE(execute_symbol("sym_that_returns_failure") == ENTRY_ERROR_VMM_START_FAILED);
    EXPECT_TRUE(common_unload_vmm() == BF_SUCCESS);
}

void
driver_entry_ut::test_helper_execute_symbol_sym_success()
{
    EXPECT_TRUE(common_add_module(m_dummy1, m_dummy1_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy2, m_dummy2_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy3, m_dummy3_length) == BF_SUCCESS);
    EXPECT_TRUE(common_load_vmm() == BF_SUCCESS);
    EXPECT_TRUE(execute_symbol("sym_that_returns_success") == ENTRY_SUCCESS);
    EXPECT_TRUE(common_unload_vmm() == BF_SUCCESS);
}

// long long int return_value;

// extern "C" long long int
// mock_add_page(struct page_t *pg)
// {
//     return return_value;
// }

// extern "C" long long int
// mock_remove_page(struct page_t *pg)
// {
//     return return_value;
// }

// int64_t
// mock_resolve_symbol(const char *name, void **sym)
// {
//     if (sym == 0)
//         return -100;

//     if (strcmp(name, "add_page") == 0) *sym = (void *)mock_add_page;
//     if (strcmp(name, "remove_page") == 0) *sym = (void *)mock_remove_page;

//     return BF_SUCCESS;
// }

// void
// driver_entry_ut::test_helper_allocate_page_pool_resolve_symbol_failed()
// {
//     MockRepository mocks;

//     mocks.OnCallFunc(resolve_symbol).Return(-1);

//     RUN_UNITTEST_WITH_MOCKS(mocks, [&]
//     {
//         EXPECT_TRUE(allocate_page_pool() == -1);
//     });
// }

// void
// driver_entry_ut::test_helper_allocate_page_pool_alloc_page_failed()
// {
//     MockRepository mocks;
//     struct page_t blank_page = {0};

//     mocks.OnCallFunc(resolve_symbol).Do(mock_resolve_symbol);
//     mocks.OnCallFunc(platform_alloc_page).Return(blank_page);

//     RUN_UNITTEST_WITH_MOCKS(mocks, [&]
//     {
//         EXPECT_TRUE(allocate_page_pool() == BF_ERROR_OUT_OF_MEMORY);
//     });
// }

// void
// driver_entry_ut::test_helper_allocate_page_pool_add_page_failed()
// {
//     MockRepository mocks;

//     mocks.OnCallFunc(resolve_symbol).Do(mock_resolve_symbol);

//     RUN_UNITTEST_WITH_MOCKS(mocks, [&]
//     {
//         return_value = -1;
//         EXPECT_TRUE(allocate_page_pool() == -1);

//         return_value = 0;
//         EXPECT_TRUE(free_page_pool() == BF_SUCCESS);
//     });
// }

// void
// driver_entry_ut::test_helper_allocate_page_pool_success()
// {
//     EXPECT_TRUE(common_add_module(m_dummy1, m_dummy1_length) == BF_SUCCESS);
//     EXPECT_TRUE(common_add_module(m_dummy2, m_dummy2_length) == BF_SUCCESS);
//     EXPECT_TRUE(common_add_module(m_dummy3, m_dummy3_length) == BF_SUCCESS);
//     EXPECT_TRUE(common_load_vmm() == BF_SUCCESS);
//     EXPECT_TRUE(allocate_page_pool() == BF_SUCCESS);
//     EXPECT_TRUE(free_page_pool() == BF_SUCCESS);
//     EXPECT_TRUE(common_unload_vmm() == BF_SUCCESS);
// }

// void
// driver_entry_ut::test_helper_allocate_page_pool_success_multiple_times()
// {
//     EXPECT_TRUE(common_add_module(m_dummy1, m_dummy1_length) == BF_SUCCESS);
//     EXPECT_TRUE(common_add_module(m_dummy2, m_dummy2_length) == BF_SUCCESS);
//     EXPECT_TRUE(common_add_module(m_dummy3, m_dummy3_length) == BF_SUCCESS);
//     EXPECT_TRUE(common_load_vmm() == BF_SUCCESS);
//     EXPECT_TRUE(allocate_page_pool() == BF_SUCCESS);
//     EXPECT_TRUE(allocate_page_pool() == BF_SUCCESS);
//     EXPECT_TRUE(allocate_page_pool() == BF_SUCCESS);
//     EXPECT_TRUE(free_page_pool() == BF_SUCCESS);
//     EXPECT_TRUE(common_unload_vmm() == BF_SUCCESS);
// }

// void
// driver_entry_ut::test_helper_free_page_pool_resolve_symbol_failed()
// {
//     MockRepository mocks;

//     mocks.OnCallFunc(resolve_symbol).Return(-1);

//     RUN_UNITTEST_WITH_MOCKS(mocks, [&]
//     {
//         EXPECT_TRUE(free_page_pool() == -1);
//     });
// }

// void
// driver_entry_ut::test_helper_free_page_pool_remove_page_failed()
// {
//     EXPECT_TRUE(common_add_module(m_dummy1, m_dummy1_length) == BF_SUCCESS);
//     EXPECT_TRUE(common_add_module(m_dummy2, m_dummy2_length) == BF_SUCCESS);
//     EXPECT_TRUE(common_add_module(m_dummy3, m_dummy3_length) == BF_SUCCESS);
//     EXPECT_TRUE(common_load_vmm() == BF_SUCCESS);
//     EXPECT_TRUE(allocate_page_pool() == BF_SUCCESS);

//     {
//         MockRepository mocks;

//         mocks.OnCallFunc(resolve_symbol).Do(mock_resolve_symbol);

//         RUN_UNITTEST_WITH_MOCKS(mocks, [&]
//         {
//             return_value = -1;
//             EXPECT_TRUE(free_page_pool() == -1);
//         });
//     }

//     EXPECT_TRUE(free_page_pool() == BF_SUCCESS);
//     EXPECT_TRUE(common_unload_vmm() == BF_SUCCESS);
// }

// void
// driver_entry_ut::test_helper_free_page_pool_success()
// {
//     EXPECT_TRUE(common_add_module(m_dummy1, m_dummy1_length) == BF_SUCCESS);
//     EXPECT_TRUE(common_add_module(m_dummy2, m_dummy2_length) == BF_SUCCESS);
//     EXPECT_TRUE(common_add_module(m_dummy3, m_dummy3_length) == BF_SUCCESS);
//     EXPECT_TRUE(common_load_vmm() == BF_SUCCESS);
//     EXPECT_TRUE(allocate_page_pool() == BF_SUCCESS);
//     EXPECT_TRUE(free_page_pool() == BF_SUCCESS);
//     EXPECT_TRUE(common_unload_vmm() == BF_SUCCESS);
// }

// void
// driver_entry_ut::test_helper_free_page_pool_success_multiple_times()
// {
//     EXPECT_TRUE(common_add_module(m_dummy1, m_dummy1_length) == BF_SUCCESS);
//     EXPECT_TRUE(common_add_module(m_dummy2, m_dummy2_length) == BF_SUCCESS);
//     EXPECT_TRUE(common_add_module(m_dummy3, m_dummy3_length) == BF_SUCCESS);
//     EXPECT_TRUE(common_load_vmm() == BF_SUCCESS);
//     EXPECT_TRUE(allocate_page_pool() == BF_SUCCESS);
//     EXPECT_TRUE(free_page_pool() == BF_SUCCESS);
//     EXPECT_TRUE(free_page_pool() == BF_SUCCESS);
//     EXPECT_TRUE(free_page_pool() == BF_SUCCESS);
//     EXPECT_TRUE(common_unload_vmm() == BF_SUCCESS);
// }
