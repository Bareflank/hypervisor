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

#include <common.h>
#include <platform.h>
#include <constants.h>
#include <driver_entry_interface.h>

// -----------------------------------------------------------------------------
// Expose Private Functions
// -----------------------------------------------------------------------------

extern "C"
{
    struct module_t *get_module(uint64_t index);
    int64_t symbol_length(const char *sym);
    int64_t resolve_symbol(const char *name, void **sym);
    int64_t execute_symbol(const char *sym, uint64_t arg1, uint64_t arg2, uint64_t cpuid);
    int64_t add_md_to_memory_manager(struct module_t *module);
    uint64_t get_elf_file_size(struct module_t *module);
    int64_t load_elf_file(struct module_t *module);
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

void
driver_entry_ut::test_helper_common_vmm_status()
{
    EXPECT_TRUE(common_vmm_status() == VMM_UNLOADED);
    EXPECT_TRUE(common_add_module(m_dummy_start_vmm_success.get(), m_dummy_start_vmm_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_stop_vmm_success.get(), m_dummy_stop_vmm_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_add_md_success.get(), m_dummy_add_md_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_misc.get(), m_dummy_misc_length) == BF_SUCCESS);
    EXPECT_TRUE(common_load_vmm() == BF_SUCCESS);
    EXPECT_TRUE(common_vmm_status() == VMM_LOADED);
    EXPECT_TRUE(common_start_vmm() == BF_SUCCESS);
    EXPECT_TRUE(common_vmm_status() == VMM_RUNNING);
    EXPECT_TRUE(common_stop_vmm() == BF_SUCCESS);
    EXPECT_TRUE(common_vmm_status() == VMM_LOADED);
    EXPECT_TRUE(common_unload_vmm() == BF_SUCCESS);
    EXPECT_TRUE(common_vmm_status() == VMM_UNLOADED);
}

void
driver_entry_ut::test_helper_get_file_invalid_index()
{
    EXPECT_TRUE(get_module(10000) == nullptr);
}

void
driver_entry_ut::test_helper_get_file_success()
{
    EXPECT_TRUE(common_add_module(m_dummy_start_vmm_success.get(), m_dummy_start_vmm_success_length) == BF_SUCCESS);
    EXPECT_TRUE(get_module(0) != nullptr);
    EXPECT_TRUE(common_fini() == BF_SUCCESS);
}

void
driver_entry_ut::test_helper_symbol_length_null_symbol()
{
    EXPECT_TRUE(symbol_length(nullptr) == 0);
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

    EXPECT_TRUE(resolve_symbol(nullptr, &sym) == BF_ERROR_INVALID_ARG);
}

void
driver_entry_ut::test_helper_resolve_symbol_invalid_sym()
{
    EXPECT_TRUE(resolve_symbol("sym", nullptr) == BF_ERROR_INVALID_ARG);
}

void
driver_entry_ut::test_helper_resolve_symbol_no_loaded_modules()
{
    void *sym;

    EXPECT_TRUE(resolve_symbol("invalid_symbol", &sym) == BF_ERROR_NO_MODULES_ADDED);
}

void
driver_entry_ut::test_helper_resolve_symbol_missing_symbol()
{
    void *sym;

    EXPECT_TRUE(common_add_module(m_dummy_start_vmm_success.get(), m_dummy_start_vmm_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_stop_vmm_success.get(), m_dummy_stop_vmm_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_add_md_success.get(), m_dummy_add_md_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_misc.get(), m_dummy_misc_length) == BF_SUCCESS);
    EXPECT_TRUE(common_load_vmm() == BF_SUCCESS);
    EXPECT_TRUE(resolve_symbol("invalid_symbol", &sym) == BFELF_ERROR_NO_SUCH_SYMBOL);
    EXPECT_TRUE(common_fini() == BF_SUCCESS);
}

void
driver_entry_ut::test_helper_execute_symbol_invalid_arg()
{
    EXPECT_TRUE(execute_symbol(nullptr, 0, 0, 0) == BF_ERROR_INVALID_ARG);
}

void
driver_entry_ut::test_helper_execute_symbol_missing_symbol()
{
    EXPECT_TRUE(common_add_module(m_dummy_start_vmm_success.get(), m_dummy_start_vmm_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_stop_vmm_success.get(), m_dummy_stop_vmm_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_add_md_success.get(), m_dummy_add_md_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_misc.get(), m_dummy_misc_length) == BF_SUCCESS);
    EXPECT_TRUE(common_load_vmm() == BF_SUCCESS);
    EXPECT_TRUE(execute_symbol("invalid_symbol", 0, 0, 0) == BFELF_ERROR_NO_SUCH_SYMBOL);
    EXPECT_TRUE(common_fini() == BF_SUCCESS);
}

void
driver_entry_ut::test_helper_execute_symbol_sym_failed()
{
    EXPECT_TRUE(common_add_module(m_dummy_start_vmm_success.get(), m_dummy_start_vmm_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_stop_vmm_success.get(), m_dummy_stop_vmm_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_add_md_success.get(), m_dummy_add_md_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_misc.get(), m_dummy_misc_length) == BF_SUCCESS);
    EXPECT_TRUE(common_load_vmm() == BF_SUCCESS);
    EXPECT_TRUE(execute_symbol("sym_that_returns_failure", 0, 0, 0) == -1);
    EXPECT_TRUE(common_fini() == BF_SUCCESS);
}

void
driver_entry_ut::test_helper_execute_symbol_sym_success()
{
    EXPECT_TRUE(common_add_module(m_dummy_start_vmm_success.get(), m_dummy_start_vmm_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_stop_vmm_success.get(), m_dummy_stop_vmm_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_add_md_success.get(), m_dummy_add_md_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_misc.get(), m_dummy_misc_length) == BF_SUCCESS);
    EXPECT_TRUE(common_load_vmm() == BF_SUCCESS);
    EXPECT_TRUE(execute_symbol("sym_that_returns_success", 0, 0, 0) == 0);
    EXPECT_TRUE(common_fini() == BF_SUCCESS);
}

void
driver_entry_ut::test_helper_add_md_to_memory_manager_null_module()
{
    EXPECT_TRUE(add_md_to_memory_manager(nullptr) == BF_ERROR_INVALID_ARG);
}

void
driver_entry_ut::test_helper_get_elf_file_size_null_module()
{
    EXPECT_TRUE(get_elf_file_size(nullptr) == 0);
}

void
driver_entry_ut::test_helper_get_elf_file_size_get_segment_fails()
{
    EXPECT_TRUE(common_add_module(m_dummy_start_vmm_success.get(), m_dummy_start_vmm_success_length) == BF_SUCCESS);

    {
        MockRepository mocks;
        mocks.ExpectCallFunc(bfelf_file_get_segment).Return(-1);

        RUN_UNITTEST_WITH_MOCKS(mocks, [&]
        {
            auto module = get_module(0);
            EXPECT_TRUE(get_elf_file_size(module) == 0);
        });
    }

    EXPECT_TRUE(common_fini() == BF_SUCCESS);
}

void
driver_entry_ut::test_helper_load_elf_file_null_module()
{
    EXPECT_TRUE(load_elf_file(nullptr) == BF_ERROR_INVALID_ARG);
}

void
driver_entry_ut::test_helper_load_elf_file_get_segment_fails()
{
    EXPECT_TRUE(common_add_module(m_dummy_start_vmm_success.get(), m_dummy_start_vmm_success_length) == BF_SUCCESS);

    {
        MockRepository mocks;
        mocks.ExpectCallFunc(bfelf_file_get_segment).Return(-1);

        RUN_UNITTEST_WITH_MOCKS(mocks, [&]
        {
            auto module = get_module(0);
            EXPECT_TRUE(load_elf_file(module) == -1);
        });
    }

    EXPECT_TRUE(common_fini() == BF_SUCCESS);
}
