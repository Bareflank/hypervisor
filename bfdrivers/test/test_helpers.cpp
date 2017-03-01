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
    int64_t load_elf_file(struct module_t *module);
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

void
driver_entry_ut::test_helper_common_vmm_status()
{
    this->expect_true(common_vmm_status() == VMM_UNLOADED);
    this->expect_true(common_add_module(m_dummy_start_vmm_success.get(), m_dummy_start_vmm_success_length) == BF_SUCCESS);
    this->expect_true(common_add_module(m_dummy_stop_vmm_success.get(), m_dummy_stop_vmm_success_length) == BF_SUCCESS);
    this->expect_true(common_add_module(m_dummy_add_md_success.get(), m_dummy_add_md_success_length) == BF_SUCCESS);
    this->expect_true(common_add_module(m_dummy_misc.get(), m_dummy_misc_length) == BF_SUCCESS);
    this->expect_true(common_load_vmm() == BF_SUCCESS);
    this->expect_true(common_vmm_status() == VMM_LOADED);
    this->expect_true(common_start_vmm() == BF_SUCCESS);
    this->expect_true(common_vmm_status() == VMM_RUNNING);
    this->expect_true(common_stop_vmm() == BF_SUCCESS);
    this->expect_true(common_vmm_status() == VMM_LOADED);
    this->expect_true(common_unload_vmm() == BF_SUCCESS);
    this->expect_true(common_vmm_status() == VMM_UNLOADED);
}

void
driver_entry_ut::test_helper_get_file_invalid_index()
{
    this->expect_true(get_module(10000) == nullptr);
}

void
driver_entry_ut::test_helper_get_file_success()
{
    this->expect_true(common_add_module(m_dummy_start_vmm_success.get(), m_dummy_start_vmm_success_length) == BF_SUCCESS);
    this->expect_true(get_module(0) != nullptr);
    this->expect_true(common_fini() == BF_SUCCESS);
}

void
driver_entry_ut::test_helper_symbol_length_null_symbol()
{
    this->expect_true(symbol_length(nullptr) == 0);
}

void
driver_entry_ut::test_helper_symbol_length_success()
{
    this->expect_true(symbol_length("hello world") == 11);
}

void
driver_entry_ut::test_helper_resolve_symbol_invalid_name()
{
    void *sym;

    this->expect_true(resolve_symbol(nullptr, &sym) == BF_ERROR_INVALID_ARG);
}

void
driver_entry_ut::test_helper_resolve_symbol_invalid_sym()
{
    this->expect_true(resolve_symbol("sym", nullptr) == BF_ERROR_INVALID_ARG);
}

void
driver_entry_ut::test_helper_resolve_symbol_no_loaded_modules()
{
    void *sym;

    this->expect_true(resolve_symbol("invalid_symbol", &sym) == BF_ERROR_NO_MODULES_ADDED);
}

void
driver_entry_ut::test_helper_resolve_symbol_missing_symbol()
{
    void *sym;

    this->expect_true(common_add_module(m_dummy_start_vmm_success.get(), m_dummy_start_vmm_success_length) == BF_SUCCESS);
    this->expect_true(common_add_module(m_dummy_stop_vmm_success.get(), m_dummy_stop_vmm_success_length) == BF_SUCCESS);
    this->expect_true(common_add_module(m_dummy_add_md_success.get(), m_dummy_add_md_success_length) == BF_SUCCESS);
    this->expect_true(common_add_module(m_dummy_misc.get(), m_dummy_misc_length) == BF_SUCCESS);
    this->expect_true(common_load_vmm() == BF_SUCCESS);
    this->expect_true(resolve_symbol("invalid_symbol", &sym) == BFELF_ERROR_NO_SUCH_SYMBOL);
    this->expect_true(common_fini() == BF_SUCCESS);
}

void
driver_entry_ut::test_helper_execute_symbol_invalid_arg()
{
    this->expect_true(execute_symbol(nullptr, 0, 0, 0) == BF_ERROR_INVALID_ARG);
}

void
driver_entry_ut::test_helper_execute_symbol_missing_symbol()
{
    this->expect_true(common_add_module(m_dummy_start_vmm_success.get(), m_dummy_start_vmm_success_length) == BF_SUCCESS);
    this->expect_true(common_add_module(m_dummy_stop_vmm_success.get(), m_dummy_stop_vmm_success_length) == BF_SUCCESS);
    this->expect_true(common_add_module(m_dummy_add_md_success.get(), m_dummy_add_md_success_length) == BF_SUCCESS);
    this->expect_true(common_add_module(m_dummy_misc.get(), m_dummy_misc_length) == BF_SUCCESS);
    this->expect_true(common_load_vmm() == BF_SUCCESS);
    this->expect_true(execute_symbol("invalid_symbol", 0, 0, 0) == BFELF_ERROR_NO_SUCH_SYMBOL);
    this->expect_true(common_fini() == BF_SUCCESS);
}

void
driver_entry_ut::test_helper_execute_symbol_sym_failed()
{
    this->expect_true(common_add_module(m_dummy_start_vmm_success.get(), m_dummy_start_vmm_success_length) == BF_SUCCESS);
    this->expect_true(common_add_module(m_dummy_stop_vmm_success.get(), m_dummy_stop_vmm_success_length) == BF_SUCCESS);
    this->expect_true(common_add_module(m_dummy_add_md_success.get(), m_dummy_add_md_success_length) == BF_SUCCESS);
    this->expect_true(common_add_module(m_dummy_misc.get(), m_dummy_misc_length) == BF_SUCCESS);
    this->expect_true(common_load_vmm() == BF_SUCCESS);
    this->expect_true(execute_symbol("sym_that_returns_failure", 0, 0, 0) == -1);
    this->expect_true(common_fini() == BF_SUCCESS);
}

void
driver_entry_ut::test_helper_execute_symbol_sym_success()
{
    this->expect_true(common_add_module(m_dummy_start_vmm_success.get(), m_dummy_start_vmm_success_length) == BF_SUCCESS);
    this->expect_true(common_add_module(m_dummy_stop_vmm_success.get(), m_dummy_stop_vmm_success_length) == BF_SUCCESS);
    this->expect_true(common_add_module(m_dummy_add_md_success.get(), m_dummy_add_md_success_length) == BF_SUCCESS);
    this->expect_true(common_add_module(m_dummy_misc.get(), m_dummy_misc_length) == BF_SUCCESS);
    this->expect_true(common_load_vmm() == BF_SUCCESS);
    this->expect_true(execute_symbol("sym_that_returns_success", 0, 0, 0) == 0);
    this->expect_true(common_fini() == BF_SUCCESS);
}

void
driver_entry_ut::test_helper_add_md_to_memory_manager_null_module()
{
    this->expect_true(add_md_to_memory_manager(nullptr) == BF_ERROR_INVALID_ARG);
}

void
driver_entry_ut::test_helper_load_elf_file_null_module()
{
    this->expect_true(load_elf_file(nullptr) == BF_ERROR_INVALID_ARG);
}
