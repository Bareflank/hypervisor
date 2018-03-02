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

#include <gsl/gsl>

#include <test.h>

#include <memory.h>
#include <common.h>
#include <platform.h>
#include <driver_entry_interface.h>

// -----------------------------------------------------------------------------
// Expose Private Functions
// -----------------------------------------------------------------------------

extern "C"
{
    struct module_t *get_module(uint64_t index);
    int64_t resolve_symbol(const char *name, void **sym);
    int64_t execute_symbol(const char *sym, uint64_t arg1, uint64_t arg2, uint64_t cpuid);
    int64_t add_raw_md_to_memory_manager(uint64_t virt, uint64_t type);
    int64_t add_md_to_memory_manager(struct module_t *module);
}

extern uint64_t g_malloc_fails;

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

void
driver_entry_ut::test_common_load_successful_load()
{
    this->expect_true(common_add_module(m_dummy_start_vmm_success.get(), m_dummy_start_vmm_success_length) == BF_SUCCESS);
    this->expect_true(common_add_module(m_dummy_stop_vmm_success.get(), m_dummy_stop_vmm_success_length) == BF_SUCCESS);
    this->expect_true(common_add_module(m_dummy_add_md_success.get(), m_dummy_add_md_success_length) == BF_SUCCESS);
    this->expect_true(common_add_module(m_dummy_misc.get(), m_dummy_misc_length) == BF_SUCCESS);
    this->expect_true(common_load_vmm() == BF_SUCCESS);
    this->expect_true(common_vmm_status() == VMM_LOADED);
    this->expect_true(common_fini() == BF_SUCCESS);
    this->expect_true(common_vmm_status() == VMM_UNLOADED);
}

void
driver_entry_ut::test_common_load_load_when_already_loaded()
{
    this->expect_true(common_add_module(m_dummy_start_vmm_success.get(), m_dummy_start_vmm_success_length) == BF_SUCCESS);
    this->expect_true(common_add_module(m_dummy_stop_vmm_success.get(), m_dummy_stop_vmm_success_length) == BF_SUCCESS);
    this->expect_true(common_add_module(m_dummy_add_md_success.get(), m_dummy_add_md_success_length) == BF_SUCCESS);
    this->expect_true(common_add_module(m_dummy_misc.get(), m_dummy_misc_length) == BF_SUCCESS);
    this->expect_true(common_load_vmm() == BF_SUCCESS);
    this->expect_true(common_load_vmm() == BF_SUCCESS);
    this->expect_true(common_vmm_status() == VMM_LOADED);
    this->expect_true(common_fini() == BF_SUCCESS);
    this->expect_true(common_vmm_status() == VMM_UNLOADED);
}

void
driver_entry_ut::test_common_load_load_when_already_running()
{
    this->expect_true(common_add_module(m_dummy_start_vmm_success.get(), m_dummy_start_vmm_success_length) == BF_SUCCESS);
    this->expect_true(common_add_module(m_dummy_stop_vmm_success.get(), m_dummy_stop_vmm_success_length) == BF_SUCCESS);
    this->expect_true(common_add_module(m_dummy_add_md_success.get(), m_dummy_add_md_success_length) == BF_SUCCESS);
    this->expect_true(common_add_module(m_dummy_misc.get(), m_dummy_misc_length) == BF_SUCCESS);
    this->expect_true(common_load_vmm() == BF_SUCCESS);
    this->expect_true(common_start_vmm() == BF_SUCCESS);
    this->expect_true(common_load_vmm() == BF_ERROR_VMM_INVALID_STATE);
    this->expect_true(common_vmm_status() == VMM_RUNNING);
    this->expect_true(common_fini() == BF_SUCCESS);
    this->expect_true(common_vmm_status() == VMM_UNLOADED);
}

void
driver_entry_ut::test_common_load_load_when_corrupt()
{
    this->expect_true(common_add_module(m_dummy_start_vmm_success.get(), m_dummy_start_vmm_success_length) == BF_SUCCESS);
    this->expect_true(common_add_module(m_dummy_stop_vmm_failure.get(), m_dummy_stop_vmm_failure_length) == BF_SUCCESS);
    this->expect_true(common_add_module(m_dummy_add_md_success.get(), m_dummy_add_md_success_length) == BF_SUCCESS);
    this->expect_true(common_add_module(m_dummy_misc.get(), m_dummy_misc_length) == BF_SUCCESS);
    this->expect_true(common_load_vmm() == BF_SUCCESS);
    this->expect_true(common_start_vmm() == BF_SUCCESS);
    this->expect_true(common_fini() == BF_ERROR_VMM_CORRUPTED);
    this->expect_true(common_vmm_status() == VMM_CORRUPT);
    this->expect_true(common_load_vmm() == BF_ERROR_VMM_CORRUPTED);

    common_reset();
}

void
driver_entry_ut::test_common_load_fail_due_to_relocation_error()
{
    this->expect_true(common_add_module(m_dummy_start_vmm_success.get(), m_dummy_start_vmm_success_length) == BF_SUCCESS);
    this->expect_true(common_add_module(m_dummy_stop_vmm_success.get(), m_dummy_stop_vmm_success_length) == BF_SUCCESS);
    this->expect_true(common_load_vmm() == BFELF_ERROR_NO_SUCH_SYMBOL);
    this->expect_true(common_vmm_status() == VMM_UNLOADED);
    this->expect_true(common_fini() == BF_SUCCESS);
    this->expect_true(common_vmm_status() == VMM_UNLOADED);
}

void
driver_entry_ut::test_common_load_fail_due_to_no_modules_added()
{
    this->expect_true(common_load_vmm() == BF_ERROR_NO_MODULES_ADDED);
    this->expect_true(common_vmm_status() == VMM_UNLOADED);
    this->expect_true(common_fini() == BF_SUCCESS);
    this->expect_true(common_vmm_status() == VMM_UNLOADED);
}

void
driver_entry_ut::test_common_load_add_md_failed()
{
    this->expect_true(common_add_module(m_dummy_start_vmm_success.get(), m_dummy_start_vmm_success_length) == BF_SUCCESS);
    this->expect_true(common_add_module(m_dummy_stop_vmm_success.get(), m_dummy_stop_vmm_success_length) == BF_SUCCESS);
    this->expect_true(common_add_module(m_dummy_add_md_failure.get(), m_dummy_add_md_failure_length) == BF_SUCCESS);
    this->expect_true(common_add_module(m_dummy_misc.get(), m_dummy_misc_length) == BF_SUCCESS);
    this->expect_true(common_load_vmm() == MEMORY_MANAGER_FAILURE);
    this->expect_true(common_fini() == BF_SUCCESS);
}

void
driver_entry_ut::test_common_load_add_md_tls_failed()
{
    this->expect_true(common_add_module(m_dummy_start_vmm_success.get(), m_dummy_start_vmm_success_length) == BF_SUCCESS);
    this->expect_true(common_add_module(m_dummy_stop_vmm_success.get(), m_dummy_stop_vmm_success_length) == BF_SUCCESS);
    this->expect_true(common_add_module(m_dummy_add_md_success.get(), m_dummy_add_md_success_length) == BF_SUCCESS);
    this->expect_true(common_add_module(m_dummy_misc.get(), m_dummy_misc_length) == BF_SUCCESS);

    {
        MockRepository mocks;
        mocks.OnCallFunc(add_md_to_memory_manager).Return(0);
        mocks.ExpectCallFunc(add_raw_md_to_memory_manager).Return(-1);

        RUN_UNITTEST_WITH_MOCKS(mocks, [&]
        {
            this->expect_true(common_load_vmm() == -1);
        });
    }

    this->expect_true(common_fini() == BF_SUCCESS);
}

void
driver_entry_ut::test_common_load_tls_platform_alloc_failed()
{
    g_malloc_fails = THREAD_LOCAL_STORAGE_SIZE;

    auto ___ = gsl::finally([&]
    { g_malloc_fails = 0; });

    this->expect_true(common_add_module(m_dummy_start_vmm_success.get(), m_dummy_start_vmm_success_length) == BF_SUCCESS);
    this->expect_true(common_add_module(m_dummy_stop_vmm_success.get(), m_dummy_stop_vmm_success_length) == BF_SUCCESS);
    this->expect_true(common_add_module(m_dummy_add_md_success.get(), m_dummy_add_md_success_length) == BF_SUCCESS);
    this->expect_true(common_add_module(m_dummy_misc.get(), m_dummy_misc_length) == BF_SUCCESS);
    this->expect_true(common_load_vmm() == BF_ERROR_OUT_OF_MEMORY);
    this->expect_true(common_fini() == BF_SUCCESS);
}

void
driver_entry_ut::test_common_load_stack_platform_alloc_failed()
{
    g_malloc_fails = STACK_SIZE * 2;

    auto ___ = gsl::finally([&]
    { g_malloc_fails = 0; });

    this->expect_true(common_add_module(m_dummy_start_vmm_success.get(), m_dummy_start_vmm_success_length) == BF_SUCCESS);
    this->expect_true(common_add_module(m_dummy_stop_vmm_success.get(), m_dummy_stop_vmm_success_length) == BF_SUCCESS);
    this->expect_true(common_add_module(m_dummy_add_md_success.get(), m_dummy_add_md_success_length) == BF_SUCCESS);
    this->expect_true(common_add_module(m_dummy_misc.get(), m_dummy_misc_length) == BF_SUCCESS);
    this->expect_true(common_load_vmm() == BF_ERROR_OUT_OF_MEMORY);
    this->expect_true(common_fini() == BF_SUCCESS);
}

void
driver_entry_ut::test_common_load_loader_add_failed()
{
    this->expect_true(common_add_module(m_dummy_start_vmm_success.get(), m_dummy_start_vmm_success_length) == BF_SUCCESS);
    this->expect_true(common_add_module(m_dummy_stop_vmm_success.get(), m_dummy_stop_vmm_success_length) == BF_SUCCESS);
    this->expect_true(common_add_module(m_dummy_add_md_success.get(), m_dummy_add_md_success_length) == BF_SUCCESS);
    this->expect_true(common_add_module(m_dummy_misc.get(), m_dummy_misc_length) == BF_SUCCESS);

    auto module = get_module(0);
    module->file.added = 1;

    this->expect_true(common_load_vmm() == BFELF_ERROR_INVALID_ARG);
    this->expect_true(common_fini() == BF_SUCCESS);
}

void
driver_entry_ut::test_common_load_resolve_symbol_failed()
{
    this->expect_true(common_add_module(m_dummy_start_vmm_success.get(), m_dummy_start_vmm_success_length) == BF_SUCCESS);
    this->expect_true(common_add_module(m_dummy_stop_vmm_success.get(), m_dummy_stop_vmm_success_length) == BF_SUCCESS);
    this->expect_true(common_add_module(m_dummy_add_md_success.get(), m_dummy_add_md_success_length) == BF_SUCCESS);
    this->expect_true(common_add_module(m_dummy_misc.get(), m_dummy_misc_length) == BF_SUCCESS);

    {
        MockRepository mocks;
        mocks.ExpectCallFunc(resolve_symbol).Return(-1);

        RUN_UNITTEST_WITH_MOCKS(mocks, [&]
        {
            this->expect_true(common_load_vmm() == -1);
        });
    }

    this->expect_true(common_fini() == BF_SUCCESS);
}

void
driver_entry_ut::test_common_load_execute_symbol_failed()
{
    this->expect_true(common_add_module(m_dummy_start_vmm_success.get(), m_dummy_start_vmm_success_length) == BF_SUCCESS);
    this->expect_true(common_add_module(m_dummy_stop_vmm_success.get(), m_dummy_stop_vmm_success_length) == BF_SUCCESS);
    this->expect_true(common_add_module(m_dummy_add_md_success.get(), m_dummy_add_md_success_length) == BF_SUCCESS);
    this->expect_true(common_add_module(m_dummy_misc.get(), m_dummy_misc_length) == BF_SUCCESS);

    {
        MockRepository mocks;
        mocks.ExpectCallFunc(execute_symbol).Return(-1);

        RUN_UNITTEST_WITH_MOCKS(mocks, [&]
        {
            this->expect_true(common_load_vmm() == -1);
        });
    }

    this->expect_true(common_fini() == BF_SUCCESS);
}
