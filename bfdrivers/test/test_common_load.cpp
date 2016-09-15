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
    int64_t resolve_symbol(const char *name, void **sym);
    int64_t execute_symbol(const char *sym, uint64_t arg1, uint64_t arg2, uint64_t cpuid);
}

extern uint64_t g_malloc_fails;

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

void
driver_entry_ut::test_common_load_successful_load()
{
    EXPECT_TRUE(common_add_module(m_dummy_start_vmm_success.get(), m_dummy_start_vmm_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_stop_vmm_success.get(), m_dummy_stop_vmm_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_add_md_success.get(), m_dummy_add_md_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_misc.get(), m_dummy_misc_length) == BF_SUCCESS);
    EXPECT_TRUE(common_load_vmm() == BF_SUCCESS);
    EXPECT_TRUE(common_vmm_status() == VMM_LOADED);
    EXPECT_TRUE(common_fini() == BF_SUCCESS);
    EXPECT_TRUE(common_vmm_status() == VMM_UNLOADED);
}

void
driver_entry_ut::test_common_load_load_when_already_loaded()
{
    EXPECT_TRUE(common_add_module(m_dummy_start_vmm_success.get(), m_dummy_start_vmm_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_stop_vmm_success.get(), m_dummy_stop_vmm_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_add_md_success.get(), m_dummy_add_md_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_misc.get(), m_dummy_misc_length) == BF_SUCCESS);
    EXPECT_TRUE(common_load_vmm() == BF_SUCCESS);
    EXPECT_TRUE(common_load_vmm() == BF_SUCCESS);
    EXPECT_TRUE(common_vmm_status() == VMM_LOADED);
    EXPECT_TRUE(common_fini() == BF_SUCCESS);
    EXPECT_TRUE(common_vmm_status() == VMM_UNLOADED);
}

void
driver_entry_ut::test_common_load_load_when_already_running()
{
    EXPECT_TRUE(common_add_module(m_dummy_start_vmm_success.get(), m_dummy_start_vmm_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_stop_vmm_success.get(), m_dummy_stop_vmm_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_add_md_success.get(), m_dummy_add_md_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_misc.get(), m_dummy_misc_length) == BF_SUCCESS);
    EXPECT_TRUE(common_load_vmm() == BF_SUCCESS);
    EXPECT_TRUE(common_start_vmm() == BF_SUCCESS);
    EXPECT_TRUE(common_load_vmm() == BF_ERROR_VMM_INVALID_STATE);
    EXPECT_TRUE(common_vmm_status() == VMM_RUNNING);
    EXPECT_TRUE(common_fini() == BF_SUCCESS);
    EXPECT_TRUE(common_vmm_status() == VMM_UNLOADED);
}

void
driver_entry_ut::test_common_load_load_when_corrupt()
{
    EXPECT_TRUE(common_add_module(m_dummy_start_vmm_success.get(), m_dummy_start_vmm_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_stop_vmm_failure.get(), m_dummy_stop_vmm_failure_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_add_md_success.get(), m_dummy_add_md_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_misc.get(), m_dummy_misc_length) == BF_SUCCESS);
    EXPECT_TRUE(common_load_vmm() == BF_SUCCESS);
    EXPECT_TRUE(common_start_vmm() == BF_SUCCESS);
    EXPECT_TRUE(common_fini() == BF_ERROR_VMM_CORRUPTED);
    EXPECT_TRUE(common_vmm_status() == VMM_CORRUPT);
    EXPECT_TRUE(common_load_vmm() == BF_ERROR_VMM_CORRUPTED);

    common_reset();
}

void
driver_entry_ut::test_common_load_fail_due_to_relocation_error()
{
    EXPECT_TRUE(common_add_module(m_dummy_start_vmm_success.get(), m_dummy_start_vmm_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_stop_vmm_success.get(), m_dummy_stop_vmm_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_load_vmm() == BFELF_ERROR_NO_SUCH_SYMBOL);
    EXPECT_TRUE(common_vmm_status() == VMM_UNLOADED);
    EXPECT_TRUE(common_fini() == BF_SUCCESS);
    EXPECT_TRUE(common_vmm_status() == VMM_UNLOADED);
}

void
driver_entry_ut::test_common_load_fail_due_to_no_modules_added()
{
    EXPECT_TRUE(common_load_vmm() == BF_ERROR_NO_MODULES_ADDED);
    EXPECT_TRUE(common_vmm_status() == VMM_UNLOADED);
    EXPECT_TRUE(common_fini() == BF_SUCCESS);
    EXPECT_TRUE(common_vmm_status() == VMM_UNLOADED);
}

void
driver_entry_ut::test_common_load_add_md_failed()
{
    EXPECT_TRUE(common_add_module(m_dummy_start_vmm_success.get(), m_dummy_start_vmm_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_stop_vmm_success.get(), m_dummy_stop_vmm_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_add_md_failure.get(), m_dummy_add_md_failure_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_misc.get(), m_dummy_misc_length) == BF_SUCCESS);
    EXPECT_TRUE(common_load_vmm() == MEMORY_MANAGER_FAILURE);
    EXPECT_TRUE(common_fini() == BF_SUCCESS);
}

void
driver_entry_ut::test_common_load_tls_platform_alloc_failed()
{
    g_malloc_fails = THREAD_LOCAL_STORAGE_SIZE;

    auto ___ = gsl::finally([&]
    { g_malloc_fails = 0; });

    EXPECT_TRUE(common_add_module(m_dummy_start_vmm_success.get(), m_dummy_start_vmm_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_stop_vmm_success.get(), m_dummy_stop_vmm_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_add_md_success.get(), m_dummy_add_md_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_misc.get(), m_dummy_misc_length) == BF_SUCCESS);
    EXPECT_TRUE(common_load_vmm() == BF_ERROR_OUT_OF_MEMORY);
    EXPECT_TRUE(common_fini() == BF_SUCCESS);
}

void
driver_entry_ut::test_common_load_stack_platform_alloc_failed()
{
    g_malloc_fails = STACK_SIZE * 2;

    auto ___ = gsl::finally([&]
    { g_malloc_fails = 0; });

    EXPECT_TRUE(common_add_module(m_dummy_start_vmm_success.get(), m_dummy_start_vmm_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_stop_vmm_success.get(), m_dummy_stop_vmm_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_add_md_success.get(), m_dummy_add_md_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_misc.get(), m_dummy_misc_length) == BF_SUCCESS);
    EXPECT_TRUE(common_load_vmm() == BF_ERROR_OUT_OF_MEMORY);
    EXPECT_TRUE(common_fini() == BF_SUCCESS);
}

void
driver_entry_ut::test_common_load_loader_add_failed()
{
    EXPECT_TRUE(common_add_module(m_dummy_start_vmm_success.get(), m_dummy_start_vmm_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_stop_vmm_success.get(), m_dummy_stop_vmm_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_add_md_success.get(), m_dummy_add_md_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_misc.get(), m_dummy_misc_length) == BF_SUCCESS);

    {
        MockRepository mocks;
        mocks.ExpectCallFunc(bfelf_loader_add).Return(-1);

        RUN_UNITTEST_WITH_MOCKS(mocks, [&]
        {
            EXPECT_TRUE(common_load_vmm() == -1);
        });
    }

    EXPECT_TRUE(common_fini() == BF_SUCCESS);
}

void
driver_entry_ut::test_common_load_resolve_symbol_failed()
{
    EXPECT_TRUE(common_add_module(m_dummy_start_vmm_success.get(), m_dummy_start_vmm_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_stop_vmm_success.get(), m_dummy_stop_vmm_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_add_md_success.get(), m_dummy_add_md_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_misc.get(), m_dummy_misc_length) == BF_SUCCESS);

    {
        MockRepository mocks;
        mocks.ExpectCallFunc(resolve_symbol).Return(-1);

        RUN_UNITTEST_WITH_MOCKS(mocks, [&]
        {
            EXPECT_TRUE(common_load_vmm() == -1);
        });
    }

    EXPECT_TRUE(common_fini() == BF_SUCCESS);
}

void
driver_entry_ut::test_common_load_loader_get_info_failed()
{
    EXPECT_TRUE(common_add_module(m_dummy_start_vmm_success.get(), m_dummy_start_vmm_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_stop_vmm_success.get(), m_dummy_stop_vmm_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_add_md_success.get(), m_dummy_add_md_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_misc.get(), m_dummy_misc_length) == BF_SUCCESS);

    {
        MockRepository mocks;
        mocks.ExpectCallFunc(bfelf_loader_get_info).Return(-1);

        RUN_UNITTEST_WITH_MOCKS(mocks, [&]
        {
            EXPECT_TRUE(common_load_vmm() == -1);
        });
    }

    EXPECT_TRUE(common_fini() == BF_SUCCESS);
}

void
driver_entry_ut::test_common_load_execute_symbol_failed()
{
    EXPECT_TRUE(common_add_module(m_dummy_start_vmm_success.get(), m_dummy_start_vmm_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_stop_vmm_success.get(), m_dummy_stop_vmm_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_add_md_success.get(), m_dummy_add_md_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_misc.get(), m_dummy_misc_length) == BF_SUCCESS);

    {
        MockRepository mocks;
        mocks.ExpectCallFunc(execute_symbol).Return(-1);

        RUN_UNITTEST_WITH_MOCKS(mocks, [&]
        {
            EXPECT_TRUE(common_load_vmm() == -1);
        });
    }

    EXPECT_TRUE(common_fini() == BF_SUCCESS);
}

