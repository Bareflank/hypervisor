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
#include <driver_entry_interface.h>

// -----------------------------------------------------------------------------
// Expose Private Functions
// -----------------------------------------------------------------------------

extern "C"
{
    int64_t execute_symbol(const char *sym, uint64_t arg1, uint64_t arg2, uint64_t cpuid);
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

void
driver_entry_ut::test_common_unload_unload_when_already_unloaded()
{
    this->expect_true(common_unload_vmm() == BF_SUCCESS);
}

void
driver_entry_ut::test_common_unload_unload_when_running()
{
    this->expect_true(common_add_module(m_dummy_start_vmm_success.get(), m_dummy_start_vmm_success_length) == BF_SUCCESS);
    this->expect_true(common_add_module(m_dummy_stop_vmm_success.get(), m_dummy_stop_vmm_success_length) == BF_SUCCESS);
    this->expect_true(common_add_module(m_dummy_add_md_success.get(), m_dummy_add_md_success_length) == BF_SUCCESS);
    this->expect_true(common_add_module(m_dummy_misc.get(), m_dummy_misc_length) == BF_SUCCESS);
    this->expect_true(common_load_vmm() == BF_SUCCESS);
    this->expect_true(common_start_vmm() == BF_SUCCESS);
    this->expect_true(common_unload_vmm() == BF_ERROR_VMM_INVALID_STATE);
    this->expect_true(common_fini() == BF_SUCCESS);
}

void
driver_entry_ut::test_common_unload_unload_when_corrupt()
{
    this->expect_true(common_add_module(m_dummy_start_vmm_success.get(), m_dummy_start_vmm_success_length) == BF_SUCCESS);
    this->expect_true(common_add_module(m_dummy_stop_vmm_failure.get(), m_dummy_stop_vmm_failure_length) == BF_SUCCESS);
    this->expect_true(common_add_module(m_dummy_add_md_success.get(), m_dummy_add_md_success_length) == BF_SUCCESS);
    this->expect_true(common_add_module(m_dummy_misc.get(), m_dummy_misc_length) == BF_SUCCESS);
    this->expect_true(common_load_vmm() == BF_SUCCESS);
    this->expect_true(common_start_vmm() == BF_SUCCESS);
    this->expect_true(common_fini() == BF_ERROR_VMM_CORRUPTED);
    this->expect_true(common_vmm_status() == VMM_CORRUPT);
    this->expect_true(common_unload_vmm() == BF_ERROR_VMM_CORRUPTED);

    common_reset();
}

void
driver_entry_ut::test_common_unload_loader_get_info_failed()
{
    this->expect_true(common_add_module(m_dummy_start_vmm_success.get(), m_dummy_start_vmm_success_length) == BF_SUCCESS);
    this->expect_true(common_add_module(m_dummy_stop_vmm_failure.get(), m_dummy_stop_vmm_failure_length) == BF_SUCCESS);
    this->expect_true(common_add_module(m_dummy_add_md_success.get(), m_dummy_add_md_success_length) == BF_SUCCESS);
    this->expect_true(common_add_module(m_dummy_misc.get(), m_dummy_misc_length) == BF_SUCCESS);
    this->expect_true(common_load_vmm() == BF_SUCCESS);

    {
        MockRepository mocks;
        mocks.ExpectCallFunc(bfelf_loader_get_info).Return(-1);

        RUN_UNITTEST_WITH_MOCKS(mocks, [&]
        {
            this->expect_true(common_unload_vmm() == -1);
        });
    }

    common_reset();
}

void
driver_entry_ut::test_common_unload_execute_symbol_failed()
{
    this->expect_true(common_add_module(m_dummy_start_vmm_success.get(), m_dummy_start_vmm_success_length) == BF_SUCCESS);
    this->expect_true(common_add_module(m_dummy_stop_vmm_failure.get(), m_dummy_stop_vmm_failure_length) == BF_SUCCESS);
    this->expect_true(common_add_module(m_dummy_add_md_success.get(), m_dummy_add_md_success_length) == BF_SUCCESS);
    this->expect_true(common_add_module(m_dummy_misc.get(), m_dummy_misc_length) == BF_SUCCESS);
    this->expect_true(common_load_vmm() == BF_SUCCESS);

    {
        MockRepository mocks;
        mocks.ExpectCallFunc(execute_symbol).Return(-1);

        RUN_UNITTEST_WITH_MOCKS(mocks, [&]
        {
            this->expect_true(common_unload_vmm() == -1);
        });
    }

    common_reset();
}

