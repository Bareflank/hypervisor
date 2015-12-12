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
#include <bfelf_loader.h>

// =============================================================================
// Expose Private Functions
// =============================================================================

// In order to mock some of the C functions, we need to expose them. These are
// private, so there is no need to test these functions, but we do need access
// to them to mock them up to test the public functions.

extern "C"
{
    uint64_t vmm_status(void);
    struct bfelf_file_t *elf_file(uint64_t index);
    int64_t execute_symbol(const char *sym);
    struct vmm_resources_t *get_vmmr(void);
}

// =============================================================================
// Tests
// =============================================================================

void
driver_entry_ut::test_common_start_already_started()
{
    MockRepository mocks;

    mocks.OnCallFunc(vmm_status).Return(VMM_STARTED);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_TRUE(common_start_vmm() == BF_SUCCESS);
    });
}

void
driver_entry_ut::test_common_start_init_loader_failed()
{
    MockRepository mocks;

    mocks.OnCallFunc(bfelf_loader_init).Return(-1);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_TRUE(common_start_vmm() == -1);
    });
}

void
driver_entry_ut::test_common_start_loader_add_failed()
{
    MockRepository mocks;

    mocks.OnCallFunc(bfelf_loader_add).Return(-1);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_TRUE(common_add_module(m_dummy1, m_dummy1_length) == BF_SUCCESS);
        EXPECT_TRUE(common_add_module(m_dummy2, m_dummy2_length) == BF_SUCCESS);
        EXPECT_TRUE(common_add_module(m_dummy3, m_dummy3_length) == BF_SUCCESS);
        EXPECT_TRUE(common_start_vmm() == -1);
        EXPECT_TRUE(common_stop_vmm() == BF_SUCCESS);
    });
}

void
driver_entry_ut::test_common_start_loader_relocate_failed()
{
    MockRepository mocks;

    mocks.OnCallFunc(bfelf_loader_relocate).Return(-1);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_TRUE(common_add_module(m_dummy1, m_dummy1_length) == BF_SUCCESS);
        EXPECT_TRUE(common_add_module(m_dummy2, m_dummy2_length) == BF_SUCCESS);
        EXPECT_TRUE(common_add_module(m_dummy3, m_dummy3_length) == BF_SUCCESS);
        EXPECT_TRUE(common_start_vmm() == -1);
        EXPECT_TRUE(common_stop_vmm() == BF_SUCCESS);
    });
}

void
driver_entry_ut::test_common_start_execute_symbol_failed()
{
    MockRepository mocks;

    mocks.OnCallFunc(execute_symbol).Return(-1);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_TRUE(common_add_module(m_dummy1, m_dummy1_length) == BF_SUCCESS);
        EXPECT_TRUE(common_add_module(m_dummy2, m_dummy2_length) == BF_SUCCESS);
        EXPECT_TRUE(common_add_module(m_dummy3, m_dummy3_length) == BF_SUCCESS);
        EXPECT_TRUE(common_start_vmm() == -1);
        EXPECT_TRUE(common_stop_vmm() == BF_SUCCESS);
    });
}

void
driver_entry_ut::test_common_start_get_vmmr_failed()
{
    MockRepository mocks;

    mocks.OnCallFunc(get_vmmr).Return(0);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_TRUE(common_add_module(m_dummy1, m_dummy1_length) == BF_SUCCESS);
        EXPECT_TRUE(common_add_module(m_dummy2, m_dummy2_length) == BF_SUCCESS);
        EXPECT_TRUE(common_add_module(m_dummy3, m_dummy3_length) == BF_SUCCESS);
        EXPECT_TRUE(common_start_vmm() == BF_ERROR_FAILED_TO_EXECUTE_SYMBOL);
        EXPECT_TRUE(common_stop_vmm() == BF_SUCCESS);
    });
}

void
driver_entry_ut::test_common_start_success()
{
    EXPECT_TRUE(common_add_module(m_dummy1, m_dummy1_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy2, m_dummy2_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy3, m_dummy3_length) == BF_SUCCESS);
    EXPECT_TRUE(common_start_vmm() == BF_SUCCESS);
    EXPECT_TRUE(common_stop_vmm() == BF_SUCCESS);
}

void
driver_entry_ut::test_common_start_success_multiple_times()
{
    EXPECT_TRUE(common_add_module(m_dummy1, m_dummy1_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy2, m_dummy2_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy3, m_dummy3_length) == BF_SUCCESS);
    EXPECT_TRUE(common_start_vmm() == BF_SUCCESS);
    EXPECT_TRUE(common_start_vmm() == BF_SUCCESS);
    EXPECT_TRUE(common_start_vmm() == BF_SUCCESS);
    EXPECT_TRUE(common_stop_vmm() == BF_SUCCESS);
}
