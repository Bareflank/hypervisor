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
    struct bfelf_file_t *get_next_file(void);
    void *add_elf_file(uint64_t size);
}

// =============================================================================
// Tests
// =============================================================================

void
driver_entry_ut::test_common_add_module_invalid_file()
{
    MockRepository mocks;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_TRUE(common_add_module(NULL, m_dummy1_length) == BF_ERROR_INVALID_ARG);
    });
}

void
driver_entry_ut::test_common_add_module_invalid_file_size()
{
    MockRepository mocks;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_TRUE(common_add_module(m_dummy1, 0) == BF_ERROR_INVALID_ARG);
    });
}

void
driver_entry_ut::test_common_add_module_status_already_running()
{
    MockRepository mocks;

    mocks.OnCallFunc(vmm_status).Return(VMM_STARTED);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_TRUE(common_add_module(m_dummy1, m_dummy1_length) == BF_ERROR_VMM_ALREADY_STARTED);
    });
}

void
driver_entry_ut::test_common_add_module_get_next_file_failed()
{
    MockRepository mocks;

    mocks.OnCallFunc(get_next_file).Return(0);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_TRUE(common_add_module(m_dummy1, m_dummy1_length) == BF_ERROR_MAX_MODULES_REACHED);
    });
}

void
driver_entry_ut::test_common_add_module_elf_file_init_failed()
{
    MockRepository mocks;

    mocks.OnCallFunc(bfelf_file_init).Return(-1);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_TRUE(common_add_module(m_dummy1, m_dummy1_length) == -1);
    });
}

void
driver_entry_ut::test_common_add_module_elf_file_total_exec_failed()
{
    MockRepository mocks;

    mocks.OnCallFunc(bfelf_total_exec_size).Return(-1);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_TRUE(common_add_module(m_dummy1, m_dummy1_length) == -1);
    });
}

void
driver_entry_ut::test_common_add_module_add_elf_file_failed()
{
    MockRepository mocks;

    mocks.OnCallFunc(add_elf_file).Return(0);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_TRUE(common_add_module(m_dummy1, m_dummy1_length) == BF_ERROR_FAILED_TO_ADD_FILE);
    });
}

void
driver_entry_ut::test_common_add_module_elf_file_load_failed()
{
    MockRepository mocks;

    mocks.OnCallFunc(bfelf_file_load).Return(-1);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_TRUE(common_add_module(m_dummy1, m_dummy1_length) == -1);
    });
}

void
driver_entry_ut::test_common_add_module_add_success()
{
    EXPECT_TRUE(common_add_module(m_dummy1, m_dummy1_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy2, m_dummy2_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy3, m_dummy3_length) == BF_SUCCESS);
    EXPECT_TRUE(common_stop_vmm() == BF_SUCCESS);
}
