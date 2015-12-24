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
#include <debug_ring_interface.h>

// =============================================================================
// Expose Private Functions
// =============================================================================

// In order to mock some of the C functions, we need to expose them. These are
// private, so there is no need to test these functions, but we do need access
// to them to mock them up to test the public functions.

extern "C"
{
    uint64_t vmm_status(void);
    int64_t resolve_symbol(const char *name, void **sym);
}

// =============================================================================
// Tests
// =============================================================================

void
driver_entry_ut::test_common_dump_status_corrupt()
{
    MockRepository mocks;

    mocks.OnCallFunc(vmm_status).Return(VMM_CORRUPT);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_TRUE(common_dump_vmm() == BF_ERROR_VMM_CORRUPTED);
    });
}

void
driver_entry_ut::test_common_dump_status_unloaded()
{
    MockRepository mocks;

    mocks.OnCallFunc(vmm_status).Return(VMM_UNLOADED);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_TRUE(common_dump_vmm() == BF_ERROR_VMM_INVALID_STATE);
    });
}

void
driver_entry_ut::test_common_dump_platform_alloc_failed()
{
    MockRepository mocks;

    mocks.OnCallFunc(platform_alloc).Return(0);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_TRUE(common_add_module(m_dummy1, m_dummy1_length) == BF_SUCCESS);
        EXPECT_TRUE(common_add_module(m_dummy2, m_dummy2_length) == BF_SUCCESS);
        EXPECT_TRUE(common_add_module(m_dummy3, m_dummy3_length) == BF_SUCCESS);
        EXPECT_TRUE(common_load_vmm() == BF_SUCCESS);
        EXPECT_TRUE(common_dump_vmm() == BF_ERROR_OUT_OF_MEMORY);
        EXPECT_TRUE(common_unload_vmm() == BF_SUCCESS);
    });
}

void
driver_entry_ut::test_common_dump_resolve_symbol_failed()
{
    EXPECT_TRUE(common_add_module(m_dummy1, m_dummy1_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy2, m_dummy2_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy3, m_dummy3_length) == BF_SUCCESS);
    EXPECT_TRUE(common_load_vmm() == BF_SUCCESS);

    // We need to wrap the mocks variable in a temporary stack frame as the
    // current implementation of HippoMocks does not have a function to undo
    // it's hooks into c-style functions as the functionality to do this is
    // in the destructor.

    {
        MockRepository mocks;

        mocks.OnCallFunc(resolve_symbol).Return(-1);

        RUN_UNITTEST_WITH_MOCKS(mocks, [&]
        {
            EXPECT_TRUE(common_dump_vmm() == BF_ERROR_FAILED_TO_DUMP_DR);
        });
    }

    EXPECT_TRUE(common_unload_vmm() == BF_SUCCESS);
}

void
driver_entry_ut::test_common_dump_debug_ring_read_failed()
{
    MockRepository mocks;

    mocks.OnCallFunc(debug_ring_read).Return(-1);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_TRUE(common_add_module(m_dummy1, m_dummy1_length) == BF_SUCCESS);
        EXPECT_TRUE(common_add_module(m_dummy2, m_dummy2_length) == BF_SUCCESS);
        EXPECT_TRUE(common_add_module(m_dummy3, m_dummy3_length) == BF_SUCCESS);
        EXPECT_TRUE(common_load_vmm() == BF_SUCCESS);
        EXPECT_TRUE(common_dump_vmm() == BF_ERROR_FAILED_TO_DUMP_DR);
        EXPECT_TRUE(common_unload_vmm() == BF_SUCCESS);
    });
}

void
driver_entry_ut::test_common_dump_success()
{
    EXPECT_TRUE(common_add_module(m_dummy1, m_dummy1_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy2, m_dummy2_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy3, m_dummy3_length) == BF_SUCCESS);
    EXPECT_TRUE(common_load_vmm() == BF_SUCCESS);
    EXPECT_TRUE(common_dump_vmm() == BF_SUCCESS);
    EXPECT_TRUE(common_unload_vmm() == BF_SUCCESS);
}

void
driver_entry_ut::test_common_dump_success_multiple_times()
{
    EXPECT_TRUE(common_add_module(m_dummy1, m_dummy1_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy2, m_dummy2_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy3, m_dummy3_length) == BF_SUCCESS);
    EXPECT_TRUE(common_load_vmm() == BF_SUCCESS);
    EXPECT_TRUE(common_dump_vmm() == BF_SUCCESS);
    EXPECT_TRUE(common_unload_vmm() == BF_SUCCESS);
}
