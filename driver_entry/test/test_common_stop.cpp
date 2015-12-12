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
    int64_t execute_symbol(const char *sym);
}

// =============================================================================
// Tests
// =============================================================================

void
driver_entry_ut::test_common_stop_already_stopped()
{
    MockRepository mocks;

    mocks.OnCallFunc(vmm_status).Return(VMM_STOPPED);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_TRUE(common_stop_vmm() == BF_SUCCESS);
    });
}

void
driver_entry_ut::test_common_stop_execute_symbol_failed()
{
    MockRepository mocks;

    mocks.OnCallFunc(vmm_status).Return(VMM_STARTED);
    mocks.OnCallFunc(execute_symbol).Return(-1);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_TRUE(common_stop_vmm() == BF_SUCCESS);
    });
}

void
driver_entry_ut::test_common_stop_success()
{
    EXPECT_TRUE(common_stop_vmm() == BF_SUCCESS);
}

void
driver_entry_ut::test_common_stop_success_multiple_times()
{
    EXPECT_TRUE(common_stop_vmm() == BF_SUCCESS);
    EXPECT_TRUE(common_stop_vmm() == BF_SUCCESS);
    EXPECT_TRUE(common_stop_vmm() == BF_SUCCESS);
}
