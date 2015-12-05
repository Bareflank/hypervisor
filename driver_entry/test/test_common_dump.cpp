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
// Tests
// =============================================================================

void
driver_entry_ut::test_common_dump_platform_alloc_failed()
{
    MockRepository mocks;

    mocks.OnCallFunc(platform_alloc).Return(0);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_TRUE(common_dump_vmm() == BF_ERROR_FAILED_TO_ALLOC_RB);
    });
}

void
driver_entry_ut::test_common_dump_debug_ring_read_failed()
{
    MockRepository mocks;

    mocks.OnCallFunc(debug_ring_read).Return(-1);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_TRUE(common_dump_vmm() == BF_SUCCESS);
    });
}

void
driver_entry_ut::test_common_dump_success()
{
    EXPECT_TRUE(common_dump_vmm() == BF_SUCCESS);
}

void
driver_entry_ut::test_common_dump_success_multiple_times()
{
    EXPECT_TRUE(common_dump_vmm() == BF_SUCCESS);
    EXPECT_TRUE(common_dump_vmm() == BF_SUCCESS);
    EXPECT_TRUE(common_dump_vmm() == BF_SUCCESS);
}
