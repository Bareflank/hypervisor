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

#include <memory>

#include <common.h>
#include <platform.h>

void
driver_entry_ut::test_commit_init_failed_alloc()
{
    MockRepository mocks;

    mocks.OnCallFunc(platform_alloc).Return(NULL);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_TRUE(common_init() == BF_ERROR_FAILED_TO_ALLOC_DRR);
    });
}

void
driver_entry_ut::test_commit_init_success()
{
    MockRepository mocks;
    auto mem = std::shared_ptr<char>(new char[1000]());

    mocks.OnCallFunc(platform_alloc).Return(mem.get());

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_TRUE(common_init() == BF_SUCCESS);
    });
}
