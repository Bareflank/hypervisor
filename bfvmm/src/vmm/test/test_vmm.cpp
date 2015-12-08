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
#include <vmm/vmm_intel_x64.h>

void
vmm_ut::test_check_support_v8086_enabled()
{
    // MockRepository mocks;
    // intrinsics_intel_x64 *intrinsics = mocks.Mock<intrinsics_intel_x64>();

    // mocks.OnCall(intrinsics, intrinsics_intel_x64::read_rflags).Return(5);

    // RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    // {
    //     vmm_intel_x64::instance().init(intrinsics);

    //     EXPECT_TRUE(vmm_intel_x64::instance().start() == vmm_error::success);
    // });
}
