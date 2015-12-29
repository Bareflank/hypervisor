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
#include <vmcs/vmcs_intel_x64.h>

uint64_t fake_vmread_return;

bool
fake_vmread(uint64_t field, uint64_t *val)
{
    if (val == 0)
        return false;

    *val = fake_vmread_return;
    return true;
}

void
vmcs_ut::test_check_host_cr0_for_unsupported_bits_missing_1s()
{
    MockRepository mocks;
    intrinsics_intel_x64 *intrinsics = mocks.Mock<intrinsics_intel_x64>();

    vmcs_intel_x64 vmcs(intrinsics);

    fake_vmread_return = 0x0;
    mocks.OnCall(intrinsics, intrinsics_intel_x64::vmread).Do(fake_vmread);
    mocks.OnCall(intrinsics, intrinsics_intel_x64::read_msr).With(IA32_VMX_CR0_FIXED0_MSR).Return(0x0F0);
    mocks.OnCall(intrinsics, intrinsics_intel_x64::read_msr).With(IA32_VMX_CR0_FIXED1_MSR).Return(0xFFFFFFFFFFFFFFFF);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_TRUE(vmcs.check_host_cr0_for_unsupported_bits() == false);
    });
}

void
vmcs_ut::test_check_host_cr0_for_unsupported_bits_missing_0s()
{
    MockRepository mocks;
    intrinsics_intel_x64 *intrinsics = mocks.Mock<intrinsics_intel_x64>();

    vmcs_intel_x64 vmcs(intrinsics);

    fake_vmread_return = 0xFFFFFFFFFFFFFFFF;
    mocks.OnCall(intrinsics, intrinsics_intel_x64::vmread).Do(fake_vmread);
    mocks.OnCall(intrinsics, intrinsics_intel_x64::read_msr).With(IA32_VMX_CR0_FIXED0_MSR).Return(0x0);
    mocks.OnCall(intrinsics, intrinsics_intel_x64::read_msr).With(IA32_VMX_CR0_FIXED1_MSR).Return(0xFFFFFFFFFFFFF0FF);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_TRUE(vmcs.check_host_cr0_for_unsupported_bits() == false);
    });
}

void
vmcs_ut::test_check_host_cr0_for_unsupported_bits_valid()
{
    MockRepository mocks;
    intrinsics_intel_x64 *intrinsics = mocks.Mock<intrinsics_intel_x64>();

    vmcs_intel_x64 vmcs(intrinsics);

    // The hardware apears to always return 0xFFFFFFFFFFFFFFFF for the fixed
    // 1 MSR, which means that it is always ok to turn on a bit. For this
    // reason we test this case specifically for valid as it's more likely to
    // occur on real hardware

    fake_vmread_return = 0x0FA;
    mocks.OnCall(intrinsics, intrinsics_intel_x64::vmread).Do(fake_vmread);
    mocks.OnCall(intrinsics, intrinsics_intel_x64::read_msr).With(IA32_VMX_CR0_FIXED0_MSR).Return(0x0F0);
    mocks.OnCall(intrinsics, intrinsics_intel_x64::read_msr).With(IA32_VMX_CR0_FIXED1_MSR).Return(0xFFFFFFFFFFFFFFFF);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_TRUE(vmcs.check_host_cr0_for_unsupported_bits() == true);
    });
}


// REMOVE ME:
//
// Make sure you take a look at the following:
// http://hippomocks.com/Main_Page
//
// Remember that you should only use ExpectCall if you cannot observe the
// result your looking for because the function modifies a dependency. Which
// is the big difference between a Mock and a Stub. A mock "expects" a function
// to be called as it is the thing your checking. A stub simply provides
// fake stimulus to get a certain part of the code to execute.
//
// There is also, NeverCall which is great here too. For example, I used that
// for vmxon / vmxoff becuase if that code is called under certain conditions
// your looking at a segfault.
//
// Also notice how I have three tests for a single function. That's because
// there are three different code paths in this one function. The function
// name clearly states what I am trying to do test_<func>_<desc>
//
