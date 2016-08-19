//
// Bareflank Hypervisor
//
// Copyright (C) 2015 Assured Information Security, Inc.
// Author: Rian Quinn        <quinnr@ainfosec.com>
// Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
// Author: Connor Davis <davisc@ainfosec.com>
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
#include <memory_manager/memory_manager.h>

static uintptr_t
virt_to_phys_ptr(void *ptr)
{
    (void) ptr;

    return 0x0000000ABCDEF0000;
}

static void
setup_vmcs_intrinsics(MockRepository &mocks, memory_manager *mm, intrinsics_intel_x64 *in)
{
    // Emulate the memory manager
    mocks.OnCallFunc(memory_manager::instance).Return(mm);
    mocks.OnCallOverload(mm, (uintptr_t(memory_manager::*)(void *))&memory_manager::virt_to_phys).Do(virt_to_phys_ptr);

    // Setup MSR and vmread returns to mock a successful vmcs_intel_x64::filter_unsupported
    mocks.OnCall(in, intrinsics_intel_x64::read_msr).With(IA32_VMX_BASIC_MSR).Return(0x7fffFFFF);
    mocks.OnCall(in, intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PINBASED_CTLS_MSR).Return(0x55555555aaaaAAAA);
    mocks.OnCall(in, intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return(0x55555555aaaaAAAA);
    mocks.OnCall(in, intrinsics_intel_x64::read_msr).With(IA32_VMX_PROCBASED_CTLS2_MSR).Return(0x55555555aaaaAAAA);
    mocks.OnCall(in, intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_EXIT_CTLS_MSR).Return(0x55555555aaaaAAAA);
    mocks.OnCall(in, intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_ENTRY_CTLS_MSR).Return(0x55555555aaaaAAAA);
    mocks.OnCall(in, intrinsics_intel_x64::vmread).Return(0x5555555555555555);

    // Make the default return of the vm* calls true
    mocks.OnCall(in, intrinsics_intel_x64::vmclear).Return(true);
    mocks.OnCall(in, intrinsics_intel_x64::vmptrld).Return(true);
    mocks.OnCall(in, intrinsics_intel_x64::vmwrite).Return(true);
    mocks.OnCall(in, intrinsics_intel_x64::vmlaunch).Return(true);
}

void
vmcs_ut::test_launch_success()
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager>();
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    setup_vmcs_intrinsics(mocks, mm, in.get());

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        vmcs_intel_x64 vmcs(in);

        auto host_state = std::make_shared<vmcs_intel_x64_state>();
        auto guest_state = std::make_shared<vmcs_intel_x64_state>();

        EXPECT_NO_EXCEPTION(vmcs.launch(host_state, guest_state));
    });
}
