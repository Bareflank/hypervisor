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
#include <memory_manager/memory_manager.h>

uint64_t fake_vmread_return;

memory_manager *mm = NULL;

static void *
stubbed_malloc_aligned(size_t size, int64_t alignment)
{
    (void)alignment;
    return malloc(size);
}

static memory_manager *
fake_memory_manager()
{
    return mm;
}

bool
fake_vmread(uint64_t field, uint64_t *val)
{
    (void) field;

    if (val == 0)
        return false;

    *val = fake_vmread_return;
    return true;
}

void
vmcs_ut::test_no_intrinsics()
{
    auto in = std::shared_ptr<intrinsics_intel_x64>(0);

    EXPECT_NO_EXCEPTION(vmcs_intel_x64 vmcs(in));
}


void
vmcs_ut::test_launch_is_supported_msr_bitmaps_failure()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    vmcs_intel_x64 vmcs(in);
    auto host_state = vmcs_state_intel_x64();
    auto guest_state = vmcs_state_intel_x64();

    // Breakage
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return(~(VM_EXEC_P_PROC_BASED_MONITOR_TRAP_FLAG << 32));

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(vmcs.launch(host_state, guest_state), bfn::hardware_unsupported_error);
    });
}


void
vmcs_ut::test_launch_is_supported_host_address_space_size_failure()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    vmcs_intel_x64 vmcs(in);
    auto host_state = vmcs_state_intel_x64();
    auto guest_state = vmcs_state_intel_x64();

    // Setup
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((VM_EXEC_P_PROC_BASED_MONITOR_TRAP_FLAG << 32));

    // Breakage
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_EXIT_CTLS_MSR).Return(~(VM_EXIT_CONTROL_HOST_ADDRESS_SPACE_SIZE << 32));

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(vmcs.launch(host_state, guest_state), bfn::hardware_unsupported_error);
    });
}


void
vmcs_ut::test_launch_is_supported_ia_32e_mode_guest_failure()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    vmcs_intel_x64 vmcs(in);
    auto host_state = vmcs_state_intel_x64();
    auto guest_state = vmcs_state_intel_x64();

    // Setup
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((VM_EXEC_P_PROC_BASED_MONITOR_TRAP_FLAG << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_EXIT_CTLS_MSR).Return((VM_EXIT_CONTROL_HOST_ADDRESS_SPACE_SIZE << 32));

    // Breakage
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_ENTRY_CTLS_MSR).Return(~(VM_ENTRY_CONTROL_IA_32E_MODE_GUEST << 32));

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(vmcs.launch(host_state, guest_state), bfn::hardware_unsupported_error);
    });
}

void
vmcs_ut::test_launch_vmclear_failure()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);
    auto host_state = vmcs_state_intel_x64();
    auto guest_state = vmcs_state_intel_x64();

    // Setup
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((VM_EXEC_P_PROC_BASED_MONITOR_TRAP_FLAG << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_EXIT_CTLS_MSR).Return((VM_EXIT_CONTROL_HOST_ADDRESS_SPACE_SIZE << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_ENTRY_CTLS_MSR).Return((VM_ENTRY_CONTROL_IA_32E_MODE_GUEST << 32));

    mocks.OnCallFunc(memory_manager::instance).Do(fake_memory_manager);
    mocks.OnCall(mm, memory_manager::malloc_aligned).Do(stubbed_malloc_aligned);
    mocks.OnCall(mm, memory_manager::virt_to_phys).Return((void *)0xDEADBEEFDEAF1000);
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_BASIC_MSR).Return(0xFFFFFFFF);

    // Breakage
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmclear).Return(false);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(vmcs.launch(host_state, guest_state), bfn::vmcs_failure_error);
    });

    mm = NULL;
}


void
vmcs_ut::test_launch_vmptrld_failure()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);
    auto host_state = vmcs_state_intel_x64();
    auto guest_state = vmcs_state_intel_x64();

    // Setup
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((VM_EXEC_P_PROC_BASED_MONITOR_TRAP_FLAG << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_EXIT_CTLS_MSR).Return((VM_EXIT_CONTROL_HOST_ADDRESS_SPACE_SIZE << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_ENTRY_CTLS_MSR).Return((VM_ENTRY_CONTROL_IA_32E_MODE_GUEST << 32));

    mocks.OnCallFunc(memory_manager::instance).Do(fake_memory_manager);
    mocks.OnCall(mm, memory_manager::malloc_aligned).Do(stubbed_malloc_aligned);
    mocks.OnCall(mm, memory_manager::virt_to_phys).Return((void *)0xDEADBEEFDEAF1000);

    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_BASIC_MSR).Return(0xFFFFFFFF);

    mocks.OnCall(in.get(), intrinsics_intel_x64::vmclear).Return(true);

    // Breakage
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmptrld).Return(false);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(vmcs.launch(host_state, guest_state), bfn::vmcs_failure_error);
    });

    mm = NULL;
}


void
vmcs_ut::test_launch_vmwrite_failure()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);
    auto host_state = vmcs_state_intel_x64();
    auto guest_state = vmcs_state_intel_x64();

    // Setup
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((VM_EXEC_P_PROC_BASED_MONITOR_TRAP_FLAG << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_EXIT_CTLS_MSR).Return((VM_EXIT_CONTROL_HOST_ADDRESS_SPACE_SIZE << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_ENTRY_CTLS_MSR).Return((VM_ENTRY_CONTROL_IA_32E_MODE_GUEST << 32));

    mocks.OnCallFunc(memory_manager::instance).Do(fake_memory_manager);
    mocks.OnCall(mm, memory_manager::malloc_aligned).Do(stubbed_malloc_aligned);
    mocks.OnCall(mm, memory_manager::virt_to_phys).Return((void *)0xDEADBEEFDEAF1000);

    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_BASIC_MSR).Return(0xFFFFFFFF);

    mocks.OnCall(in.get(), intrinsics_intel_x64::vmclear).Return(true);
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmptrld).Return(true);

    // Breakage
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmwrite).Return(false);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(vmcs.launch(host_state, guest_state), bfn::vmcs_write_failure_error);
    });

    mm = NULL;
}

void
vmcs_ut::test_launch_vmread_failure()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);
    auto host_state = vmcs_state_intel_x64();
    auto guest_state = vmcs_state_intel_x64();

    // Setup
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((VM_EXEC_P_PROC_BASED_MONITOR_TRAP_FLAG << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_EXIT_CTLS_MSR).Return((VM_EXIT_CONTROL_HOST_ADDRESS_SPACE_SIZE << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_ENTRY_CTLS_MSR).Return((VM_ENTRY_CONTROL_IA_32E_MODE_GUEST << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PINBASED_CTLS_MSR).Return((0xFFFFFFFFFFFFFFFF));

    mocks.OnCallFunc(memory_manager::instance).Do(fake_memory_manager);
    mocks.OnCall(mm, memory_manager::malloc_aligned).Do(stubbed_malloc_aligned);
    mocks.OnCall(mm, memory_manager::virt_to_phys).Return((void *)0xDEADBEEFDEAF1000);

    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_BASIC_MSR).Return(0xFFFFFFFF);

    mocks.OnCall(in.get(), intrinsics_intel_x64::vmclear).Return(true);
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmptrld).Return(true);

    mocks.OnCall(in.get(), intrinsics_intel_x64::segment_descriptor_access).Return(0);

    mocks.OnCall(in.get(), intrinsics_intel_x64::vmwrite).Return(true);

    // Breakage
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Return(false);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(vmcs.launch(host_state, guest_state), bfn::vmcs_read_failure_error);
    });

    mm = NULL;
}

void
vmcs_ut::test_launch_vmlaunch_failure()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);
    auto host_state = vmcs_state_intel_x64();
    auto guest_state = vmcs_state_intel_x64();

    // Setup
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((VM_EXEC_P_PROC_BASED_MONITOR_TRAP_FLAG << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_EXIT_CTLS_MSR).Return((VM_EXIT_CONTROL_HOST_ADDRESS_SPACE_SIZE << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_ENTRY_CTLS_MSR).Return((VM_ENTRY_CONTROL_IA_32E_MODE_GUEST << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PINBASED_CTLS_MSR).Return((0xFFFFFFFFFFFFFFFF));

    mocks.OnCallFunc(memory_manager::instance).Do(fake_memory_manager);
    mocks.OnCall(mm, memory_manager::malloc_aligned).Do(stubbed_malloc_aligned);
    mocks.OnCall(mm, memory_manager::virt_to_phys).Return((void *)0xDEADBEEFDEAF1000);

    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_BASIC_MSR).Return(0xFFFFFFFF);

    mocks.OnCall(in.get(), intrinsics_intel_x64::vmclear).Return(true);
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmptrld).Return(true);

    mocks.OnCall(in.get(), intrinsics_intel_x64::segment_descriptor_access).Return(0);

    mocks.OnCall(in.get(), intrinsics_intel_x64::vmwrite).Return(true);
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Return(true);

    // Breakage
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmlaunch).Return(false);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(vmcs.launch(host_state, guest_state), bfn::vmcs_launch_failure_error);
    });

    mm = NULL;
}

void
vmcs_ut::test_launch_success()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);
    auto host_state = vmcs_state_intel_x64();
    auto guest_state = vmcs_state_intel_x64();

    // Setup
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((VM_EXEC_P_PROC_BASED_MONITOR_TRAP_FLAG << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_EXIT_CTLS_MSR).Return((VM_EXIT_CONTROL_HOST_ADDRESS_SPACE_SIZE << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_ENTRY_CTLS_MSR).Return((VM_ENTRY_CONTROL_IA_32E_MODE_GUEST << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PINBASED_CTLS_MSR).Return((0xFFFFFFFFFFFFFFFF));

    mocks.OnCallFunc(memory_manager::instance).Do(fake_memory_manager);
    mocks.OnCall(mm, memory_manager::malloc_aligned).Do(stubbed_malloc_aligned);
    mocks.OnCall(mm, memory_manager::virt_to_phys).Return((void *)0xDEADBEEFDEAF1000);

    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_BASIC_MSR).Return(0xFFFFFFFF);

    mocks.OnCall(in.get(), intrinsics_intel_x64::vmclear).Return(true);
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmptrld).Return(true);

    mocks.OnCall(in.get(), intrinsics_intel_x64::segment_descriptor_access).Return(0);

    mocks.OnCall(in.get(), intrinsics_intel_x64::vmwrite).Return(true);
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Return(true);

    // Breakage
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmlaunch).Return(true);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(vmcs.launch(host_state, guest_state));
    });

    mm = NULL;
}

