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
#include <vmcs/vmcs_intel_x64_exceptions.h>
#include <memory_manager/memory_manager.h>

uint64_t fake_vmread_return[8];
uint64_t fake_vmread_index = 0;
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

    std::cout << "[" << fake_vmread_index << "] -> " << (void *)fake_vmread_return[fake_vmread_index] << std::endl;

    *val = fake_vmread_return[fake_vmread_index];
    fake_vmread_index++;

    return true;
}

void
vmcs_ut::test_no_intrinsics()
{
    auto in = std::shared_ptr<intrinsics_intel_x64>(0);

    EXPECT_NO_EXCEPTION(vmcs_intel_x64 vmcs(in));
}

void
vmcs_ut::test_launch_is_supported_host_address_space_size_failure()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    vmcs_intel_x64 vmcs(in);
    auto host_state = std::make_shared<vmcs_intel_x64_state>();
    auto guest_state = std::make_shared<vmcs_intel_x64_state>();

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
    auto host_state = std::make_shared<vmcs_intel_x64_state>();
    auto guest_state = std::make_shared<vmcs_intel_x64_state>();

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
    auto host_state = std::make_shared<vmcs_intel_x64_state>();
    auto guest_state = std::make_shared<vmcs_intel_x64_state>();

    // Setup
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
    auto host_state = std::make_shared<vmcs_intel_x64_state>();
    auto guest_state = std::make_shared<vmcs_intel_x64_state>();

    // Setup

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
    auto host_state = std::make_shared<vmcs_intel_x64_state>();
    auto guest_state = std::make_shared<vmcs_intel_x64_state>();

    // Setup
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
    auto host_state = std::make_shared<vmcs_intel_x64_state>();
    auto guest_state = std::make_shared<vmcs_intel_x64_state>();

    // Setup
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((VM_EXEC_P_PROC_BASED_USE_MSR_BITMAPS << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_EXIT_CTLS_MSR).Return((VM_EXIT_CONTROL_HOST_ADDRESS_SPACE_SIZE << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_ENTRY_CTLS_MSR).Return((VM_ENTRY_CONTROL_IA_32E_MODE_GUEST << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PINBASED_CTLS_MSR).Return((0xFFFFFFFFFFFFFFFF));

    mocks.OnCallFunc(memory_manager::instance).Do(fake_memory_manager);
    mocks.OnCall(mm, memory_manager::malloc_aligned).Do(stubbed_malloc_aligned);
    mocks.OnCall(mm, memory_manager::virt_to_phys).Return((void *)0xDEADBEEFDEAF1000);

    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_BASIC_MSR).Return(0xFFFFFFFF);

    mocks.OnCall(in.get(), intrinsics_intel_x64::vmclear).Return(true);
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmptrld).Return(true);

    mocks.OnCall(in.get(), intrinsics_intel_x64::vmwrite).Return(true);

    // Breakage
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Return(false);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(vmcs.launch(host_state, guest_state), bfn::vmcs_read_failure_error);
    });

    mm = NULL;
}


static void setup_success_launch(MockRepository &mocks, intrinsics_intel_x64 *in)
{
    // Setup
    mocks.OnCall(in, intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((VM_EXEC_P_PROC_BASED_USE_MSR_BITMAPS << 32));
    mocks.OnCall(in, intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_EXIT_CTLS_MSR).Return((VM_EXIT_CONTROL_HOST_ADDRESS_SPACE_SIZE << 32));
    mocks.OnCall(in, intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_ENTRY_CTLS_MSR).Return((VM_ENTRY_CONTROL_IA_32E_MODE_GUEST << 32));
    mocks.OnCall(in, intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PINBASED_CTLS_MSR).Return((0xFFFFFFFFFFFFFFFF));

    mocks.OnCallFunc(memory_manager::instance).Do(fake_memory_manager);
    mocks.OnCall(mm, memory_manager::malloc_aligned).Do(stubbed_malloc_aligned);
    mocks.OnCall(mm, memory_manager::virt_to_phys).Return((void *)0xDEADBEEFDEAF1000);

    mocks.OnCall(in, intrinsics_intel_x64::read_msr).With(IA32_VMX_BASIC_MSR).Return(0xFFFFFFFF);

    mocks.OnCall(in, intrinsics_intel_x64::vmclear).Return(true);
    mocks.OnCall(in, intrinsics_intel_x64::vmptrld).Return(true);

    mocks.OnCall(in, intrinsics_intel_x64::vmwrite).Return(true);
    mocks.OnCall(in, intrinsics_intel_x64::vmread).Return(true);

    // fake msr_read for dump_vmcs()
    mocks.OnCall(in, intrinsics_intel_x64::read_msr).With(IA32_VMX_PROCBASED_CTLS2_MSR).Return(0);

}

void
vmcs_ut::test_launch_success()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);
    auto host_state = std::make_shared<vmcs_intel_x64_state>();
    auto guest_state = std::make_shared<vmcs_intel_x64_state>();

    setup_success_launch(mocks, in.get());

    mocks.OnCall(in.get(), intrinsics_intel_x64::vmlaunch).Return(true);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(vmcs.launch(host_state, guest_state));
    });

    mm = NULL;
}


void
vmcs_ut::test_check_control_pin_based_ctls_reserved_properly_set_success()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    // Breakage
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PINBASED_CTLS_MSR).Return((0x55555555aaaaAAAA));
    fake_vmread_return[0] = 0xAAAAaaaaAAAAaaaa;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(vmcs.check_control_pin_based_ctls_reserved_properly_set());
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_pin_based_ctls_reserved_properly_set_fail_lower()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    // Breakage
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PINBASED_CTLS_MSR).Return((0x55555555aaaaAAAA));
    fake_vmread_return[0] = 0x7777777755555555;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(vmcs.check_control_pin_based_ctls_reserved_properly_set(), bfn::vmcs_invalid_ctls_error);
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_pin_based_ctls_reserved_properly_set_fail_upper()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    // Breakage
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PINBASED_CTLS_MSR).Return((0x55555555aaaaAAAA));
    fake_vmread_return[0] = 0x77777777AAAAaaaa;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(vmcs.check_control_pin_based_ctls_reserved_properly_set(), bfn::vmcs_invalid_ctls_error);
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_proc_based_ctls_reserved_properly_set_success()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    // Breakage
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((0x55555555aaaaAAAA));
    fake_vmread_return[0] = 0xAAAAaaaaAAAAaaaa;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(vmcs.check_control_proc_based_ctls_reserved_properly_set());
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_proc_based_ctls_reserved_properly_set_fail_lower()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);
    fake_vmread_index = 0;

    // Breakage
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((0x55555555aaaaAAAA));
    fake_vmread_return[0] = 0x7777777755555555;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(vmcs.check_control_proc_based_ctls_reserved_properly_set(), bfn::vmcs_invalid_ctls_error);
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_proc_based_ctls_reserved_properly_set_fail_upper()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);
    fake_vmread_index = 0;

    // Breakage
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((0x55555555aaaaAAAA));
    fake_vmread_return[0] = 0x77777777AAAAaaaa;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(vmcs.check_control_proc_based_ctls_reserved_properly_set(), bfn::vmcs_invalid_ctls_error);
    });

    fake_vmread_index = 0;
    mm = NULL;
}


void
vmcs_ut::test_check_control_proc_based_ctls2_reserved_properly_set_success()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    // Breakage
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((0xFFFFFFFFFFFFFFFF));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_PROCBASED_CTLS2_MSR).Return((0x55555555aaaaAAAA));

    fake_vmread_index = 0;
    fake_vmread_return[0] = 0xFFFFFFFFFFFFFFFF;
    fake_vmread_return[1] = 0xAAAAAAAAAAAAAAAA;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(vmcs.check_control_proc_based_ctls2_reserved_properly_set());
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_proc_based_ctls2_reserved_properly_set_fail_lower()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    // Breakage
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((0xFFFFFFFFFFFFFFFF));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_PROCBASED_CTLS2_MSR).Return((0x55555555aaaaAAAA));
    fake_vmread_return[0] = 0x7777777755555555;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(vmcs.check_control_proc_based_ctls2_reserved_properly_set(), bfn::vmcs_invalid_ctls_error);
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_proc_based_ctls2_reserved_properly_set_fail_upper()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    // Breakage
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((0xFFFFFFFFFFFFFFFF));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_PROCBASED_CTLS2_MSR).Return((0x55555555aaaaAAAA));
    fake_vmread_return[0] = 0xAAAAAAAA77777777;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(vmcs.check_control_proc_based_ctls2_reserved_properly_set(), bfn::vmcs_invalid_ctls_error);
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_cr3_count_less_then_4_fail()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    // Breakage
    fake_vmread_return[0] = 0x20;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(vmcs.check_control_cr3_count_less_then_4(), bfn::vmcs_invalid_field_error);
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_cr3_count_less_then_4_success()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    // Breakage
    fake_vmread_return[0] = 0x4;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(vmcs.check_control_cr3_count_less_then_4());
    });

    fake_vmread_index = 0;
    mm = NULL;
}


void
vmcs_ut::test_check_control_io_bitmap_address_bits_success()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;

    // Breakage
    fake_vmread_return[0] = VM_EXEC_P_PROC_BASED_USE_IO_BITMAPS;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);
    fake_vmread_return[1] = 0xFFFFAAAA0000;
    fake_vmread_return[2] = 0xFFFFBBBB0000;

    mocks.OnCall(in.get(), intrinsics_intel_x64::cpuid_eax).Return(48);
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((VM_EXEC_P_PROC_BASED_USE_IO_BITMAPS << 32));

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(vmcs.check_control_io_bitmap_address_bits());
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_io_bitmap_address_bits_fail_alignment_a()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;

    // Breakage
    fake_vmread_return[0] = VM_EXEC_P_PROC_BASED_USE_IO_BITMAPS;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);
    fake_vmread_return[1] = 0xFFFCAAAA0010;
    fake_vmread_return[2] = 0xFFFCBBBB0000;

    mocks.OnCall(in.get(), intrinsics_intel_x64::cpuid_eax).Return(48);
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((VM_EXEC_P_PROC_BASED_USE_IO_BITMAPS << 32));

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(vmcs.check_control_io_bitmap_address_bits(), bfn::invalid_alignment_error);
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_io_bitmap_address_bits_fail_alignment_b()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;

    // Breakage
    fake_vmread_return[0] = VM_EXEC_P_PROC_BASED_USE_IO_BITMAPS;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);
    fake_vmread_return[1] = 0xFFFCAAAA0000;
    fake_vmread_return[2] = 0xFFFCBBBB0010;

    mocks.OnCall(in.get(), intrinsics_intel_x64::cpuid_eax).Return(48);
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((VM_EXEC_P_PROC_BASED_USE_IO_BITMAPS << 32));

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(vmcs.check_control_io_bitmap_address_bits(), bfn::invalid_alignment_error);
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_io_bitmap_address_bits_fail_size_a()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;

    // Breakage
    fake_vmread_return[0] = VM_EXEC_P_PROC_BASED_USE_IO_BITMAPS;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);
    fake_vmread_return[1] = 0xFFFC0000AAAA0000;
    fake_vmread_return[2] = 0xFFFC0000BBBB0000;

    mocks.OnCall(in.get(), intrinsics_intel_x64::cpuid_eax).Return(48);
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((VM_EXEC_P_PROC_BASED_USE_IO_BITMAPS << 32));

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(vmcs.check_control_io_bitmap_address_bits(), bfn::invalid_address_error);
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_io_bitmap_address_bits_fail_size_b()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;

    // Breakage
    fake_vmread_return[0] = VM_EXEC_P_PROC_BASED_USE_IO_BITMAPS;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);
    fake_vmread_return[1] = 0xFFFC0000AAAA0000;
    fake_vmread_return[2] = 0xFFFC0000BBBB0000;

    mocks.OnCall(in.get(), intrinsics_intel_x64::cpuid_eax).Return(48);
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((VM_EXEC_P_PROC_BASED_USE_IO_BITMAPS << 32));

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(vmcs.check_control_io_bitmap_address_bits(), bfn::invalid_address_error);
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_msr_bitmap_address_bits_success()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;

    // Breakage
    fake_vmread_return[0] = VM_EXEC_P_PROC_BASED_USE_MSR_BITMAPS;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);
    fake_vmread_return[1] = 0xFFFCAAAA0000;

    mocks.OnCall(in.get(), intrinsics_intel_x64::cpuid_eax).Return(48);
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((VM_EXEC_P_PROC_BASED_USE_MSR_BITMAPS << 32));


    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(vmcs.check_control_msr_bitmap_address_bits());
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_msr_bitmap_address_bits_fail_alignment()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;

    // Breakage
    fake_vmread_return[0] = VM_EXEC_P_PROC_BASED_USE_MSR_BITMAPS;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);
    fake_vmread_return[1] = 0xFFFCAAAA0002;

    mocks.OnCall(in.get(), intrinsics_intel_x64::cpuid_eax).Return(48);
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((VM_EXEC_P_PROC_BASED_USE_MSR_BITMAPS << 32));


    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(vmcs.check_control_msr_bitmap_address_bits(), bfn::invalid_alignment_error);
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_msr_bitmap_address_bits_fail_size()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;

    // Breakage
    fake_vmread_return[0] = VM_EXEC_P_PROC_BASED_USE_MSR_BITMAPS;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);
    fake_vmread_return[1] = 0xFFFC0000AAAA0000;

    mocks.OnCall(in.get(), intrinsics_intel_x64::cpuid_eax).Return(48);
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((VM_EXEC_P_PROC_BASED_USE_MSR_BITMAPS << 32));


    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(vmcs.check_control_msr_bitmap_address_bits(), bfn::invalid_address_error);
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_tpr_shadow_and_virtual_apic_success_enabled()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;

    // tpr shadow enabled
    fake_vmread_return[0] = (VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS | VM_EXEC_P_PROC_BASED_USE_TPR_SHADOW);
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    // valid phys addr
    fake_vmread_return[1] = 0xFFFCAAAA0000;

    // secondary controls supported and enabled
    fake_vmread_return[2] = fake_vmread_return[0];
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((VM_EXEC_P_PROC_BASED_USE_TPR_SHADOW << 32) | (VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_PROCBASED_CTLS2_MSR).Return((VM_EXEC_S_PROC_BASED_VIRTUALIZE_APIC_ACCESSES << 32) | (VM_EXEC_S_PROC_BASED_VIRTUAL_INTERRUPT_DELIVERY << 32));
    fake_vmread_return[3] = (VM_EXEC_S_PROC_BASED_VIRTUAL_INTERRUPT_DELIVERY | VM_EXEC_S_PROC_BASED_VIRTUALIZE_APIC_ACCESSES);
    fake_vmread_return[5] = fake_vmread_return[0];
    fake_vmread_return[6] = fake_vmread_return[3];

    // TPR threshold value
    fake_vmread_return[4] = 0x07;

    // physaddr width
    mocks.OnCall(in.get(), intrinsics_intel_x64::cpuid_eax).Return(48);

    // phys addr lookup
    mocks.OnCallFunc(memory_manager::instance).Do(fake_memory_manager);
    void *vapic_page = malloc(4096);
    mocks.OnCall(mm, memory_manager::phys_to_virt).Return(vapic_page);
    uint8_t *ptr2 = (uint8_t *)((uint8_t *)vapic_page + 0x80);
    ptr2[0] = 0xF0;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(vmcs.check_control_tpr_shadow_and_virtual_apic());
    });

    fake_vmread_index = 0;
    free(vapic_page);
    mm = NULL;
}

void
vmcs_ut::test_check_control_tpr_shadow_and_virtual_apic_fail_enabled_null_phys_page()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;

    // tpr shadow enabled
    fake_vmread_return[0] = (VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS | VM_EXEC_P_PROC_BASED_USE_TPR_SHADOW);
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    // valid phys addr
    fake_vmread_return[1] = 0;

    // secondary controls supported and enabled
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((VM_EXEC_P_PROC_BASED_USE_TPR_SHADOW << 32) | (VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_PROCBASED_CTLS2_MSR).Return((VM_EXEC_S_PROC_BASED_VIRTUALIZE_APIC_ACCESSES << 32) | (VM_EXEC_S_PROC_BASED_VIRTUAL_INTERRUPT_DELIVERY << 32));

    // TPR threshold value
    fake_vmread_return[4] = 0x07;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(vmcs.check_control_tpr_shadow_and_virtual_apic(), bfn::invalid_address_error);
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_tpr_shadow_and_virtual_apic_fail_enabled_unaligned()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;

    // tpr shadow enabled
    fake_vmread_return[0] = (VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS | VM_EXEC_P_PROC_BASED_USE_TPR_SHADOW);
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    // valid phys addr
    fake_vmread_return[1] = 0xFFFCAAAA0024;

    // secondary controls supported and enabled
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((VM_EXEC_P_PROC_BASED_USE_TPR_SHADOW << 32) | (VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_PROCBASED_CTLS2_MSR).Return((VM_EXEC_S_PROC_BASED_VIRTUALIZE_APIC_ACCESSES << 32) | (VM_EXEC_S_PROC_BASED_VIRTUAL_INTERRUPT_DELIVERY << 32));

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(vmcs.check_control_tpr_shadow_and_virtual_apic(), bfn::invalid_alignment_error);
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_tpr_shadow_and_virtual_apic_fail_enabled_bad_physaddr()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;

    // tpr shadow enabled
    fake_vmread_return[0] = (VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS | VM_EXEC_P_PROC_BASED_USE_TPR_SHADOW);
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    // bad phys addr
    fake_vmread_return[1] = 0xFFFC0000AAAA0000;

    // secondary controls supported and enabled
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((VM_EXEC_P_PROC_BASED_USE_TPR_SHADOW << 32) | (VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_PROCBASED_CTLS2_MSR).Return((VM_EXEC_S_PROC_BASED_VIRTUALIZE_APIC_ACCESSES << 32) | (VM_EXEC_S_PROC_BASED_VIRTUAL_INTERRUPT_DELIVERY << 32));

    // physaddr width
    mocks.OnCall(in.get(), intrinsics_intel_x64::cpuid_eax).Return(48);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(vmcs.check_control_tpr_shadow_and_virtual_apic(), bfn::invalid_address_error);
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_tpr_shadow_and_virtual_apic_fail_enabled_virtual_interrupt_delivery_unsupported()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;

    // tpr shadow enabled
    fake_vmread_return[0] = (VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS | VM_EXEC_P_PROC_BASED_USE_TPR_SHADOW);
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    // valid phys addr
    fake_vmread_return[1] = 0xFFFCAAAA0000;
    mocks.OnCall(in.get(), intrinsics_intel_x64::cpuid_eax).Return(48);

    // secondary controls supported and enabled
    fake_vmread_return[2] = fake_vmread_return[0];
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((VM_EXEC_P_PROC_BASED_USE_TPR_SHADOW << 32) | (VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_PROCBASED_CTLS2_MSR).Return((VM_EXEC_S_PROC_BASED_VIRTUALIZE_APIC_ACCESSES << 32));
    fake_vmread_return[3] = (VM_EXEC_S_PROC_BASED_VIRTUAL_INTERRUPT_DELIVERY | VM_EXEC_S_PROC_BASED_VIRTUALIZE_APIC_ACCESSES);
    fake_vmread_return[5] = fake_vmread_return[0];
    fake_vmread_return[6] = fake_vmread_return[3];

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(vmcs.check_control_tpr_shadow_and_virtual_apic(), bfn::hardware_unsupported_error);
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_tpr_shadow_and_virtual_apic_fail_enabled_invalid_tpr_threshold()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;

    // tpr shadow enabled
    fake_vmread_return[0] = (VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS | VM_EXEC_P_PROC_BASED_USE_TPR_SHADOW);
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    // valid phys addr
    fake_vmread_return[1] = 0xFFFCAAAA0000;
    mocks.OnCall(in.get(), intrinsics_intel_x64::cpuid_eax).Return(48);

    // secondary controls supported and enabled
    fake_vmread_return[2] = fake_vmread_return[0];
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((VM_EXEC_P_PROC_BASED_USE_TPR_SHADOW << 32) | (VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_PROCBASED_CTLS2_MSR).Return((VM_EXEC_S_PROC_BASED_VIRTUALIZE_APIC_ACCESSES << 32) | (VM_EXEC_S_PROC_BASED_VIRTUAL_INTERRUPT_DELIVERY << 32));
    fake_vmread_return[3] = (VM_EXEC_S_PROC_BASED_VIRTUAL_INTERRUPT_DELIVERY | VM_EXEC_S_PROC_BASED_VIRTUALIZE_APIC_ACCESSES);
    fake_vmread_return[5] = fake_vmread_return[0];
    fake_vmread_return[6] = fake_vmread_return[3];

    // TPR threshold value
    fake_vmread_return[4] = 0xFF;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(vmcs.check_control_tpr_shadow_and_virtual_apic(), bfn::vmcs_invalid_field_error);
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_tpr_shadow_and_virtual_apic_fail_enabled_virtual_apic_unsupported()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;

    // tpr shadow enabled
    fake_vmread_return[0] = (VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS | VM_EXEC_P_PROC_BASED_USE_TPR_SHADOW);
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    // valid phys addr
    fake_vmread_return[1] = 0xFFFCAAAA0000;
    mocks.OnCall(in.get(), intrinsics_intel_x64::cpuid_eax).Return(48);

    // secondary controls supported and enabled
    fake_vmread_return[2] = fake_vmread_return[0];
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((VM_EXEC_P_PROC_BASED_USE_TPR_SHADOW << 32) | (VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_PROCBASED_CTLS2_MSR).Return((VM_EXEC_S_PROC_BASED_VIRTUAL_INTERRUPT_DELIVERY << 32));
    fake_vmread_return[3] = (VM_EXEC_S_PROC_BASED_VIRTUAL_INTERRUPT_DELIVERY | VM_EXEC_S_PROC_BASED_VIRTUALIZE_APIC_ACCESSES);
    fake_vmread_return[5] = fake_vmread_return[0];
    fake_vmread_return[6] = fake_vmread_return[3];

    // TPR threshold value
    fake_vmread_return[4] = 0x07;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(vmcs.check_control_tpr_shadow_and_virtual_apic(), bfn::hardware_unsupported_error);
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_tpr_shadow_and_virtual_apic_fail_enabled_invalid_apic_vaddr()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;

    // tpr shadow enabled
    fake_vmread_return[0] = (VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS | VM_EXEC_P_PROC_BASED_USE_TPR_SHADOW);
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    // valid phys addr
    fake_vmread_return[1] = 0xFFFCAAAA0000;
    mocks.OnCall(in.get(), intrinsics_intel_x64::cpuid_eax).Return(48);

    // secondary controls supported and enabled
    fake_vmread_return[2] = fake_vmread_return[0];
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((VM_EXEC_P_PROC_BASED_USE_TPR_SHADOW << 32) | (VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_PROCBASED_CTLS2_MSR).Return((VM_EXEC_S_PROC_BASED_VIRTUALIZE_APIC_ACCESSES << 32) | (VM_EXEC_S_PROC_BASED_VIRTUAL_INTERRUPT_DELIVERY << 32));
    fake_vmread_return[3] = (VM_EXEC_S_PROC_BASED_VIRTUAL_INTERRUPT_DELIVERY | VM_EXEC_S_PROC_BASED_VIRTUALIZE_APIC_ACCESSES);
    fake_vmread_return[5] = fake_vmread_return[0];
    fake_vmread_return[6] = fake_vmread_return[3];

    // TPR threshold value
    fake_vmread_return[4] = 0x07;

    // phys addr lookup
    mocks.OnCallFunc(memory_manager::instance).Do(fake_memory_manager);
    mocks.OnCall(mm, memory_manager::phys_to_virt).Return(0);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(vmcs.check_control_tpr_shadow_and_virtual_apic(), bfn::invalid_address_error);
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_tpr_shadow_and_virtual_apic_fail_enabled_vtpr_range_check()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;

    // tpr shadow enabled
    fake_vmread_return[0] = (VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS | VM_EXEC_P_PROC_BASED_USE_TPR_SHADOW);
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    // valid phys addr
    fake_vmread_return[1] = 0xFFFCAAAA0000;
    mocks.OnCall(in.get(), intrinsics_intel_x64::cpuid_eax).Return(48);

    // secondary controls supported and enabled
    fake_vmread_return[2] = fake_vmread_return[0];
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((VM_EXEC_P_PROC_BASED_USE_TPR_SHADOW << 32) | (VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_PROCBASED_CTLS2_MSR).Return((VM_EXEC_S_PROC_BASED_VIRTUALIZE_APIC_ACCESSES << 32) | (VM_EXEC_S_PROC_BASED_VIRTUAL_INTERRUPT_DELIVERY << 32));
    fake_vmread_return[3] = (VM_EXEC_S_PROC_BASED_VIRTUAL_INTERRUPT_DELIVERY | VM_EXEC_S_PROC_BASED_VIRTUALIZE_APIC_ACCESSES);
    fake_vmread_return[5] = fake_vmread_return[0];
    fake_vmread_return[6] = fake_vmread_return[3];

    // TPR threshold value
    fake_vmread_return[4] = 0x07;

    // phys addr lookup
    mocks.OnCallFunc(memory_manager::instance).Do(fake_memory_manager);
    void *vapic_page = malloc(4096);
    mocks.OnCall(mm, memory_manager::phys_to_virt).Return(vapic_page);
    uint8_t *ptr2 = (uint8_t *)((uint8_t *)vapic_page + 0x80);
    ptr2[0] = 0x40;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(vmcs.check_control_tpr_shadow_and_virtual_apic(), bfn::vmcs_invalid_field_error);
    });

    fake_vmread_index = 0;
    free(vapic_page);
    mm = NULL;
}

void
vmcs_ut::test_check_control_tpr_shadow_and_virtual_apic_success_disabled()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;

    // tpr shadow enabled
    fake_vmread_return[0] = (VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS | VM_EXEC_P_PROC_BASED_USE_TPR_SHADOW);
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS << 32));

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(vmcs.check_control_tpr_shadow_and_virtual_apic());
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_tpr_shadow_and_virtual_apic_fail_disabled_x2apic_enabled()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;

    // tpr shadow enabled
    fake_vmread_return[0] = (VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS | VM_EXEC_P_PROC_BASED_USE_TPR_SHADOW);
    fake_vmread_return[1] = (VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS | VM_EXEC_P_PROC_BASED_USE_TPR_SHADOW);
    fake_vmread_return[2] = VM_EXEC_S_PROC_BASED_VIRTUALIZE_X2APIC_MODE;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_PROCBASED_CTLS2_MSR).Return((VM_EXEC_S_PROC_BASED_VIRTUALIZE_X2APIC_MODE << 32));

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(vmcs.check_control_tpr_shadow_and_virtual_apic(), bfn::hardware_unsupported_error);
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_tpr_shadow_and_virtual_apic_fail_disabled_apic_reg_virt_enabled()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;

    // tpr shadow enabled
    fake_vmread_return[0] = (VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS | VM_EXEC_P_PROC_BASED_USE_TPR_SHADOW);
    fake_vmread_return[1] = (VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS | VM_EXEC_P_PROC_BASED_USE_TPR_SHADOW);
    fake_vmread_return[2] = ~VM_EXEC_S_PROC_BASED_VIRTUALIZE_X2APIC_MODE;
    fake_vmread_return[3] = (VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS | VM_EXEC_P_PROC_BASED_USE_TPR_SHADOW);
    fake_vmread_return[4] = VM_EXEC_S_PROC_BASED_APIC_REGISTER_VIRTUALIZATION;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_PROCBASED_CTLS2_MSR).Return((VM_EXEC_S_PROC_BASED_APIC_REGISTER_VIRTUALIZATION << 32) | (VM_EXEC_S_PROC_BASED_VIRTUALIZE_X2APIC_MODE << 32));

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(vmcs.check_control_tpr_shadow_and_virtual_apic(), bfn::hardware_unsupported_error);
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_tpr_shadow_and_virtual_apic_fail_disabled_virtual_interrupt_delivery_enabled()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;

    // tpr shadow enabled
    fake_vmread_return[0] = (VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS | VM_EXEC_P_PROC_BASED_USE_TPR_SHADOW);
    fake_vmread_return[1] = (VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS | VM_EXEC_P_PROC_BASED_USE_TPR_SHADOW);
    fake_vmread_return[2] = ~VM_EXEC_S_PROC_BASED_VIRTUALIZE_X2APIC_MODE;
    fake_vmread_return[3] = (VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS | VM_EXEC_P_PROC_BASED_USE_TPR_SHADOW);
    fake_vmread_return[4] = ~VM_EXEC_S_PROC_BASED_APIC_REGISTER_VIRTUALIZATION;
    fake_vmread_return[5] = (VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS | VM_EXEC_P_PROC_BASED_USE_TPR_SHADOW);
    fake_vmread_return[6] = VM_EXEC_S_PROC_BASED_VIRTUAL_INTERRUPT_DELIVERY;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_PROCBASED_CTLS2_MSR).Return((VM_EXEC_S_PROC_BASED_VIRTUAL_INTERRUPT_DELIVERY << 32) | (VM_EXEC_S_PROC_BASED_APIC_REGISTER_VIRTUALIZATION << 32) | (VM_EXEC_S_PROC_BASED_VIRTUALIZE_X2APIC_MODE << 32));

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(vmcs.check_control_tpr_shadow_and_virtual_apic(), bfn::hardware_unsupported_error);
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_nmi_exiting_and_virtual_nmi_success()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;

    fake_vmread_return[0] = 0;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PINBASED_CTLS_MSR).Return((VM_EXEC_PIN_BASED_NMI_EXITING << 32));

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(vmcs.check_control_nmi_exiting_and_virtual_nmi());
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_nmi_exiting_and_virtual_nmi_fail_vnmis_and_nmi_exiting_enabled()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;

    fake_vmread_return[0] = ~VM_EXEC_PIN_BASED_NMI_EXITING;
    fake_vmread_return[1] = VM_EXEC_PIN_BASED_VIRTUAL_NMIS;

    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PINBASED_CTLS_MSR).Return((VM_EXEC_PIN_BASED_NMI_EXITING << 32) | (VM_EXEC_PIN_BASED_VIRTUAL_NMIS << 32));

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(vmcs.check_control_nmi_exiting_and_virtual_nmi(), bfn::vmcs_invalid_field_error);
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_virtual_nmi_and_nmi_window_success_one()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;

    fake_vmread_return[0] = VM_EXEC_PIN_BASED_VIRTUAL_NMIS;
    fake_vmread_return[1] = VM_EXEC_P_PROC_BASED_NMI_WINDOW_EXITING;

    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PINBASED_CTLS_MSR).Return((VM_EXEC_PIN_BASED_VIRTUAL_NMIS << 32) & ~(VM_EXEC_P_PROC_BASED_NMI_WINDOW_EXITING << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((VM_EXEC_P_PROC_BASED_NMI_WINDOW_EXITING << 32));

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(vmcs.check_control_virtual_nmi_and_nmi_window());
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_virtual_nmi_and_nmi_window_success_two()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;

    fake_vmread_return[0] = ~VM_EXEC_PIN_BASED_VIRTUAL_NMIS;
    fake_vmread_return[1] = VM_EXEC_P_PROC_BASED_NMI_WINDOW_EXITING;

    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PINBASED_CTLS_MSR).Return((VM_EXEC_PIN_BASED_VIRTUAL_NMIS << 32) & ~(VM_EXEC_P_PROC_BASED_NMI_WINDOW_EXITING << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return(~(VM_EXEC_P_PROC_BASED_NMI_WINDOW_EXITING << 32));

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(vmcs.check_control_virtual_nmi_and_nmi_window());
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_virtual_nmi_and_nmi_window_success_three()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;

    fake_vmread_return[0] = ~VM_EXEC_PIN_BASED_VIRTUAL_NMIS;
    fake_vmread_return[1] = VM_EXEC_P_PROC_BASED_NMI_WINDOW_EXITING;

    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PINBASED_CTLS_MSR).Return((VM_EXEC_PIN_BASED_VIRTUAL_NMIS << 32) & ~(VM_EXEC_P_PROC_BASED_NMI_WINDOW_EXITING << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return(~(VM_EXEC_P_PROC_BASED_NMI_WINDOW_EXITING << 32));

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(vmcs.check_control_virtual_nmi_and_nmi_window());
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_virtual_nmi_and_nmi_window_fail_nmi_window_exiting_enabled_vnmis_disabled()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;

    fake_vmread_return[0] = ~VM_EXEC_PIN_BASED_VIRTUAL_NMIS;
    fake_vmread_return[1] = VM_EXEC_P_PROC_BASED_NMI_WINDOW_EXITING;

    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PINBASED_CTLS_MSR).Return((VM_EXEC_PIN_BASED_VIRTUAL_NMIS << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((VM_EXEC_P_PROC_BASED_NMI_WINDOW_EXITING << 32));

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(vmcs.check_control_virtual_nmi_and_nmi_window(), bfn::vmcs_invalid_field_error);
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_virtual_apic_address_bits_success_enabled()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;
    fake_vmread_return[0] = VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS;
    fake_vmread_return[1] = VM_EXEC_S_PROC_BASED_VIRTUALIZE_APIC_ACCESSES;

    mocks.OnCall(in.get(), intrinsics_intel_x64::cpuid_eax).Return(48);
    fake_vmread_return[2] = 0xFFFCAAAA0000;

    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_PROCBASED_CTLS2_MSR).Return((VM_EXEC_S_PROC_BASED_VIRTUALIZE_APIC_ACCESSES << 32));

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(vmcs.check_control_virtual_apic_address_bits());
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_virtual_apic_address_bits_success_disabled_one()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;
    fake_vmread_return[0] = VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS;
    fake_vmread_return[1] = ~VM_EXEC_S_PROC_BASED_VIRTUALIZE_APIC_ACCESSES;

    mocks.OnCall(in.get(), intrinsics_intel_x64::cpuid_eax).Return(48);
    fake_vmread_return[2] = 0xFFFCAAAA0000;

    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_PROCBASED_CTLS2_MSR).Return((VM_EXEC_S_PROC_BASED_VIRTUALIZE_APIC_ACCESSES << 32));

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(vmcs.check_control_virtual_apic_address_bits());
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_virtual_apic_address_bits_success_disabled_two()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;
    fake_vmread_return[0] = ~VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS;
    fake_vmread_return[1] = VM_EXEC_S_PROC_BASED_VIRTUALIZE_APIC_ACCESSES;

    mocks.OnCall(in.get(), intrinsics_intel_x64::cpuid_eax).Return(48);
    fake_vmread_return[2] = 0xFFFCAAAA0000;

    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_PROCBASED_CTLS2_MSR).Return((VM_EXEC_S_PROC_BASED_VIRTUALIZE_APIC_ACCESSES << 32));

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(vmcs.check_control_virtual_apic_address_bits());
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_virtual_apic_address_bits_fail_null_physaddr()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;
    fake_vmread_return[0] = VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS;
    fake_vmread_return[1] = VM_EXEC_S_PROC_BASED_VIRTUALIZE_APIC_ACCESSES;

    mocks.OnCall(in.get(), intrinsics_intel_x64::cpuid_eax).Return(48);
    fake_vmread_return[2] = 0;

    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_PROCBASED_CTLS2_MSR).Return((VM_EXEC_S_PROC_BASED_VIRTUALIZE_APIC_ACCESSES << 32));

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(vmcs.check_control_virtual_apic_address_bits(), bfn::invalid_address_error);
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_virtual_apic_address_bits_fail_unaligned_physaddr()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;
    fake_vmread_return[0] = VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS;
    fake_vmread_return[1] = VM_EXEC_S_PROC_BASED_VIRTUALIZE_APIC_ACCESSES;

    mocks.OnCall(in.get(), intrinsics_intel_x64::cpuid_eax).Return(48);
    fake_vmread_return[2] = 0xDEADBEEF;

    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_PROCBASED_CTLS2_MSR).Return((VM_EXEC_S_PROC_BASED_VIRTUALIZE_APIC_ACCESSES << 32));

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(vmcs.check_control_virtual_apic_address_bits(), bfn::invalid_alignment_error);
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_virtual_apic_address_bits_fail_invalid_physaddr()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;
    fake_vmread_return[0] = VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS;
    fake_vmread_return[1] = VM_EXEC_S_PROC_BASED_VIRTUALIZE_APIC_ACCESSES;

    mocks.OnCall(in.get(), intrinsics_intel_x64::cpuid_eax).Return(48);
    fake_vmread_return[2] = 0xDEADBEEFDEAF1000;

    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_PROCBASED_CTLS2_MSR).Return((VM_EXEC_S_PROC_BASED_VIRTUALIZE_APIC_ACCESSES << 32));

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(vmcs.check_control_virtual_apic_address_bits(), bfn::invalid_address_error);
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_x2apic_mode_and_virtual_apic_access_success_one()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;
    fake_vmread_return[0] = VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS;
    fake_vmread_return[1] = ~VM_EXEC_S_PROC_BASED_VIRTUALIZE_X2APIC_MODE;

    fake_vmread_return[2] = VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS;
    fake_vmread_return[3] = ~VM_EXEC_S_PROC_BASED_VIRTUALIZE_APIC_ACCESSES;

    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_PROCBASED_CTLS2_MSR).Return((VM_EXEC_S_PROC_BASED_VIRTUALIZE_APIC_ACCESSES << 32) | (VM_EXEC_S_PROC_BASED_VIRTUALIZE_X2APIC_MODE << 32));

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(vmcs.check_control_x2apic_mode_and_virtual_apic_access());
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_x2apic_mode_and_virtual_apic_access_success_two()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;
    fake_vmread_return[0] = VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS;
    fake_vmread_return[1] = ~VM_EXEC_S_PROC_BASED_VIRTUALIZE_X2APIC_MODE;

    fake_vmread_return[2] = VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS;
    fake_vmread_return[3] = VM_EXEC_S_PROC_BASED_VIRTUALIZE_APIC_ACCESSES;

    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_PROCBASED_CTLS2_MSR).Return((VM_EXEC_S_PROC_BASED_VIRTUALIZE_APIC_ACCESSES << 32) | (VM_EXEC_S_PROC_BASED_VIRTUALIZE_X2APIC_MODE << 32));

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(vmcs.check_control_x2apic_mode_and_virtual_apic_access());
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_x2apic_mode_and_virtual_apic_access_success_three()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;
    fake_vmread_return[0] = VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS;
    fake_vmread_return[1] = VM_EXEC_S_PROC_BASED_VIRTUALIZE_X2APIC_MODE;

    fake_vmread_return[2] = VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS;
    fake_vmread_return[3] = ~VM_EXEC_S_PROC_BASED_VIRTUALIZE_APIC_ACCESSES;

    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_PROCBASED_CTLS2_MSR).Return((VM_EXEC_S_PROC_BASED_VIRTUALIZE_APIC_ACCESSES << 32) | (VM_EXEC_S_PROC_BASED_VIRTUALIZE_X2APIC_MODE << 32));

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(vmcs.check_control_x2apic_mode_and_virtual_apic_access());
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_x2apic_mode_and_virtual_apic_access_fail()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;
    fake_vmread_return[0] = VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS;
    fake_vmread_return[1] = VM_EXEC_S_PROC_BASED_VIRTUALIZE_X2APIC_MODE;

    fake_vmread_return[2] = VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS;
    fake_vmread_return[3] = VM_EXEC_S_PROC_BASED_VIRTUALIZE_APIC_ACCESSES;

    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_PROCBASED_CTLS2_MSR).Return((VM_EXEC_S_PROC_BASED_VIRTUALIZE_APIC_ACCESSES << 32) | (VM_EXEC_S_PROC_BASED_VIRTUALIZE_X2APIC_MODE << 32));

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(vmcs.check_control_x2apic_mode_and_virtual_apic_access(), bfn::vmcs_invalid_field_error);
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_virtual_interrupt_and_external_interrupt_success_one()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;
    fake_vmread_return[0] = VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS;
    fake_vmread_return[1] = VM_EXEC_S_PROC_BASED_VIRTUAL_INTERRUPT_DELIVERY;
    fake_vmread_return[2] = VM_EXEC_PIN_BASED_EXTERNAL_INTERRUPT_EXITING;

    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PINBASED_CTLS_MSR).Return((VM_EXEC_PIN_BASED_EXTERNAL_INTERRUPT_EXITING << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_PROCBASED_CTLS2_MSR).Return((VM_EXEC_S_PROC_BASED_VIRTUAL_INTERRUPT_DELIVERY << 32));

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(vmcs.check_control_virtual_interrupt_and_external_interrupt());
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_virtual_interrupt_and_external_interrupt_success_two()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;
    fake_vmread_return[0] = VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS;
    fake_vmread_return[1] = ~VM_EXEC_S_PROC_BASED_VIRTUAL_INTERRUPT_DELIVERY;
    fake_vmread_return[2] = VM_EXEC_PIN_BASED_EXTERNAL_INTERRUPT_EXITING;

    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PINBASED_CTLS_MSR).Return((VM_EXEC_PIN_BASED_EXTERNAL_INTERRUPT_EXITING << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_PROCBASED_CTLS2_MSR).Return((VM_EXEC_S_PROC_BASED_VIRTUAL_INTERRUPT_DELIVERY << 32));

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(vmcs.check_control_virtual_interrupt_and_external_interrupt());
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_virtual_interrupt_and_external_interrupt_success_three()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;
    fake_vmread_return[0] = VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS;
    fake_vmread_return[1] = ~VM_EXEC_S_PROC_BASED_VIRTUAL_INTERRUPT_DELIVERY;
    fake_vmread_return[2] = ~VM_EXEC_PIN_BASED_EXTERNAL_INTERRUPT_EXITING;

    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PINBASED_CTLS_MSR).Return((VM_EXEC_PIN_BASED_EXTERNAL_INTERRUPT_EXITING << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_PROCBASED_CTLS2_MSR).Return((VM_EXEC_S_PROC_BASED_VIRTUAL_INTERRUPT_DELIVERY << 32));

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(vmcs.check_control_virtual_interrupt_and_external_interrupt());
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_virtual_interrupt_and_external_interrupt_fail()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;
    fake_vmread_return[0] = VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS;
    fake_vmread_return[1] = VM_EXEC_S_PROC_BASED_VIRTUAL_INTERRUPT_DELIVERY;
    fake_vmread_return[2] = ~VM_EXEC_PIN_BASED_EXTERNAL_INTERRUPT_EXITING;

    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PINBASED_CTLS_MSR).Return((VM_EXEC_PIN_BASED_EXTERNAL_INTERRUPT_EXITING << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_PROCBASED_CTLS2_MSR).Return((VM_EXEC_S_PROC_BASED_VIRTUAL_INTERRUPT_DELIVERY << 32));

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(vmcs.check_control_virtual_interrupt_and_external_interrupt(), bfn::vmcs_invalid_field_error);
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_process_posted_interrupt_checks_success_disabled()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;
    fake_vmread_return[0] = ~VM_EXEC_PIN_BASED_PROCESS_POSTED_INTERRUPTS;

    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PINBASED_CTLS_MSR).Return((VM_EXEC_PIN_BASED_PROCESS_POSTED_INTERRUPTS << 32));

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(vmcs.check_control_process_posted_interrupt_checks());
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_process_posted_interrupt_checks_success_enabled()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    // posted_interrupts_enabled
    fake_vmread_return[0] = VM_EXEC_PIN_BASED_PROCESS_POSTED_INTERRUPTS;

    // virtual_interrupt_delivery
    fake_vmread_return[1] = VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS;
    fake_vmread_return[2] = VM_EXEC_S_PROC_BASED_VIRTUAL_INTERRUPT_DELIVERY;

    // ack_interrupt_on_exit
    fake_vmread_return[3] = VM_EXIT_CONTROL_ACKNOWLEDGE_INTERRUPT_ON_EXIT;
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_EXIT_CTLS_MSR).Return((VM_EXIT_CONTROL_ACKNOWLEDGE_INTERRUPT_ON_EXIT << 32));

    // posted_interrupt vector
    fake_vmread_return[4] = 0xFF;

    // posted_interrupt_descripter address
    mocks.OnCall(in.get(), intrinsics_intel_x64::cpuid_eax).Return(48);
    fake_vmread_return[5] = 0xFFFCAAAA00C0;

    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PINBASED_CTLS_MSR).Return((VM_EXEC_PIN_BASED_PROCESS_POSTED_INTERRUPTS << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_PROCBASED_CTLS2_MSR).Return((VM_EXEC_S_PROC_BASED_VIRTUAL_INTERRUPT_DELIVERY << 32));

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(vmcs.check_control_process_posted_interrupt_checks());
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_process_posted_interrupt_checks_fail_no_virtual_interrupt_delivery()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    // posted_interrupts_enabled
    fake_vmread_return[0] = VM_EXEC_PIN_BASED_PROCESS_POSTED_INTERRUPTS;

    // virtual_interrupt_delivery
    fake_vmread_return[1] = VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS;
    fake_vmread_return[2] = ~VM_EXEC_S_PROC_BASED_VIRTUAL_INTERRUPT_DELIVERY;

    // ack_interrupt_on_exit
    fake_vmread_return[3] = VM_EXIT_CONTROL_ACKNOWLEDGE_INTERRUPT_ON_EXIT;
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_EXIT_CTLS_MSR).Return((VM_EXIT_CONTROL_ACKNOWLEDGE_INTERRUPT_ON_EXIT << 32));

    // posted_interrupt vector
    fake_vmread_return[4] = 0xFF;

    // posted_interrupt_descripter address
    mocks.OnCall(in.get(), intrinsics_intel_x64::cpuid_eax).Return(48);
    fake_vmread_return[5] = 0xFFFCAAAA00C0;

    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PINBASED_CTLS_MSR).Return((VM_EXEC_PIN_BASED_PROCESS_POSTED_INTERRUPTS << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_PROCBASED_CTLS2_MSR).Return((VM_EXEC_S_PROC_BASED_VIRTUAL_INTERRUPT_DELIVERY << 32));

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(vmcs.check_control_process_posted_interrupt_checks(), bfn::vmcs_invalid_field_error);
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_process_posted_interrupt_checks_fail_no_ack_interrupt_on_exit()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    // posted_interrupts_enabled
    fake_vmread_return[0] = VM_EXEC_PIN_BASED_PROCESS_POSTED_INTERRUPTS;

    // virtual_interrupt_delivery
    fake_vmread_return[1] = VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS;
    fake_vmread_return[2] = VM_EXEC_S_PROC_BASED_VIRTUAL_INTERRUPT_DELIVERY;

    // ack_interrupt_on_exit
    fake_vmread_return[3] = ~VM_EXIT_CONTROL_ACKNOWLEDGE_INTERRUPT_ON_EXIT;
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_EXIT_CTLS_MSR).Return((VM_EXIT_CONTROL_ACKNOWLEDGE_INTERRUPT_ON_EXIT << 32));

    // posted_interrupt vector
    fake_vmread_return[4] = 0xFF;

    // posted_interrupt_descripter address
    mocks.OnCall(in.get(), intrinsics_intel_x64::cpuid_eax).Return(48);
    fake_vmread_return[5] = 0xFFFCAAAA00C0;

    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PINBASED_CTLS_MSR).Return((VM_EXEC_PIN_BASED_PROCESS_POSTED_INTERRUPTS << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_PROCBASED_CTLS2_MSR).Return((VM_EXEC_S_PROC_BASED_VIRTUAL_INTERRUPT_DELIVERY << 32));

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(vmcs.check_control_process_posted_interrupt_checks(), bfn::vmcs_invalid_field_error);
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_process_posted_interrupt_checks_fail_invalid_vector()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    // posted_interrupts_enabled
    fake_vmread_return[0] = VM_EXEC_PIN_BASED_PROCESS_POSTED_INTERRUPTS;

    // virtual_interrupt_delivery
    fake_vmread_return[1] = VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS;
    fake_vmread_return[2] = VM_EXEC_S_PROC_BASED_VIRTUAL_INTERRUPT_DELIVERY;

    // ack_interrupt_on_exit
    fake_vmread_return[3] = VM_EXIT_CONTROL_ACKNOWLEDGE_INTERRUPT_ON_EXIT;
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_EXIT_CTLS_MSR).Return((VM_EXIT_CONTROL_ACKNOWLEDGE_INTERRUPT_ON_EXIT << 32));

    // posted_interrupt vector
    fake_vmread_return[4] = 0x1FF;

    // posted_interrupt_descripter address
    mocks.OnCall(in.get(), intrinsics_intel_x64::cpuid_eax).Return(48);
    fake_vmread_return[5] = 0xFFFCAAAA00C0;

    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PINBASED_CTLS_MSR).Return((VM_EXEC_PIN_BASED_PROCESS_POSTED_INTERRUPTS << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_PROCBASED_CTLS2_MSR).Return((VM_EXEC_S_PROC_BASED_VIRTUAL_INTERRUPT_DELIVERY << 32));

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(vmcs.check_control_process_posted_interrupt_checks(), bfn::vmcs_invalid_field_error);
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_process_posted_interrupt_checks_fail_invalid_alignment()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    // posted_interrupts_enabled
    fake_vmread_return[0] = VM_EXEC_PIN_BASED_PROCESS_POSTED_INTERRUPTS;

    // virtual_interrupt_delivery
    fake_vmread_return[1] = VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS;
    fake_vmread_return[2] = VM_EXEC_S_PROC_BASED_VIRTUAL_INTERRUPT_DELIVERY;

    // ack_interrupt_on_exit
    fake_vmread_return[3] = VM_EXIT_CONTROL_ACKNOWLEDGE_INTERRUPT_ON_EXIT;
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_EXIT_CTLS_MSR).Return((VM_EXIT_CONTROL_ACKNOWLEDGE_INTERRUPT_ON_EXIT << 32));

    // posted_interrupt vector
    fake_vmread_return[4] = 0xFF;

    // posted_interrupt_descripter address
    mocks.OnCall(in.get(), intrinsics_intel_x64::cpuid_eax).Return(48);
    fake_vmread_return[5] = 0xFFFCAAAA00CF;

    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PINBASED_CTLS_MSR).Return((VM_EXEC_PIN_BASED_PROCESS_POSTED_INTERRUPTS << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_PROCBASED_CTLS2_MSR).Return((VM_EXEC_S_PROC_BASED_VIRTUAL_INTERRUPT_DELIVERY << 32));

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(vmcs.check_control_process_posted_interrupt_checks(), bfn::vmcs_invalid_field_error);
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_process_posted_interrupt_checks_fail_invalid_physaddr()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    // posted_interrupts_enabled
    fake_vmread_return[0] = VM_EXEC_PIN_BASED_PROCESS_POSTED_INTERRUPTS;

    // virtual_interrupt_delivery
    fake_vmread_return[1] = VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS;
    fake_vmread_return[2] = VM_EXEC_S_PROC_BASED_VIRTUAL_INTERRUPT_DELIVERY;

    // ack_interrupt_on_exit
    fake_vmread_return[3] = VM_EXIT_CONTROL_ACKNOWLEDGE_INTERRUPT_ON_EXIT;
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_EXIT_CTLS_MSR).Return((VM_EXIT_CONTROL_ACKNOWLEDGE_INTERRUPT_ON_EXIT << 32));

    // posted_interrupt vector
    fake_vmread_return[4] = 0xFF;

    // posted_interrupt_descripter address
    mocks.OnCall(in.get(), intrinsics_intel_x64::cpuid_eax).Return(48);
    fake_vmread_return[5] = 0xDEADFFFCAAAA00C0;

    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PINBASED_CTLS_MSR).Return((VM_EXEC_PIN_BASED_PROCESS_POSTED_INTERRUPTS << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_PROCBASED_CTLS2_MSR).Return((VM_EXEC_S_PROC_BASED_VIRTUAL_INTERRUPT_DELIVERY << 32));

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(vmcs.check_control_process_posted_interrupt_checks(), bfn::invalid_address_error);
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_vpid_checks_success_early()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    fake_vmread_return[0] = VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS;
    fake_vmread_return[1] = ~VM_EXEC_S_PROC_BASED_ENABLE_VPID;

    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_PROCBASED_CTLS2_MSR).Return((VM_EXEC_S_PROC_BASED_ENABLE_VPID << 32));

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(vmcs.check_control_vpid_checks());
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_vpid_checks_success()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    fake_vmread_return[0] = VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS;
    fake_vmread_return[1] = VM_EXEC_S_PROC_BASED_ENABLE_VPID;

    // vpid != 0
    fake_vmread_return[2] = 3;
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_PROCBASED_CTLS2_MSR).Return((VM_EXEC_S_PROC_BASED_ENABLE_VPID << 32));

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(vmcs.check_control_vpid_checks());
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_vpid_checks_fail_invalid_vpid()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    fake_vmread_return[0] = VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS;
    fake_vmread_return[1] = VM_EXEC_S_PROC_BASED_ENABLE_VPID;

    // vpid != 0
    fake_vmread_return[2] = 0;
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_PROCBASED_CTLS2_MSR).Return((VM_EXEC_S_PROC_BASED_ENABLE_VPID << 32));

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(vmcs.check_control_vpid_checks(), bfn::vmcs_invalid_field_error);
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_enable_ept_checks_success_early()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    fake_vmread_return[0] = VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS;
    fake_vmread_return[1] = ~VM_EXEC_S_PROC_BASED_ENABLE_EPT;

    // vpid != 0
    fake_vmread_return[2] = 0;
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_PROCBASED_CTLS2_MSR).Return((VM_EXEC_S_PROC_BASED_ENABLE_EPT << 32));

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(vmcs.check_control_enable_ept_checks());
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_enable_ept_checks_success()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    fake_vmread_return[0] = VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS;
    fake_vmread_return[1] = VM_EXEC_S_PROC_BASED_ENABLE_EPT;

    fake_vmread_return[2] = (EPTP_MEMORY_TYPE & 6) | ((3) << 3) | (EPTP_ACCESSED_DIRTY_FLAGS_ENABLED);

    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_PROCBASED_CTLS2_MSR).Return((VM_EXEC_S_PROC_BASED_ENABLE_EPT << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_EPT_VPID_CAP_MSR).Return(IA32_VMX_EPT_VPID_CAP_UC | IA32_VMX_EPT_VPID_CAP_WB | IA32_VMX_EPT_VPID_CAP_AD);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(vmcs.check_control_enable_ept_checks());
    });

    fake_vmread_index = 0;
    mm = NULL;
}


void
vmcs_ut::test_check_control_enable_ept_checks_fail_invalid_uncache()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    fake_vmread_return[0] = VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS;
    fake_vmread_return[1] = VM_EXEC_S_PROC_BASED_ENABLE_EPT;

    fake_vmread_return[2] = (EPTP_MEMORY_TYPE & 0) | ((3) << 3) | (EPTP_ACCESSED_DIRTY_FLAGS_ENABLED);

    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_PROCBASED_CTLS2_MSR).Return((VM_EXEC_S_PROC_BASED_ENABLE_EPT << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_EPT_VPID_CAP_MSR).Return(IA32_VMX_EPT_VPID_CAP_WB | IA32_VMX_EPT_VPID_CAP_AD);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(vmcs.check_control_enable_ept_checks(), bfn::vmcs_invalid_field_error);
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_enable_ept_checks_fail_invalid_writeback()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    fake_vmread_return[0] = VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS;
    fake_vmread_return[1] = VM_EXEC_S_PROC_BASED_ENABLE_EPT;

    fake_vmread_return[2] = (EPTP_MEMORY_TYPE & 6) | ((3) << 3) | (EPTP_ACCESSED_DIRTY_FLAGS_ENABLED);

    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_PROCBASED_CTLS2_MSR).Return((VM_EXEC_S_PROC_BASED_ENABLE_EPT << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_EPT_VPID_CAP_MSR).Return(IA32_VMX_EPT_VPID_CAP_UC | IA32_VMX_EPT_VPID_CAP_AD);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(vmcs.check_control_enable_ept_checks(), bfn::vmcs_invalid_field_error);
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_enable_ept_checks_fail_invalid_memtype()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    fake_vmread_return[0] = VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS;
    fake_vmread_return[1] = VM_EXEC_S_PROC_BASED_ENABLE_EPT;

    fake_vmread_return[2] = (EPTP_MEMORY_TYPE & 4) | ((3) << 3) | (EPTP_ACCESSED_DIRTY_FLAGS_ENABLED);

    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_PROCBASED_CTLS2_MSR).Return((VM_EXEC_S_PROC_BASED_ENABLE_EPT << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_EPT_VPID_CAP_MSR).Return(IA32_VMX_EPT_VPID_CAP_UC | IA32_VMX_EPT_VPID_CAP_WB | IA32_VMX_EPT_VPID_CAP_AD);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(vmcs.check_control_enable_ept_checks(), bfn::vmcs_invalid_field_error);
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_enable_ept_checks_fail_invalid_page_walk_length()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    fake_vmread_return[0] = VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS;
    fake_vmread_return[1] = VM_EXEC_S_PROC_BASED_ENABLE_EPT;

    fake_vmread_return[2] = (EPTP_MEMORY_TYPE & 6) | ((4) << 3) | (EPTP_ACCESSED_DIRTY_FLAGS_ENABLED);

    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_PROCBASED_CTLS2_MSR).Return((VM_EXEC_S_PROC_BASED_ENABLE_EPT << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_EPT_VPID_CAP_MSR).Return(IA32_VMX_EPT_VPID_CAP_UC | IA32_VMX_EPT_VPID_CAP_WB | IA32_VMX_EPT_VPID_CAP_AD);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(vmcs.check_control_enable_ept_checks(), bfn::vmcs_invalid_field_error);
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_enable_ept_checks_fail_no_dirty_support()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    fake_vmread_return[0] = VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS;
    fake_vmread_return[1] = VM_EXEC_S_PROC_BASED_ENABLE_EPT;

    fake_vmread_return[2] = (EPTP_MEMORY_TYPE & 6) | ((3) << 3) | (EPTP_ACCESSED_DIRTY_FLAGS_ENABLED);

    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_PROCBASED_CTLS2_MSR).Return((VM_EXEC_S_PROC_BASED_ENABLE_EPT << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_EPT_VPID_CAP_MSR).Return(IA32_VMX_EPT_VPID_CAP_UC | IA32_VMX_EPT_VPID_CAP_WB);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(vmcs.check_control_enable_ept_checks(), bfn::vmcs_invalid_field_error);
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_enable_ept_checks_fail_invalid_eptp_one()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    fake_vmread_return[0] = VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS;
    fake_vmread_return[1] = VM_EXEC_S_PROC_BASED_ENABLE_EPT;

    fake_vmread_return[2] = (0xFFFF000000000000 | (EPTP_MEMORY_TYPE & 6) | ((3) << 3) | (EPTP_ACCESSED_DIRTY_FLAGS_ENABLED));

    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_PROCBASED_CTLS2_MSR).Return((VM_EXEC_S_PROC_BASED_ENABLE_EPT << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_EPT_VPID_CAP_MSR).Return(IA32_VMX_EPT_VPID_CAP_UC | IA32_VMX_EPT_VPID_CAP_WB | IA32_VMX_EPT_VPID_CAP_AD);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(vmcs.check_control_enable_ept_checks(), bfn::vmcs_invalid_field_error);
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_enable_ept_checks_fail_invalid_eptp_two()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    fake_vmread_return[0] = VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS;
    fake_vmread_return[1] = VM_EXEC_S_PROC_BASED_ENABLE_EPT;

    fake_vmread_return[2] = (0x0000000000000F80 | (EPTP_MEMORY_TYPE & 6) | ((3) << 3) | (EPTP_ACCESSED_DIRTY_FLAGS_ENABLED));

    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_PROCBASED_CTLS2_MSR).Return((VM_EXEC_S_PROC_BASED_ENABLE_EPT << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_EPT_VPID_CAP_MSR).Return(IA32_VMX_EPT_VPID_CAP_UC | IA32_VMX_EPT_VPID_CAP_WB | IA32_VMX_EPT_VPID_CAP_AD);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(vmcs.check_control_enable_ept_checks(), bfn::vmcs_invalid_field_error);
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_unrestricted_guests_success_early()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    fake_vmread_return[0] = VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS;
    fake_vmread_return[1] = ~VM_EXEC_S_PROC_BASED_UNRESTRICTED_GUEST;

    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_PROCBASED_CTLS2_MSR).Return((VM_EXEC_S_PROC_BASED_ENABLE_EPT << 32) | (VM_EXEC_S_PROC_BASED_UNRESTRICTED_GUEST << 32));

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(vmcs.check_control_unrestricted_guests());
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_unrestricted_guests_success()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    fake_vmread_return[0] = VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS;
    fake_vmread_return[1] = VM_EXEC_S_PROC_BASED_UNRESTRICTED_GUEST;
    fake_vmread_return[2] = VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS;
    fake_vmread_return[3] = VM_EXEC_S_PROC_BASED_ENABLE_EPT;

    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_PROCBASED_CTLS2_MSR).Return((VM_EXEC_S_PROC_BASED_ENABLE_EPT << 32) | (VM_EXEC_S_PROC_BASED_UNRESTRICTED_GUEST << 32));

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(vmcs.check_control_unrestricted_guests());
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_unrestricted_guests_fail_no_ept()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    fake_vmread_return[0] = VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS;
    fake_vmread_return[1] = VM_EXEC_S_PROC_BASED_UNRESTRICTED_GUEST;
    fake_vmread_return[2] = VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS;
    fake_vmread_return[3] = ~VM_EXEC_S_PROC_BASED_ENABLE_EPT;

    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_PROCBASED_CTLS2_MSR).Return((VM_EXEC_S_PROC_BASED_ENABLE_EPT << 32) | (VM_EXEC_S_PROC_BASED_UNRESTRICTED_GUEST << 32));

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(vmcs.check_control_unrestricted_guests(), bfn::vmcs_invalid_field_error);
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_enable_vm_functions_success_early()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    fake_vmread_return[0] = VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS;
    fake_vmread_return[1] = ~VM_EXEC_S_PROC_BASED_ENABLE_VM_FUNCTIONS;

    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_PROCBASED_CTLS2_MSR).Return((VM_EXEC_S_PROC_BASED_ENABLE_VM_FUNCTIONS << 32));

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(vmcs.check_control_enable_vm_functions());
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_enable_vm_functions_success()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    fake_vmread_return[0] = VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS;
    fake_vmread_return[1] = VM_EXEC_S_PROC_BASED_ENABLE_VM_FUNCTIONS;
    fake_vmread_return[2] = 0x5555AAAA5555AAAA | VM_FUNCTION_CONTROL_EPTP_SWITCHING;
    fake_vmread_return[3] = VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS;
    fake_vmread_return[4] = VM_EXEC_S_PROC_BASED_ENABLE_EPT;
    fake_vmread_return[5] = 0xFFFCAAAA0000;

    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_PROCBASED_CTLS2_MSR).Return((VM_EXEC_S_PROC_BASED_ENABLE_EPT << 32) | (VM_EXEC_S_PROC_BASED_ENABLE_VM_FUNCTIONS << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_VMFUNC_MSR).Return(0x5555AAAA5555AAAA | VM_FUNCTION_CONTROL_EPTP_SWITCHING);
    mocks.OnCall(in.get(), intrinsics_intel_x64::cpuid_eax).Return(48);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(vmcs.check_control_enable_vm_functions());
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_enable_vm_functions_fail_vm_func_ctrl_bit()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    fake_vmread_return[0] = VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS;
    fake_vmread_return[1] = VM_EXEC_S_PROC_BASED_ENABLE_VM_FUNCTIONS;
    fake_vmread_return[2] = 0xFFFFFFFFFFFFFFFF | VM_FUNCTION_CONTROL_EPTP_SWITCHING;

    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_PROCBASED_CTLS2_MSR).Return((VM_EXEC_S_PROC_BASED_ENABLE_EPT << 32) | (VM_EXEC_S_PROC_BASED_ENABLE_VM_FUNCTIONS << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_VMFUNC_MSR).Return(0x5555AAAA5555AAAA | VM_FUNCTION_CONTROL_EPTP_SWITCHING);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(vmcs.check_control_enable_vm_functions(), bfn::vmcs_invalid_field_error);
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_enable_vm_functions_success_no_eptp_switching()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    fake_vmread_return[0] = VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS;
    fake_vmread_return[1] = VM_EXEC_S_PROC_BASED_ENABLE_VM_FUNCTIONS;
    fake_vmread_return[2] = 0x5555AAAA5555AAAA & ~VM_FUNCTION_CONTROL_EPTP_SWITCHING;

    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_PROCBASED_CTLS2_MSR).Return((VM_EXEC_S_PROC_BASED_ENABLE_EPT << 32) | (VM_EXEC_S_PROC_BASED_ENABLE_VM_FUNCTIONS << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_VMFUNC_MSR).Return(0x5555AAAA5555AAAA | VM_FUNCTION_CONTROL_EPTP_SWITCHING);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        // This case just returns silently, may want to throw here
        EXPECT_NO_EXCEPTION(vmcs.check_control_enable_vm_functions());
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_enable_vm_functions_fail_no_ept_enabled()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    fake_vmread_return[0] = VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS;
    fake_vmread_return[1] = VM_EXEC_S_PROC_BASED_ENABLE_VM_FUNCTIONS;
    fake_vmread_return[2] = 0x5555AAAA5555AAAA | VM_FUNCTION_CONTROL_EPTP_SWITCHING;
    fake_vmread_return[3] = VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS;
    fake_vmread_return[4] = ~VM_EXEC_S_PROC_BASED_ENABLE_EPT;

    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_PROCBASED_CTLS2_MSR).Return((VM_EXEC_S_PROC_BASED_ENABLE_EPT << 32) | (VM_EXEC_S_PROC_BASED_ENABLE_VM_FUNCTIONS << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_VMFUNC_MSR).Return(0x5555AAAA5555AAAA | VM_FUNCTION_CONTROL_EPTP_SWITCHING);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(vmcs.check_control_enable_vm_functions(), bfn::vmcs_invalid_field_error);
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_enable_vm_functions_fail_invalid_alignment()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    fake_vmread_return[0] = VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS;
    fake_vmread_return[1] = VM_EXEC_S_PROC_BASED_ENABLE_VM_FUNCTIONS;
    fake_vmread_return[2] = 0x5555AAAA5555AAAA | VM_FUNCTION_CONTROL_EPTP_SWITCHING;
    fake_vmread_return[3] = VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS;
    fake_vmread_return[4] = VM_EXEC_S_PROC_BASED_ENABLE_EPT;
    fake_vmread_return[5] = 0xFFFCAAAA000F;

    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_PROCBASED_CTLS2_MSR).Return((VM_EXEC_S_PROC_BASED_ENABLE_EPT << 32) | (VM_EXEC_S_PROC_BASED_ENABLE_VM_FUNCTIONS << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_VMFUNC_MSR).Return(0x5555AAAA5555AAAA | VM_FUNCTION_CONTROL_EPTP_SWITCHING);
    mocks.OnCall(in.get(), intrinsics_intel_x64::cpuid_eax).Return(48);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(vmcs.check_control_enable_vm_functions(), bfn::vmcs_invalid_field_error);
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_enable_vm_functions_fail_invalid_physaddr()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    fake_vmread_return[0] = VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS;
    fake_vmread_return[1] = VM_EXEC_S_PROC_BASED_ENABLE_VM_FUNCTIONS;
    fake_vmread_return[2] = 0x5555AAAA5555AAAA | VM_FUNCTION_CONTROL_EPTP_SWITCHING;
    fake_vmread_return[3] = VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS;
    fake_vmread_return[4] = VM_EXEC_S_PROC_BASED_ENABLE_EPT;
    fake_vmread_return[5] = 0xDEADFFFCAAAA0000;

    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_PROCBASED_CTLS2_MSR).Return((VM_EXEC_S_PROC_BASED_ENABLE_EPT << 32) | (VM_EXEC_S_PROC_BASED_ENABLE_VM_FUNCTIONS << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_VMFUNC_MSR).Return(0x5555AAAA5555AAAA | VM_FUNCTION_CONTROL_EPTP_SWITCHING);
    mocks.OnCall(in.get(), intrinsics_intel_x64::cpuid_eax).Return(48);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(vmcs.check_control_enable_vm_functions(), bfn::invalid_address_error);
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_enable_vmcs_shadowing_success_early()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    fake_vmread_return[0] = VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS;
    fake_vmread_return[1] = ~VM_EXEC_S_PROC_BASED_VMCS_SHADOWING;

    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_PROCBASED_CTLS2_MSR).Return(VM_EXEC_S_PROC_BASED_VMCS_SHADOWING);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(vmcs.check_control_enable_vm_functions());
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_enable_vmcs_shadowing_success()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    fake_vmread_return[0] = VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS;
    fake_vmread_return[1] = VM_EXEC_S_PROC_BASED_VMCS_SHADOWING;

    // vmread bitmap address
    fake_vmread_return[2] = 0xFFFCAAAA0000;
    fake_vmread_return[3] = 0xFFFBAAAA0000;

    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_PROCBASED_CTLS2_MSR).Return((VM_EXEC_S_PROC_BASED_VMCS_SHADOWING << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::cpuid_eax).Return(48);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(vmcs.check_control_enable_vmcs_shadowing());
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_enable_vmcs_shadowing_fail_vmread_bitmap_unaligned()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    fake_vmread_return[0] = VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS;
    fake_vmread_return[1] = VM_EXEC_S_PROC_BASED_VMCS_SHADOWING;

    // vmread bitmap address
    fake_vmread_return[2] = 0xFFFCAAAA000F;

    // vmwrite bitmap address
    fake_vmread_return[3] = 0xFFFBAAAA0000;

    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_PROCBASED_CTLS2_MSR).Return((VM_EXEC_S_PROC_BASED_VMCS_SHADOWING << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::cpuid_eax).Return(48);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(vmcs.check_control_enable_vmcs_shadowing(), bfn::vmcs_invalid_field_error);
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_enable_vmcs_shadowing_fail_vmwrite_bitmap_unaligned()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    fake_vmread_return[0] = VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS;
    fake_vmread_return[1] = VM_EXEC_S_PROC_BASED_VMCS_SHADOWING;

    // vmread bitmap address
    fake_vmread_return[2] = 0xFFFCAAAA0000;

    // vmwrite bitmap address
    fake_vmread_return[3] = 0xFFFBAAAA000F;

    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_PROCBASED_CTLS2_MSR).Return((VM_EXEC_S_PROC_BASED_VMCS_SHADOWING << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::cpuid_eax).Return(48);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(vmcs.check_control_enable_vmcs_shadowing(), bfn::vmcs_invalid_field_error);
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_enable_vmcs_shadowing_fail_vmread_bitmap_invalid_physaddr()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    fake_vmread_return[0] = VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS;
    fake_vmread_return[1] = VM_EXEC_S_PROC_BASED_VMCS_SHADOWING;

    // vmread bitmap address
    fake_vmread_return[2] = 0xDEADFFFCAAAA0000;

    // vmwrite bitmap address
    fake_vmread_return[3] = 0xFFFBAAAA0000;

    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_PROCBASED_CTLS2_MSR).Return((VM_EXEC_S_PROC_BASED_VMCS_SHADOWING << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::cpuid_eax).Return(48);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(vmcs.check_control_enable_vmcs_shadowing(), bfn::invalid_address_error);
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_enable_vmcs_shadowing_fail_vmwrite_bitmap_invalid_physaddr()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    fake_vmread_return[0] = VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS;
    fake_vmread_return[1] = VM_EXEC_S_PROC_BASED_VMCS_SHADOWING;

    // vmread bitmap address
    fake_vmread_return[2] = 0xFFFCAAAA0000;

    // vmwrite bitmap address
    fake_vmread_return[3] = 0xDEADFFFBAAAA0000;

    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_PROCBASED_CTLS2_MSR).Return((VM_EXEC_S_PROC_BASED_VMCS_SHADOWING << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::cpuid_eax).Return(48);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(vmcs.check_control_enable_vmcs_shadowing(), bfn::invalid_address_error);
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_enable_ept_violation_checks_early_success()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    fake_vmread_return[0] = VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS;
    fake_vmread_return[1] = ~VM_EXEC_S_PROC_BASED_EPT_VIOLATION_VE;

    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_PROCBASED_CTLS2_MSR).Return((VM_EXEC_S_PROC_BASED_EPT_VIOLATION_VE << 32));

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(vmcs.check_control_enable_vmcs_shadowing());
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_enable_ept_violation_checks_success()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    fake_vmread_return[0] = VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS;
    fake_vmread_return[1] = VM_EXEC_S_PROC_BASED_EPT_VIOLATION_VE;

    // vmcs_virt_exception_info address
    fake_vmread_return[2] = 0xFFFCAAAA0000;

    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_PROCBASED_CTLS2_MSR).Return((VM_EXEC_S_PROC_BASED_EPT_VIOLATION_VE << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::cpuid_eax).Return(48);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(vmcs.check_control_enable_vmcs_shadowing());
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_enable_ept_violation_checks_fail_unaligned()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    fake_vmread_return[0] = VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS;
    fake_vmread_return[1] = VM_EXEC_S_PROC_BASED_EPT_VIOLATION_VE;

    // vmcs_virt_exception_info address
    fake_vmread_return[2] = 0xFFFCAAAA000F;

    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_PROCBASED_CTLS2_MSR).Return((VM_EXEC_S_PROC_BASED_EPT_VIOLATION_VE << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::cpuid_eax).Return(48);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(vmcs.check_control_enable_vmcs_shadowing());
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_enable_ept_violation_checks_fail_invalid_physaddr()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    fake_vmread_return[0] = VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS;
    fake_vmread_return[1] = VM_EXEC_S_PROC_BASED_EPT_VIOLATION_VE;

    // vmcs_virt_exception_info address
    fake_vmread_return[2] = 0xDEADFFFCAAAA0000;

    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_PROCBASED_CTLS2_MSR).Return((VM_EXEC_S_PROC_BASED_EPT_VIOLATION_VE << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::cpuid_eax).Return(48);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(vmcs.check_control_enable_vmcs_shadowing());
    });

    fake_vmread_index = 0;
    mm = NULL;
}


void
vmcs_ut::test_check_control_vm_exit_ctls_reserved_properly_set_success()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    // Breakage
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_EXIT_CTLS_MSR).Return((0x55555555aaaaAAAA));
    fake_vmread_return[0] = 0xAAAAaaaaAAAAaaaa;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(vmcs.check_control_vm_exit_ctls_reserved_properly_set());
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_vm_exit_ctls_reserved_properly_set_fail_lower()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    // Breakage
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_EXIT_CTLS_MSR).Return((0x55555555aaaaAAAA));
    fake_vmread_return[0] = 0x7777777755555555;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(vmcs.check_control_vm_exit_ctls_reserved_properly_set(), bfn::vmcs_invalid_ctls_error);
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_vm_exit_ctls_reserved_properly_set_fail_upper()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    // Breakage
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_EXIT_CTLS_MSR).Return((0x55555555aaaaAAAA));
    fake_vmread_return[0] = 0x77777777AAAAaaaa;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(vmcs.check_control_vm_exit_ctls_reserved_properly_set(), bfn::vmcs_invalid_ctls_error);
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_activate_and_save_premeption_timer_must_be_0_success_one()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    fake_vmread_return[0] = VM_EXEC_PIN_BASED_ACTIVATE_VMX_PREEMPTION_TIMER;
    fake_vmread_return[1] = VM_EXIT_CONTROL_SAVE_VMX_PREEMPTION_TIMER_VALUE;

    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PINBASED_CTLS_MSR).Return((VM_EXEC_PIN_BASED_ACTIVATE_VMX_PREEMPTION_TIMER << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_EXIT_CTLS_MSR).Return((VM_EXIT_CONTROL_SAVE_VMX_PREEMPTION_TIMER_VALUE << 32));

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(vmcs.check_control_activate_and_save_premeption_timer_must_be_0());
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_activate_and_save_premeption_timer_must_be_0_success_two()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    fake_vmread_return[0] = VM_EXEC_PIN_BASED_ACTIVATE_VMX_PREEMPTION_TIMER;
    fake_vmread_return[1] = ~VM_EXIT_CONTROL_SAVE_VMX_PREEMPTION_TIMER_VALUE;

    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PINBASED_CTLS_MSR).Return((VM_EXEC_PIN_BASED_ACTIVATE_VMX_PREEMPTION_TIMER << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_EXIT_CTLS_MSR).Return((VM_EXIT_CONTROL_SAVE_VMX_PREEMPTION_TIMER_VALUE << 32));

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(vmcs.check_control_activate_and_save_premeption_timer_must_be_0());
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_activate_and_save_premeption_timer_must_be_0_success_three()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    fake_vmread_return[0] = ~VM_EXEC_PIN_BASED_ACTIVATE_VMX_PREEMPTION_TIMER;
    fake_vmread_return[1] = ~VM_EXIT_CONTROL_SAVE_VMX_PREEMPTION_TIMER_VALUE;

    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PINBASED_CTLS_MSR).Return((VM_EXEC_PIN_BASED_ACTIVATE_VMX_PREEMPTION_TIMER << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_EXIT_CTLS_MSR).Return((VM_EXIT_CONTROL_SAVE_VMX_PREEMPTION_TIMER_VALUE << 32));

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(vmcs.check_control_activate_and_save_premeption_timer_must_be_0());
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_activate_and_save_premeption_timer_must_be_0_fail()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    fake_vmread_return[0] = ~VM_EXEC_PIN_BASED_ACTIVATE_VMX_PREEMPTION_TIMER;
    fake_vmread_return[1] = VM_EXIT_CONTROL_SAVE_VMX_PREEMPTION_TIMER_VALUE;

    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PINBASED_CTLS_MSR).Return((VM_EXEC_PIN_BASED_ACTIVATE_VMX_PREEMPTION_TIMER << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_EXIT_CTLS_MSR).Return((VM_EXIT_CONTROL_SAVE_VMX_PREEMPTION_TIMER_VALUE << 32));

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(vmcs.check_control_activate_and_save_premeption_timer_must_be_0(), bfn::vmcs_invalid_field_error);
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_exit_msr_store_address_success_early()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);
    mocks.OnCall(in.get(), intrinsics_intel_x64::cpuid_eax).Return(48);

    fake_vmread_return[0] = 0;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(vmcs.check_control_exit_msr_store_address());
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_exit_msr_store_address_success()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);
    mocks.OnCall(in.get(), intrinsics_intel_x64::cpuid_eax).Return(48);

    fake_vmread_return[0] = 16;
    fake_vmread_return[1] = 0xFFFCAAAA0000;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(vmcs.check_control_exit_msr_store_address());
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_exit_msr_store_address_fail_unaligned()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);
    mocks.OnCall(in.get(), intrinsics_intel_x64::cpuid_eax).Return(48);

    fake_vmread_return[0] = 16;
    fake_vmread_return[1] = 0xFFFCAAAA000F;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(vmcs.check_control_exit_msr_store_address(), bfn::vmcs_invalid_field_error);
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_exit_msr_store_address_fail_invalid_start_physaddr()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);
    mocks.OnCall(in.get(), intrinsics_intel_x64::cpuid_eax).Return(48);

    fake_vmread_return[0] = 16;
    fake_vmread_return[1] = 0xDEADFFFCAAAA0000;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(vmcs.check_control_exit_msr_store_address(), bfn::invalid_address_error);
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_exit_msr_store_address_fail_invalid_end_physaddr()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);
    mocks.OnCall(in.get(), intrinsics_intel_x64::cpuid_eax).Return(48);

    // 256*16 + 1 = 4097
    fake_vmread_return[0] = (256 + 1);
    fake_vmread_return[1] = 0xFFFFFFFFF000;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(vmcs.check_control_exit_msr_store_address(), bfn::invalid_address_error);
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_exit_msr_load_address_success_early()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);
    mocks.OnCall(in.get(), intrinsics_intel_x64::cpuid_eax).Return(48);

    fake_vmread_return[0] = 0;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(vmcs.check_control_exit_msr_load_address());
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_exit_msr_load_address_success()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);
    mocks.OnCall(in.get(), intrinsics_intel_x64::cpuid_eax).Return(48);

    fake_vmread_return[0] = 16;
    fake_vmread_return[1] = 0xFFFCAAAA0000;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(vmcs.check_control_exit_msr_load_address());
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_exit_msr_load_address_fail_unaligned()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);
    mocks.OnCall(in.get(), intrinsics_intel_x64::cpuid_eax).Return(48);

    fake_vmread_return[0] = 16;
    fake_vmread_return[1] = 0xFFFCAAAA000F;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(vmcs.check_control_exit_msr_load_address(), bfn::vmcs_invalid_field_error);
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_exit_msr_load_address_fail_invalid_start_physaddr()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);
    mocks.OnCall(in.get(), intrinsics_intel_x64::cpuid_eax).Return(48);

    fake_vmread_return[0] = 16;
    fake_vmread_return[1] = 0xDEADFFFCAAAA0000;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(vmcs.check_control_exit_msr_load_address(), bfn::invalid_address_error);
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_exit_msr_load_address_fail_invalid_end_physaddr()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);
    mocks.OnCall(in.get(), intrinsics_intel_x64::cpuid_eax).Return(48);

    // 256*16 + 1 = 4097
    fake_vmread_return[0] = (256 + 1);
    fake_vmread_return[1] = 0xFFFFFFFFF000;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(vmcs.check_control_exit_msr_load_address(), bfn::invalid_address_error);
    });

    fake_vmread_index = 0;
    mm = NULL;
}


void
vmcs_ut::test_check_control_vm_entry_ctls_reserved_properly_set_success()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    // Breakage
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_ENTRY_CTLS_MSR).Return((0x55555555aaaaAAAA));
    fake_vmread_return[0] = 0xAAAAaaaaAAAAaaaa;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(vmcs.check_control_vm_entry_ctls_reserved_properly_set());
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_vm_entry_ctls_reserved_properly_set_fail_lower()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    // Breakage
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_ENTRY_CTLS_MSR).Return((0x55555555aaaaAAAA));
    fake_vmread_return[0] = 0x7777777755555555;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(vmcs.check_control_vm_entry_ctls_reserved_properly_set(), bfn::vmcs_invalid_ctls_error);
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_vm_entry_ctls_reserved_properly_set_fail_upper()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    // Breakage
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_ENTRY_CTLS_MSR).Return((0x55555555aaaaAAAA));
    fake_vmread_return[0] = 0x77777777AAAAaaaa;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(vmcs.check_control_vm_entry_ctls_reserved_properly_set(), bfn::vmcs_invalid_ctls_error);
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_event_injection_type_vector_checks_early_success()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    // Breakage
    fake_vmread_return[0] = ~VM_INTERRUPT_INFORMATION_VALID;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(vmcs.check_control_event_injection_type_vector_checks());
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_event_injection_type_vector_checks_success()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    auto type = 0x04;
    auto vector = 0x04;

    // Breakage
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((VM_EXEC_P_PROC_BASED_MONITOR_TRAP_FLAG << 32));
    fake_vmread_return[0] = (VM_INTERRUPT_INFORMATION_VALID | (type << 8) | (vector & VM_INTERRUPT_INFORMATION_VECTOR));
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(vmcs.check_control_event_injection_type_vector_checks());
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_event_injection_type_vector_checks_fail_reserved_set()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    auto type = 0x01;
    auto vector = 0x04;

    // Breakage
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((VM_EXEC_P_PROC_BASED_MONITOR_TRAP_FLAG << 32));
    fake_vmread_return[0] = (VM_INTERRUPT_INFORMATION_VALID | (type << 8) | (vector & VM_INTERRUPT_INFORMATION_VECTOR));
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(vmcs.check_control_event_injection_type_vector_checks(), bfn::vmcs_invalid_field_error);
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_event_injection_type_vector_checks_fail_no_monitor_trap_support()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    auto type = 0x07;
    auto vector = 0x04;

    // Breakage
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return(~(VM_EXEC_P_PROC_BASED_MONITOR_TRAP_FLAG << 32));
    fake_vmread_return[0] = (VM_INTERRUPT_INFORMATION_VALID | (type << 8) | (vector & VM_INTERRUPT_INFORMATION_VECTOR));
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(vmcs.check_control_event_injection_type_vector_checks(), bfn::vmcs_invalid_field_error);
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_event_injection_type_vector_checks_fail_nmi_vector_mismatch()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    auto type = 0x02;
    auto vector = 0x04;

    // Breakage
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return(~(VM_EXEC_P_PROC_BASED_MONITOR_TRAP_FLAG << 32));
    fake_vmread_return[0] = (VM_INTERRUPT_INFORMATION_VALID | (type << 8) | (vector & VM_INTERRUPT_INFORMATION_VECTOR));
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(vmcs.check_control_event_injection_type_vector_checks(), bfn::vmcs_invalid_field_error);
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_event_injection_type_vector_checks_fail_hw_exception_mismatch()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    auto type = 0x03;
    auto vector = 0x40;

    // Breakage
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return(~(VM_EXEC_P_PROC_BASED_MONITOR_TRAP_FLAG << 32));
    fake_vmread_return[0] = (VM_INTERRUPT_INFORMATION_VALID | (type << 8) | (vector & VM_INTERRUPT_INFORMATION_VECTOR));
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(vmcs.check_control_event_injection_type_vector_checks(), bfn::vmcs_invalid_field_error);
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_event_injection_type_vector_checks_fail_other_blank_vector()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    auto type = 0x07;
    auto vector = 0xFF;

    // Breakage
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return(~(VM_EXEC_P_PROC_BASED_MONITOR_TRAP_FLAG << 32));
    fake_vmread_return[0] = (VM_INTERRUPT_INFORMATION_VALID | (type << 8) | (vector & VM_INTERRUPT_INFORMATION_VECTOR));
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(vmcs.check_control_event_injection_type_vector_checks(), bfn::vmcs_invalid_field_error);
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_event_injection_delivery_ec_checks_early_success_one()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    // Breakage
    fake_vmread_return[0] = ~VM_INTERRUPT_INFORMATION_VALID;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(vmcs.check_control_event_injection_delivery_ec_checks());
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_event_injection_delivery_ec_checks_early_success_two()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    // Breakage
    fake_vmread_return[0] = ~VM_INTERRUPT_INFORMATION_DELIVERY_ERROR;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(vmcs.check_control_event_injection_delivery_ec_checks());
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_event_injection_delivery_ec_checks_success_with_unrestricted_guests()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    auto type = 0x03;
    auto vector = 0x08;

    // Breakage
    fake_vmread_return[0] = (VM_INTERRUPT_INFORMATION_VALID |
                             VM_INTERRUPT_INFORMATION_DELIVERY_ERROR |
                             ((type) << 8) |
                             ((vector) << 0));
    fake_vmread_return[1] = CRO_PE_PROTECTION_ENABLE;
    fake_vmread_return[2] = VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS;
    fake_vmread_return[3] = VM_EXEC_S_PROC_BASED_UNRESTRICTED_GUEST;

    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_PROCBASED_CTLS2_MSR).Return((VM_EXEC_S_PROC_BASED_ENABLE_EPT << 32) | (VM_EXEC_S_PROC_BASED_UNRESTRICTED_GUEST << 32));

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(vmcs.check_control_event_injection_delivery_ec_checks());
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_event_injection_delivery_ec_checks_fail_invalid_cr0()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    auto type = 0x03;
    auto vector = 0x08;

    // Breakage
    fake_vmread_return[0] = (VM_INTERRUPT_INFORMATION_VALID |
                             VM_INTERRUPT_INFORMATION_DELIVERY_ERROR |
                             ((type) << 8) |
                             ((vector) << 0));
    fake_vmread_return[1] = ~CRO_PE_PROTECTION_ENABLE;
    fake_vmread_return[2] = VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS;
    fake_vmread_return[3] = VM_EXEC_S_PROC_BASED_UNRESTRICTED_GUEST;

    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_PROCBASED_CTLS2_MSR).Return((VM_EXEC_S_PROC_BASED_ENABLE_EPT << 32) | (VM_EXEC_S_PROC_BASED_UNRESTRICTED_GUEST << 32));

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(vmcs.check_control_event_injection_delivery_ec_checks(), bfn::vmcs_invalid_field_error);
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_event_injection_delivery_ec_checks_success_without_unrestricted_guests()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    auto type = 0x03;
    auto vector = 0x08;

    // Breakage
    fake_vmread_return[0] = (VM_INTERRUPT_INFORMATION_VALID |
                             VM_INTERRUPT_INFORMATION_DELIVERY_ERROR |
                             ((type) << 8) |
                             ((vector) << 0));
    fake_vmread_return[1] = CRO_PE_PROTECTION_ENABLE;
    fake_vmread_return[2] = VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS;
    fake_vmread_return[3] = ~VM_EXEC_S_PROC_BASED_UNRESTRICTED_GUEST;

    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_PROCBASED_CTLS2_MSR).Return((VM_EXEC_S_PROC_BASED_ENABLE_EPT << 32) | (VM_EXEC_S_PROC_BASED_UNRESTRICTED_GUEST << 32));

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(vmcs.check_control_event_injection_delivery_ec_checks());
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_event_injection_delivery_ec_checks_fail_invalid_information_field()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    // Breakage
    auto type = 0x04;
    auto vector = 0x08;

    fake_vmread_return[0] = (VM_INTERRUPT_INFORMATION_VALID |
                             VM_INTERRUPT_INFORMATION_DELIVERY_ERROR |
                             ((type) << 8) |
                             ((vector) << 0));
    fake_vmread_return[1] = CRO_PE_PROTECTION_ENABLE;
    fake_vmread_return[2] = VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS;
    fake_vmread_return[3] = VM_EXEC_S_PROC_BASED_UNRESTRICTED_GUEST;

    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_PROCBASED_CTLS2_MSR).Return((VM_EXEC_S_PROC_BASED_ENABLE_EPT << 32) | (VM_EXEC_S_PROC_BASED_UNRESTRICTED_GUEST << 32));

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(vmcs.check_control_event_injection_delivery_ec_checks(), bfn::vmcs_invalid_field_error);
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_event_injection_delivery_ec_checks_fail_invalid_exception()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    // Breakage
    auto type = 0x03;
    auto vector = 0x0F;

    fake_vmread_return[0] = (VM_INTERRUPT_INFORMATION_VALID |
                             VM_INTERRUPT_INFORMATION_DELIVERY_ERROR |
                             ((type) << 8) |
                             ((vector) << 0));
    fake_vmread_return[1] = CRO_PE_PROTECTION_ENABLE;
    fake_vmread_return[2] = VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS;
    fake_vmread_return[3] = VM_EXEC_S_PROC_BASED_UNRESTRICTED_GUEST;

    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return((VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS << 32));
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_PROCBASED_CTLS2_MSR).Return((VM_EXEC_S_PROC_BASED_ENABLE_EPT << 32) | (VM_EXEC_S_PROC_BASED_UNRESTRICTED_GUEST << 32));

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(vmcs.check_control_event_injection_delivery_ec_checks(), bfn::vmcs_invalid_field_error);
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_event_injection_reserved_bits_checks_early_success()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_return[0] = ~VM_INTERRUPT_INFORMATION_VALID;

    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(vmcs.check_control_event_injection_reserved_bits_checks());
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_event_injection_reserved_bits_checks_success()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_return[0] = VM_INTERRUPT_INFORMATION_VALID | ~0x000000007FFFF000;

    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(vmcs.check_control_event_injection_reserved_bits_checks());
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_event_injection_reserved_bits_checks_fail()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    // Breakage
    fake_vmread_return[0] = VM_INTERRUPT_INFORMATION_VALID | 0x000000007FFFF000;

    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(vmcs.check_control_event_injection_reserved_bits_checks(), bfn::vmcs_invalid_field_error);
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_event_injection_ec_checks_early_success_one()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_return[0] = ~VM_INTERRUPT_INFORMATION_VALID;

    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(vmcs.check_control_event_injection_ec_checks());
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_event_injection_ec_checks_early_success_two()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_return[0] = VM_INTERRUPT_INFORMATION_VALID & ~VM_INTERRUPT_INFORMATION_DELIVERY_ERROR;

    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(vmcs.check_control_event_injection_ec_checks());
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_event_injection_ec_checks_early_success()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_return[0] = VM_INTERRUPT_INFORMATION_VALID | VM_INTERRUPT_INFORMATION_DELIVERY_ERROR;
    fake_vmread_return[1] = ~0x00000000FFFF8000;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(vmcs.check_control_event_injection_ec_checks());
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_event_injection_ec_checks_fail()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_return[0] = VM_INTERRUPT_INFORMATION_VALID | VM_INTERRUPT_INFORMATION_DELIVERY_ERROR;
    fake_vmread_return[1] = 0x00000000FFFF8000;

    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(vmcs.check_control_event_injection_ec_checks(), bfn::vmcs_invalid_field_error);
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_event_injection_instr_length_checks_early_success_one()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    auto type = 0x04;

    // Breakage
    fake_vmread_return[0] = (~VM_INTERRUPT_INFORMATION_VALID & (type << 8));
    fake_vmread_return[1] = 0x03;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(vmcs.check_control_event_injection_instr_length_checks());
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_event_injection_instr_length_checks_early_success_two()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    auto type = 0x04;

    // Breakage
    fake_vmread_return[0] = (VM_INTERRUPT_INFORMATION_VALID | (type << 8));
    fake_vmread_return[1] = 0x03;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(vmcs.check_control_event_injection_instr_length_checks());
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_event_injection_instr_length_checks_success()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    auto type = 0x04;

    // Breakage
    fake_vmread_return[0] = (VM_INTERRUPT_INFORMATION_VALID | (type << 8));
    fake_vmread_return[1] = 0x0A;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(vmcs.check_control_event_injection_instr_length_checks());
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_event_injection_instr_length_checks_fail_invalid_instr_length_high()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    auto type = 0x04;

    // Breakage
    fake_vmread_return[0] = (VM_INTERRUPT_INFORMATION_VALID | (type << 8));
    fake_vmread_return[1] = 0x10;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(vmcs.check_control_event_injection_instr_length_checks(), bfn::vmcs_invalid_field_error);
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_event_injection_instr_length_checks_fail_invalid_instr_length_low()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    auto type = 0x04;

    // Breakage
    fake_vmread_return[0] = (VM_INTERRUPT_INFORMATION_VALID | (type << 8));
    fake_vmread_return[1] = 0x00;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(vmcs.check_control_event_injection_instr_length_checks(), bfn::vmcs_invalid_field_error);
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_entry_msr_load_address_early_success()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);
    mocks.OnCall(in.get(), intrinsics_intel_x64::cpuid_eax).Return(48);

    fake_vmread_return[0] = 0;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(vmcs.check_control_entry_msr_load_address());
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_entry_msr_load_address_success()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);
    mocks.OnCall(in.get(), intrinsics_intel_x64::cpuid_eax).Return(48);

    fake_vmread_return[0] = 16;
    fake_vmread_return[1] = 0xFFFCAAAA0000;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(vmcs.check_control_entry_msr_load_address());
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_entry_msr_load_address_fail_unaligned()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);
    mocks.OnCall(in.get(), intrinsics_intel_x64::cpuid_eax).Return(48);

    fake_vmread_return[0] = 16;
    fake_vmread_return[1] = 0xFFFCAAAA000F;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(vmcs.check_control_entry_msr_load_address(), bfn::vmcs_invalid_field_error);
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_entry_msr_load_address_fail_invalid_start_physaddr()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);
    mocks.OnCall(in.get(), intrinsics_intel_x64::cpuid_eax).Return(48);

    fake_vmread_return[0] = 16;
    fake_vmread_return[1] = 0xDEADFFFCAAAA0000;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(vmcs.check_control_entry_msr_load_address(), bfn::invalid_address_error);
    });

    fake_vmread_index = 0;
    mm = NULL;
}

void
vmcs_ut::test_check_control_entry_msr_load_address_fail_invalid_end_physaddr()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    vmcs_intel_x64 vmcs(in);

    fake_vmread_index = 0;
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Do(fake_vmread);
    mocks.OnCall(in.get(), intrinsics_intel_x64::cpuid_eax).Return(48);

    // 256*16 + 1 = 4097
    fake_vmread_return[0] = (256 + 1);
    fake_vmread_return[1] = 0xFFFFFFFFF000;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(vmcs.check_control_entry_msr_load_address(), bfn::invalid_address_error);
    });

    fake_vmread_index = 0;
    mm = NULL;
}



