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
#include <vmxon/vmxon_intel_x64.h>
#include <vmxon/vmxon_exceptions_intel_x64.h>
#include <memory_manager/memory_manager.h>

memory_manager *mm = NULL;
uint64_t f_cr4 = 0;

static void *
stubbed_malloc_aligned(size_t size, int64_t alignment)
{
    void *ptr = NULL;

    if (posix_memalign(&ptr, alignment, size) != 0)
        return 0;

    return ptr;
}

static memory_manager *
fake_memory_manager()
{
    return mm;
}

static void
stubbed_write_cr4(uint32_t cr4)
{
    f_cr4 = cr4;
}

//////////////////////////////////////////////////////////////////////////////
// vmxon::stop
//////////////////////////////////////////////////////////////////////////////

void
vmxon_ut::test_start_success()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto intrinsics = in.get();
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    // is_vmx_operation_enabled
    Call &cr4_0 = mocks.ExpectCall(intrinsics, intrinsics_intel_x64::read_cr4).Return(0);

    // check_cpuid_vmx_supported
    mocks.OnCall(intrinsics, intrinsics_intel_x64::cpuid_ecx).With(1).Return((1 << 5));

    // check_vmx_capabilities_msr
    auto basic = ((1ULL << 55) | ((6ULL << 50) & (~(1ULL << 48))));
    mocks.OnCall(intrinsics, intrinsics_intel_x64::read_msr).With(IA32_VMX_BASIC_MSR).Return(basic);

    // check_ia32_vmx_cr0_fixed_msr
    mocks.OnCall(intrinsics, intrinsics_intel_x64::read_cr0).Return((0xffffffff));
    mocks.OnCall(intrinsics, intrinsics_intel_x64::read_msr).With(IA32_VMX_CR0_FIXED0_MSR).Return(0);
    mocks.OnCall(intrinsics, intrinsics_intel_x64::read_msr).With(IA32_VMX_CR0_FIXED1_MSR).Return(0xffffffff);

    // check_ia32_feature_control_msr
    mocks.OnCall(intrinsics, intrinsics_intel_x64::read_msr).With(IA32_FEATURE_CONTROL_MSR).Return((1 << 0));

    // check_v8086_disabled
    mocks.OnCall(intrinsics, intrinsics_intel_x64::read_rflags).Return(~RFLAGS_VM_VIRTUAL_8086_MODE);

    // create_vmxon_region
    mocks.OnCallFunc(memory_manager::instance).Do(fake_memory_manager);
    mocks.OnCall(mm, memory_manager::malloc_aligned).Do(stubbed_malloc_aligned);
    mocks.OnCall(mm, memory_manager::virt_to_phys).Return(reinterpret_cast<void *>(0xDEADBEEFDEAF1000));

    // enable_vmx_operation
    Call &cr4_1 = mocks.ExpectCall(intrinsics, intrinsics_intel_x64::read_cr4).After(cr4_0).Return(0);
    mocks.OnCall(intrinsics, intrinsics_intel_x64::write_cr4).Do(stubbed_write_cr4);

    // is_vmx_operation_enabled
    Call &cr4_2 = mocks.ExpectCall(intrinsics, intrinsics_intel_x64::read_cr4).After(cr4_1).Return(CR4_VMXE_VMX_ENABLE_BIT);

    // check_ia32_vmx_cr4_fixed_msr
    mocks.ExpectCall(intrinsics, intrinsics_intel_x64::read_cr4).After(cr4_2).Return(0xDEADBEEF);
    mocks.OnCall(intrinsics, intrinsics_intel_x64::read_msr).With(IA32_VMX_CR4_FIXED0_MSR).Return(~(~(0xDEADBEEF)));
    mocks.OnCall(intrinsics, intrinsics_intel_x64::read_msr).With(IA32_VMX_CR4_FIXED1_MSR).Return(0xDEADBEEF);

    // execute_vmxon
    mocks.OnCall(intrinsics, intrinsics_intel_x64::vmxon).Return(true);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        vmxon_intel_x64 vmxon(in);

        EXPECT_NO_EXCEPTION(vmxon.start());
    });
}

void
vmxon_ut::test_start_execute_vmxon_already_on_failure()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto intrinsics = in.get();
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    // is_vmx_operation_enabled
    Call &cr4_0 = mocks.ExpectCall(intrinsics, intrinsics_intel_x64::read_cr4).Return(0);

    // check_cpuid_vmx_supported
    mocks.OnCall(intrinsics, intrinsics_intel_x64::cpuid_ecx).With(1).Return((1 << 5));

    // check_vmx_capabilities_msr
    auto basic = ((1ULL << 55) | ((6ULL << 50) & (~(1ULL << 48))));
    mocks.OnCall(intrinsics, intrinsics_intel_x64::read_msr).With(IA32_VMX_BASIC_MSR).Return(basic);

    // check_ia32_vmx_cr0_fixed_msr
    mocks.OnCall(intrinsics, intrinsics_intel_x64::read_cr0).Return((0xffffffff));
    mocks.OnCall(intrinsics, intrinsics_intel_x64::read_msr).With(IA32_VMX_CR0_FIXED0_MSR).Return(0);
    mocks.OnCall(intrinsics, intrinsics_intel_x64::read_msr).With(IA32_VMX_CR0_FIXED1_MSR).Return(0xffffffff);

    // check_ia32_feature_control_msr
    mocks.OnCall(intrinsics, intrinsics_intel_x64::read_msr).With(IA32_FEATURE_CONTROL_MSR).Return((1 << 0));

    // check_v8086_disabled
    mocks.OnCall(intrinsics, intrinsics_intel_x64::read_rflags).Return(~RFLAGS_VM_VIRTUAL_8086_MODE);

    // create_vmxon_region
    mocks.OnCallFunc(memory_manager::instance).Do(fake_memory_manager);
    mocks.OnCall(mm, memory_manager::malloc_aligned).Do(stubbed_malloc_aligned);
    mocks.OnCall(mm, memory_manager::virt_to_phys).Return(reinterpret_cast<void *>(0xDEADBEEFDEAF1000));

    // enable_vmx_operation
    Call &cr4_1 = mocks.ExpectCall(intrinsics, intrinsics_intel_x64::read_cr4).After(cr4_0).Return(0);
    mocks.OnCall(intrinsics, intrinsics_intel_x64::write_cr4).Do(stubbed_write_cr4);

    // is_vmx_operation_enabled ***
    Call &cr4_2 = mocks.ExpectCall(intrinsics, intrinsics_intel_x64::read_cr4).After(cr4_1).Return(~CR4_VMXE_VMX_ENABLE_BIT);

    // check_ia32_vmx_cr4_fixed_msr
    mocks.ExpectCall(intrinsics, intrinsics_intel_x64::read_cr4).After(cr4_2).Return(0xDEADBEEF);
    mocks.OnCall(intrinsics, intrinsics_intel_x64::read_msr).With(IA32_VMX_CR4_FIXED0_MSR).Return(~(~(0xDEADBEEF)));
    mocks.OnCall(intrinsics, intrinsics_intel_x64::read_msr).With(IA32_VMX_CR4_FIXED1_MSR).Return(0xDEADBEEF);

    // execute_vmxon
    mocks.OnCall(intrinsics, intrinsics_intel_x64::vmxon).Return(true);

    // Handle rollbacks
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_cr4).Return(0);
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmxoff).Return(true);
    mocks.OnCall(in.get(), intrinsics_intel_x64::write_cr4).Do(stubbed_write_cr4);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        vmxon_intel_x64 vmxon(in);
        vmxon.m_vmxon_enabled = true;
        EXPECT_EXCEPTION(vmxon.start(), bfn::vmxon_failure_error);
    });
}

void
vmxon_ut::test_start_execute_vmxon_failure()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto intrinsics = in.get();
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    // is_vmx_operation_enabled
    Call &cr4_0 = mocks.ExpectCall(intrinsics, intrinsics_intel_x64::read_cr4).Return(0);

    // check_cpuid_vmx_supported
    mocks.OnCall(intrinsics, intrinsics_intel_x64::cpuid_ecx).With(1).Return((1 << 5));

    // check_vmx_capabilities_msr
    auto basic = ((1ULL << 55) | ((6ULL << 50) & (~(1ULL << 48))));
    mocks.OnCall(intrinsics, intrinsics_intel_x64::read_msr).With(IA32_VMX_BASIC_MSR).Return(basic);

    // check_ia32_vmx_cr0_fixed_msr
    mocks.OnCall(intrinsics, intrinsics_intel_x64::read_cr0).Return((0xffffffff));
    mocks.OnCall(intrinsics, intrinsics_intel_x64::read_msr).With(IA32_VMX_CR0_FIXED0_MSR).Return(0);
    mocks.OnCall(intrinsics, intrinsics_intel_x64::read_msr).With(IA32_VMX_CR0_FIXED1_MSR).Return(0xffffffff);

    // check_ia32_feature_control_msr
    mocks.OnCall(intrinsics, intrinsics_intel_x64::read_msr).With(IA32_FEATURE_CONTROL_MSR).Return((1 << 0));

    // check_v8086_disabled
    mocks.OnCall(intrinsics, intrinsics_intel_x64::read_rflags).Return(~RFLAGS_VM_VIRTUAL_8086_MODE);

    // create_vmxon_region
    mocks.OnCallFunc(memory_manager::instance).Do(fake_memory_manager);
    mocks.OnCall(mm, memory_manager::malloc_aligned).Do(stubbed_malloc_aligned);
    mocks.OnCall(mm, memory_manager::virt_to_phys).Return(reinterpret_cast<void *>(0xDEADBEEFDEAF1000));

    // enable_vmx_operation
    Call &cr4_1 = mocks.ExpectCall(intrinsics, intrinsics_intel_x64::read_cr4).After(cr4_0).Return(0);
    mocks.OnCall(intrinsics, intrinsics_intel_x64::write_cr4).Do(stubbed_write_cr4);

    // is_vmx_operation_enabled ***
    Call &cr4_2 = mocks.ExpectCall(intrinsics, intrinsics_intel_x64::read_cr4).After(cr4_1).Return(~CR4_VMXE_VMX_ENABLE_BIT);

    // check_ia32_vmx_cr4_fixed_msr
    mocks.ExpectCall(intrinsics, intrinsics_intel_x64::read_cr4).After(cr4_2).Return(0xDEADBEEF);
    mocks.OnCall(intrinsics, intrinsics_intel_x64::read_msr).With(IA32_VMX_CR4_FIXED0_MSR).Return(~(~(0xDEADBEEF)));
    mocks.OnCall(intrinsics, intrinsics_intel_x64::read_msr).With(IA32_VMX_CR4_FIXED1_MSR).Return(0xDEADBEEF);

    // execute_vmxon
    mocks.OnCall(intrinsics, intrinsics_intel_x64::vmxon).Return(false);

    // Handle rollbacks
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_cr4).Return(0);
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmxoff).Return(true);
    mocks.OnCall(in.get(), intrinsics_intel_x64::write_cr4).Do(stubbed_write_cr4);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        vmxon_intel_x64 vmxon(in);

        EXPECT_EXCEPTION(vmxon.start(), bfn::vmxon_failure_error);
    });
}

void
vmxon_ut::test_start_check_ia32_vmx_cr4_fixed0_msr_failure()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto intrinsics = in.get();
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    // is_vmx_operation_enabled
    Call &cr4_0 = mocks.ExpectCall(intrinsics, intrinsics_intel_x64::read_cr4).Return(0);

    // check_cpuid_vmx_supported
    mocks.OnCall(intrinsics, intrinsics_intel_x64::cpuid_ecx).With(1).Return((1 << 5));

    // check_vmx_capabilities_msr
    auto basic = ((1ULL << 55) | ((6ULL << 50) & (~(1ULL << 48))));
    mocks.OnCall(intrinsics, intrinsics_intel_x64::read_msr).With(IA32_VMX_BASIC_MSR).Return(basic);

    // check_ia32_vmx_cr0_fixed_msr
    mocks.OnCall(intrinsics, intrinsics_intel_x64::read_cr0).Return((0xffffffff));
    mocks.OnCall(intrinsics, intrinsics_intel_x64::read_msr).With(IA32_VMX_CR0_FIXED0_MSR).Return(0);
    mocks.OnCall(intrinsics, intrinsics_intel_x64::read_msr).With(IA32_VMX_CR0_FIXED1_MSR).Return(0xffffffff);

    // check_ia32_feature_control_msr
    mocks.OnCall(intrinsics, intrinsics_intel_x64::read_msr).With(IA32_FEATURE_CONTROL_MSR).Return((1 << 0));

    // check_v8086_disabled
    mocks.OnCall(intrinsics, intrinsics_intel_x64::read_rflags).Return(~RFLAGS_VM_VIRTUAL_8086_MODE);

    // create_vmxon_region
    mocks.OnCallFunc(memory_manager::instance).Do(fake_memory_manager);
    mocks.OnCall(mm, memory_manager::malloc_aligned).Do(stubbed_malloc_aligned);
    mocks.OnCall(mm, memory_manager::virt_to_phys).Return(reinterpret_cast<void *>(0xDEADBEEFDEAF1000));

    // enable_vmx_operation
    Call &cr4_1 = mocks.ExpectCall(intrinsics, intrinsics_intel_x64::read_cr4).After(cr4_0).Return(0);
    mocks.OnCall(intrinsics, intrinsics_intel_x64::write_cr4).Do(stubbed_write_cr4);

    // is_vmx_operation_enabled
    Call &cr4_2 = mocks.ExpectCall(intrinsics, intrinsics_intel_x64::read_cr4).After(cr4_1).Return(CR4_VMXE_VMX_ENABLE_BIT);

    // check_ia32_vmx_cr4_fixed_msr ***
    mocks.ExpectCall(intrinsics, intrinsics_intel_x64::read_cr4).After(cr4_2).Return(0xDEADBEEF);
    mocks.OnCall(intrinsics, intrinsics_intel_x64::read_msr).With(IA32_VMX_CR4_FIXED0_MSR).Return(0xFEEDBEEF);
    mocks.OnCall(intrinsics, intrinsics_intel_x64::read_msr).With(IA32_VMX_CR4_FIXED1_MSR).Return(0xDEADBEEF);

    // Handle rollbacks
    mocks.OnCall(intrinsics, intrinsics_intel_x64::read_cr4).Return(0);
    mocks.OnCall(intrinsics, intrinsics_intel_x64::vmxoff).Return(true);
    mocks.OnCall(intrinsics, intrinsics_intel_x64::write_cr4).Do(stubbed_write_cr4);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        vmxon_intel_x64 vmxon(in);

        EXPECT_EXCEPTION(vmxon.start(), bfn::vmxon_fixed_msr_failure_error);
    });
}

void
vmxon_ut::test_start_check_ia32_vmx_cr4_fixed1_msr_failure()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto intrinsics = in.get();
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    // is_vmx_operation_enabled
    Call &cr4_0 = mocks.ExpectCall(intrinsics, intrinsics_intel_x64::read_cr4).Return(0);

    // check_cpuid_vmx_supported
    mocks.OnCall(intrinsics, intrinsics_intel_x64::cpuid_ecx).With(1).Return((1 << 5));

    // check_vmx_capabilities_msr
    auto basic = ((1ULL << 55) | ((6ULL << 50) & (~(1ULL << 48))));
    mocks.OnCall(intrinsics, intrinsics_intel_x64::read_msr).With(IA32_VMX_BASIC_MSR).Return(basic);

    // check_ia32_vmx_cr0_fixed_msr
    mocks.OnCall(intrinsics, intrinsics_intel_x64::read_cr0).Return((0xffffffff));
    mocks.OnCall(intrinsics, intrinsics_intel_x64::read_msr).With(IA32_VMX_CR0_FIXED0_MSR).Return(0);
    mocks.OnCall(intrinsics, intrinsics_intel_x64::read_msr).With(IA32_VMX_CR0_FIXED1_MSR).Return(0xffffffff);

    // check_ia32_feature_control_msr
    mocks.OnCall(intrinsics, intrinsics_intel_x64::read_msr).With(IA32_FEATURE_CONTROL_MSR).Return((1 << 0));

    // check_v8086_disabled
    mocks.OnCall(intrinsics, intrinsics_intel_x64::read_rflags).Return(~RFLAGS_VM_VIRTUAL_8086_MODE);

    // create_vmxon_region
    mocks.OnCallFunc(memory_manager::instance).Do(fake_memory_manager);
    mocks.OnCall(mm, memory_manager::malloc_aligned).Do(stubbed_malloc_aligned);
    mocks.OnCall(mm, memory_manager::virt_to_phys).Return(reinterpret_cast<void *>(0xDEADBEEFDEAF1000));

    // enable_vmx_operation
    Call &cr4_1 = mocks.ExpectCall(intrinsics, intrinsics_intel_x64::read_cr4).After(cr4_0).Return(0);
    mocks.OnCall(intrinsics, intrinsics_intel_x64::write_cr4).Do(stubbed_write_cr4);

    // is_vmx_operation_enabled
    Call &cr4_2 = mocks.ExpectCall(intrinsics, intrinsics_intel_x64::read_cr4).After(cr4_1).Return(CR4_VMXE_VMX_ENABLE_BIT);

    // check_ia32_vmx_cr4_fixed_msr ***
    mocks.ExpectCall(intrinsics, intrinsics_intel_x64::read_cr4).After(cr4_2).Return(0xDEADBEEF);
    mocks.OnCall(intrinsics, intrinsics_intel_x64::read_msr).With(IA32_VMX_CR4_FIXED0_MSR).Return(~(~(0xDEADBEEF)));
    mocks.OnCall(intrinsics, intrinsics_intel_x64::read_msr).With(IA32_VMX_CR4_FIXED1_MSR).Return(0);

    // execute_vmxon
    mocks.OnCall(intrinsics, intrinsics_intel_x64::vmxon).Return(true);

    // Handle rollbacks
    mocks.OnCall(intrinsics, intrinsics_intel_x64::read_cr4).Return(0);
    mocks.OnCall(intrinsics, intrinsics_intel_x64::vmxoff).Return(true);
    mocks.OnCall(intrinsics, intrinsics_intel_x64::write_cr4).Do(stubbed_write_cr4);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        vmxon_intel_x64 vmxon(in);

        EXPECT_EXCEPTION(vmxon.start(), bfn::vmxon_fixed_msr_failure_error);
    });
}

void
vmxon_ut::test_start_enable_vmx_operation_failure()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto intrinsics = in.get();
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    // is_vmx_operation_enabled
    Call &cr4_0 = mocks.ExpectCall(intrinsics, intrinsics_intel_x64::read_cr4).Return(0);

    // check_cpuid_vmx_supported
    mocks.OnCall(intrinsics, intrinsics_intel_x64::cpuid_ecx).With(1).Return((1 << 5));

    // check_vmx_capabilities_msr
    auto basic = ((1ULL << 55) | ((6ULL << 50) & (~(1ULL << 48))));
    mocks.OnCall(intrinsics, intrinsics_intel_x64::read_msr).With(IA32_VMX_BASIC_MSR).Return(basic);

    // check_ia32_vmx_cr0_fixed_msr
    mocks.OnCall(intrinsics, intrinsics_intel_x64::read_cr0).Return((0xffffffff));
    mocks.OnCall(intrinsics, intrinsics_intel_x64::read_msr).With(IA32_VMX_CR0_FIXED0_MSR).Return(0);
    mocks.OnCall(intrinsics, intrinsics_intel_x64::read_msr).With(IA32_VMX_CR0_FIXED1_MSR).Return(0xffffffff);

    // check_ia32_feature_control_msr
    mocks.OnCall(intrinsics, intrinsics_intel_x64::read_msr).With(IA32_FEATURE_CONTROL_MSR).Return((1 << 0));

    // check_v8086_disabled
    mocks.OnCall(intrinsics, intrinsics_intel_x64::read_rflags).Return(~RFLAGS_VM_VIRTUAL_8086_MODE);

    // create_vmxon_region
    mocks.OnCallFunc(memory_manager::instance).Do(fake_memory_manager);
    mocks.OnCall(mm, memory_manager::malloc_aligned).Do(stubbed_malloc_aligned);
    mocks.OnCall(mm, memory_manager::virt_to_phys).Return(reinterpret_cast<void *>(0xDEADBEEFDEAF1000));

    // enable_vmx_operation
    Call &cr4_1 = mocks.ExpectCall(intrinsics, intrinsics_intel_x64::read_cr4).After(cr4_0).Return(0);
    mocks.OnCall(intrinsics, intrinsics_intel_x64::write_cr4).Do(stubbed_write_cr4);

    // is_vmx_operation_enabled ***
    Call &cr4_2 = mocks.ExpectCall(intrinsics, intrinsics_intel_x64::read_cr4).After(cr4_1).Return(~CR4_VMXE_VMX_ENABLE_BIT);

    // check_ia32_vmx_cr4_fixed_msr
    mocks.ExpectCall(intrinsics, intrinsics_intel_x64::read_cr4).After(cr4_2).Return(0xDEADBEEF);
    mocks.OnCall(intrinsics, intrinsics_intel_x64::read_msr).With(IA32_VMX_CR4_FIXED0_MSR).Return(~(~(0xDEADBEEF)));
    mocks.OnCall(intrinsics, intrinsics_intel_x64::read_msr).With(IA32_VMX_CR4_FIXED1_MSR).Return(0xDEADBEEF);

    // execute_vmxon
    mocks.OnCall(intrinsics, intrinsics_intel_x64::vmxon).Return(true);

    // Handle rollbacks
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_cr4).Return(0);
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmxoff).Return(true);
    mocks.OnCall(in.get(), intrinsics_intel_x64::write_cr4).Do(stubbed_write_cr4);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        vmxon_intel_x64 vmxon(in);

        EXPECT_EXCEPTION(vmxon.start(), bfn::vmxon_failure_error);
    });
}

void
vmxon_ut::test_start_v8086_disabled_failure()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto intrinsics = in.get();
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    // is_vmx_operation_enabled
    mocks.ExpectCall(intrinsics, intrinsics_intel_x64::read_cr4).Return(0);

    // check_cpuid_vmx_supported
    mocks.OnCall(intrinsics, intrinsics_intel_x64::cpuid_ecx).With(1).Return((1 << 5));

    // check_vmx_capabilities_msr
    auto basic = ((1ULL << 55) | ((6ULL << 50) & (~(1ULL << 48))));
    mocks.OnCall(intrinsics, intrinsics_intel_x64::read_msr).With(IA32_VMX_BASIC_MSR).Return(basic);

    // check_ia32_vmx_cr0_fixed_msr
    mocks.OnCall(intrinsics, intrinsics_intel_x64::read_cr0).Return((0xffffffff));
    mocks.OnCall(intrinsics, intrinsics_intel_x64::read_msr).With(IA32_VMX_CR0_FIXED0_MSR).Return(0);
    mocks.OnCall(intrinsics, intrinsics_intel_x64::read_msr).With(IA32_VMX_CR0_FIXED1_MSR).Return(0xffffffff);

    // check_ia32_feature_control_msr
    mocks.OnCall(intrinsics, intrinsics_intel_x64::read_msr).With(IA32_FEATURE_CONTROL_MSR).Return((1 << 0));

    // check_v8086_disabled
    mocks.OnCall(intrinsics, intrinsics_intel_x64::read_rflags).Return(RFLAGS_VM_VIRTUAL_8086_MODE);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        vmxon_intel_x64 vmxon(in);

        EXPECT_EXCEPTION(vmxon.start(), bfn::vmxon_failure_error);
    });
}

void
vmxon_ut::test_start_check_ia32_feature_control_msr()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto intrinsics = in.get();
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    // is_vmx_operation_enabled
    mocks.OnCall(intrinsics, intrinsics_intel_x64::read_cr4).Return(0);

    // check_cpuid_vmx_supported
    mocks.OnCall(intrinsics, intrinsics_intel_x64::cpuid_ecx).With(1).Return((1 << 5));

    // check_vmx_capabilities_msr
    auto basic = ((1ULL << 55) | ((6ULL << 50) & (~(1ULL << 48))));
    mocks.OnCall(intrinsics, intrinsics_intel_x64::read_msr).With(IA32_VMX_BASIC_MSR).Return(basic);

    // check_ia32_vmx_cr0_fixed_msr
    mocks.OnCall(intrinsics, intrinsics_intel_x64::read_cr0).Return((0xffffffff));
    mocks.OnCall(intrinsics, intrinsics_intel_x64::read_msr).With(IA32_VMX_CR0_FIXED0_MSR).Return(0);
    mocks.OnCall(intrinsics, intrinsics_intel_x64::read_msr).With(IA32_VMX_CR0_FIXED1_MSR).Return(0xffffffff);

    // check_ia32_feature_control_msr
    mocks.OnCall(intrinsics, intrinsics_intel_x64::read_msr).With(IA32_FEATURE_CONTROL_MSR).Return(0);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        vmxon_intel_x64 vmxon(in);

        EXPECT_EXCEPTION(vmxon.start(), bfn::vmxon_failure_error);
    });
}

void
vmxon_ut::test_start_check_ia32_vmx_cr0_fixed0_msr()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto intrinsics = in.get();
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    // is_vmx_operation_enabled
    mocks.OnCall(intrinsics, intrinsics_intel_x64::read_cr4).Return(0);

    // check_cpuid_vmx_supported
    mocks.OnCall(intrinsics, intrinsics_intel_x64::cpuid_ecx).With(1).Return((1 << 5));

    // check_vmx_capabilities_msr
    auto basic = ((1ULL << 55) | ((6ULL << 50) & (~(1ULL << 48))));
    mocks.OnCall(intrinsics, intrinsics_intel_x64::read_msr).With(IA32_VMX_BASIC_MSR).Return(basic);

    // check_ia32_vmx_cr0_fixed_msr
    mocks.OnCall(intrinsics, intrinsics_intel_x64::read_cr0).Return(0xDEADBEEF);
    mocks.OnCall(intrinsics, intrinsics_intel_x64::read_msr).With(IA32_VMX_CR0_FIXED0_MSR).Return(~(0xDEADBEEF));
    mocks.OnCall(intrinsics, intrinsics_intel_x64::read_msr).With(IA32_VMX_CR0_FIXED1_MSR).Return(0xDEADBEEF);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        vmxon_intel_x64 vmxon(in);

        EXPECT_EXCEPTION(vmxon.start(), bfn::vmxon_fixed_msr_failure_error);
    });
}

void
vmxon_ut::test_start_check_ia32_vmx_cr0_fixed1_msr()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto intrinsics = in.get();
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    // is_vmx_operation_enabled
    mocks.ExpectCall(intrinsics, intrinsics_intel_x64::read_cr4).Return(0);

    // check_cpuid_vmx_supported
    mocks.OnCall(intrinsics, intrinsics_intel_x64::cpuid_ecx).With(1).Return((1 << 5));

    // check_vmx_capabilities_msr
    auto basic = ((1ULL << 55) | ((6ULL << 50) & (~(1ULL << 48))));
    mocks.OnCall(intrinsics, intrinsics_intel_x64::read_msr).With(IA32_VMX_BASIC_MSR).Return(basic);

    // check_ia32_vmx_cr0_fixed_msr
    mocks.OnCall(intrinsics, intrinsics_intel_x64::read_cr0).Return(0xDEADBEEF);
    mocks.OnCall(intrinsics, intrinsics_intel_x64::read_msr).With(IA32_VMX_CR0_FIXED0_MSR).Return(~(0xDEADBEEF));
    mocks.OnCall(intrinsics, intrinsics_intel_x64::read_msr).With(IA32_VMX_CR0_FIXED1_MSR).Return(0);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        vmxon_intel_x64 vmxon(in);

        EXPECT_EXCEPTION(vmxon.start(), bfn::vmxon_fixed_msr_failure_error);
    });
}


void
vmxon_ut::test_start_check_vmx_capabilities_msr_memtype_failure()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto intrinsics = in.get();
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    // is_vmx_operation_enabled
    mocks.ExpectCall(intrinsics, intrinsics_intel_x64::read_cr4).Return(0);

    // check_cpuid_vmx_supported
    mocks.OnCall(intrinsics, intrinsics_intel_x64::cpuid_ecx).With(1).Return((1 << 5));

    // check_vmx_capabilities_msr
    auto basic = ((1ULL << 55) | ((3ULL << 50) & (~(1ULL << 48))));
    mocks.OnCall(intrinsics, intrinsics_intel_x64::read_msr).With(IA32_VMX_BASIC_MSR).Return(basic);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        vmxon_intel_x64 vmxon(in);

        EXPECT_EXCEPTION(vmxon.start(), bfn::vmxon_capabilities_failure_error);
    });
}

void
vmxon_ut::test_start_check_vmx_capabilities_msr_addr_width_failure()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto intrinsics = in.get();
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    // is_vmx_operation_enabled
    mocks.ExpectCall(intrinsics, intrinsics_intel_x64::read_cr4).Return(0);

    // check_cpuid_vmx_supported
    mocks.OnCall(intrinsics, intrinsics_intel_x64::cpuid_ecx).With(1).Return((1 << 5));

    // check_vmx_capabilities_msr
    auto basic = ((1ULL << 55) | ((~(1ULL << 48))));
    mocks.OnCall(intrinsics, intrinsics_intel_x64::read_msr).With(IA32_VMX_BASIC_MSR).Return(basic);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        vmxon_intel_x64 vmxon(in);

        EXPECT_EXCEPTION(vmxon.start(), bfn::vmxon_capabilities_failure_error);
    });
}

void
vmxon_ut::test_start_check_cpuid_vmx_supported_failure()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto intrinsics = in.get();
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    // is_vmx_operation_enabled
    mocks.ExpectCall(intrinsics, intrinsics_intel_x64::read_cr4).Return(0);

    // check_cpuid_vmx_supported
    mocks.OnCall(intrinsics, intrinsics_intel_x64::cpuid_ecx).With(1).Return(~(1 << 5));

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        vmxon_intel_x64 vmxon(in);

        EXPECT_EXCEPTION(vmxon.start(), bfn::vmxon_failure_error);
    });
}

void
vmxon_ut::test_start_vmxon_already_enabled_failure()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto intrinsics = in.get();
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    // is_vmx_operation_enabled
    mocks.ExpectCall(intrinsics, intrinsics_intel_x64::read_cr4).Return(CR4_VMXE_VMX_ENABLE_BIT);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        vmxon_intel_x64 vmxon(in);

        EXPECT_EXCEPTION(vmxon.start(), bfn::vmxon_failure_error);
    });
}

//////////////////////////////////////////////////////////////////////////////
// vmxon::stop
//////////////////////////////////////////////////////////////////////////////

void
vmxon_ut::test_stop_success()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto intrinsics = in.get();
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    // execute_vmxoff
    mocks.OnCall(intrinsics, intrinsics_intel_x64::vmxoff).Return(true);

    // disable_vmx_operation
    Call &cr4_0 = mocks.ExpectCall(intrinsics, intrinsics_intel_x64::read_cr4).Return(0);
    mocks.OnCall(intrinsics, intrinsics_intel_x64::write_cr4).Do(stubbed_write_cr4);

    // is_vmx_operation_enabled
    mocks.ExpectCall(intrinsics, intrinsics_intel_x64::read_cr4).After(cr4_0).Return(~CR4_VMXE_VMX_ENABLE_BIT);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        vmxon_intel_x64 vmxon(in);

        EXPECT_NO_EXCEPTION(vmxon.stop());
    });
}

void
vmxon_ut::test_stop_vmxoff_check_failure()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto intrinsics = in.get();
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    // execute_vmxoff
    mocks.OnCall(intrinsics, intrinsics_intel_x64::vmxoff).Return(true);

    // disable_vmx_operation
    Call &cr4_0 = mocks.ExpectCall(intrinsics, intrinsics_intel_x64::read_cr4).Return(0);
    mocks.OnCall(intrinsics, intrinsics_intel_x64::write_cr4).Do(stubbed_write_cr4);

    // is_vmx_operation_enabled
    mocks.ExpectCall(intrinsics, intrinsics_intel_x64::read_cr4).After(cr4_0).Return(CR4_VMXE_VMX_ENABLE_BIT);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        vmxon_intel_x64 vmxon(in);

        EXPECT_EXCEPTION(vmxon.stop(), bfn::vmxon_failure_error);
    });
}

void
vmxon_ut::test_stop_vmxoff_failure()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto intrinsics = in.get();
    auto l_mm = bfn::mock_shared<memory_manager>(mocks);
    mm = l_mm.get();

    // execute_vmxoff
    mocks.OnCall(intrinsics, intrinsics_intel_x64::vmxoff).Return(false);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        vmxon_intel_x64 vmxon(in);
        vmxon.m_vmxon_enabled = true;
        EXPECT_EXCEPTION(vmxon.stop(), bfn::vmxon_failure_error);
    });
}
