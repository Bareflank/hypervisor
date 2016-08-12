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

static uint64_t g_cr0 = 0;
static uint64_t g_cr4 = 0;

static uint64_t
read_cr0(void)
{ return g_cr0; }

// static void
// write_cr0(uint64_t cr0)
// { g_cr0 = cr0; }

static uint64_t
read_cr4(void)
{ return g_cr4; }

static void
write_cr4(uint64_t cr4)
{ g_cr4 = cr4; }

static void *
malloc_aligned(size_t size, uint64_t alignment)
{
    void *ptr = 0;
    if (posix_memalign(&ptr, alignment, size) != 0)
        return 0;
    return ptr;
}

static void *
virt_to_phys(void *)
{
    static uintptr_t phys = 0x0000000ABCDEF0000;
    return reinterpret_cast<void *>(phys + 0x1000);
}

void
vmxon_ut::test_constructor_null_intrinsics()
{
    EXPECT_NO_EXCEPTION(vmxon_intel_x64(nullptr));
}

static void
setup_intrinsics(MockRepository &mocks, memory_manager *mm, intrinsics_intel_x64 *in)
{
    g_cr0 = 0x0;
    g_cr4 = 0x0;

    // Place no restrictions on the control registers.
    mocks.OnCall(in, intrinsics_intel_x64::read_msr).With(IA32_VMX_CR0_FIXED0_MSR).Return(0x0);
    mocks.OnCall(in, intrinsics_intel_x64::read_msr).With(IA32_VMX_CR0_FIXED1_MSR).Return(0xFFFFFFFFFFFFFFFF);
    mocks.OnCall(in, intrinsics_intel_x64::read_msr).With(IA32_VMX_CR4_FIXED0_MSR).Return(0x0);
    mocks.OnCall(in, intrinsics_intel_x64::read_msr).With(IA32_VMX_CR4_FIXED1_MSR).Return(0xFFFFFFFFFFFFFFFF);

    // Enable VMX operation
    mocks.OnCall(in, intrinsics_intel_x64::cpuid_ecx).With(1).Return((1 << 5));
    mocks.OnCall(in, intrinsics_intel_x64::read_msr).With(IA32_VMX_BASIC_MSR).Return((1ULL << 55) | (6ULL << 50));
    mocks.OnCall(in, intrinsics_intel_x64::read_msr).With(IA32_FEATURE_CONTROL_MSR).Return((0x1ULL << 0));

    // v8086 emulation must be disabled
    mocks.OnCall(in, intrinsics_intel_x64::read_rflags).Return(~RFLAGS_VM_VIRTUAL_8086_MODE);

    // Emulate the control registers
    mocks.OnCall(in, intrinsics_intel_x64::read_cr0).Do(read_cr0);
    // mocks.OnCall(in, intrinsics_intel_x64::write_cr0).Do(write_cr0);
    mocks.OnCall(in, intrinsics_intel_x64::read_cr4).Do(read_cr4);
    mocks.OnCall(in, intrinsics_intel_x64::write_cr4).Do(write_cr4);

    // By default, the VMX instructions are successful
    mocks.OnCall(in, intrinsics_intel_x64::vmxon).Return(true);
    mocks.OnCall(in, intrinsics_intel_x64::vmxoff).Return(true);

    // Emulate the memory manager
    mocks.OnCallFunc(memory_manager::instance).Return(mm);
    mocks.OnCall(mm, memory_manager::malloc_aligned).Do(malloc_aligned);
    mocks.OnCall(mm, memory_manager::virt_to_phys).Do(virt_to_phys);
}

void
vmxon_ut::test_start_success()
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager>();
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    setup_intrinsics(mocks, mm, in.get());

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        vmxon_intel_x64 vmxon(in);

        EXPECT_NO_EXCEPTION(vmxon.start());
    });
}

void
vmxon_ut::test_start_start_twice()
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager>();
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    setup_intrinsics(mocks, mm, in.get());

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        vmxon_intel_x64 vmxon(in);

        EXPECT_NO_EXCEPTION(vmxon.start());
        g_cr4 = 0;
        EXPECT_EXCEPTION(vmxon.start(), bfn::vmxon_failure_error);
    });
}

void
vmxon_ut::test_start_execute_vmxon_already_on_failure()
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager>();
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    setup_intrinsics(mocks, mm, in.get());

    g_cr4 = CR4_VMXE_VMX_ENABLE_BIT;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        vmxon_intel_x64 vmxon(in);

        EXPECT_EXCEPTION(vmxon.start(), bfn::vmxon_failure_error);
    });
}

void
vmxon_ut::test_start_execute_vmxon_failure()
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager>();
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    setup_intrinsics(mocks, mm, in.get());

    mocks.OnCall(in.get(), intrinsics_intel_x64::vmxon).Return(false);

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
    auto mm = mocks.Mock<memory_manager>();
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    setup_intrinsics(mocks, mm, in.get());

    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_CR4_FIXED0_MSR).Return(0x1);

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
    auto mm = mocks.Mock<memory_manager>();
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    setup_intrinsics(mocks, mm, in.get());

    g_cr4 = 0x1;
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_CR4_FIXED1_MSR).Return(0xFFFFFFFFFFFFFFF0);

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
    auto mm = mocks.Mock<memory_manager>();
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    setup_intrinsics(mocks, mm, in.get());

    mocks.OnCall(in.get(), intrinsics_intel_x64::write_cr4);

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
    auto mm = mocks.Mock<memory_manager>();
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    setup_intrinsics(mocks, mm, in.get());

    mocks.OnCall(in.get(), intrinsics_intel_x64::read_rflags).Return(0xFFFFFFFFFFFFFFFF);

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
    auto mm = mocks.Mock<memory_manager>();
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    setup_intrinsics(mocks, mm, in.get());

    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_FEATURE_CONTROL_MSR).Return(0);

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
    auto mm = mocks.Mock<memory_manager>();
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    setup_intrinsics(mocks, mm, in.get());

    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_CR0_FIXED0_MSR).Return(0x1);

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
    auto mm = mocks.Mock<memory_manager>();
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    setup_intrinsics(mocks, mm, in.get());

    g_cr0 = 0x1;
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_CR0_FIXED1_MSR).Return(0xFFFFFFFFFFFFFFF0);

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
    auto mm = mocks.Mock<memory_manager>();
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    setup_intrinsics(mocks, mm, in.get());

    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_BASIC_MSR).Return((1ULL << 55));

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
    auto mm = mocks.Mock<memory_manager>();
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    setup_intrinsics(mocks, mm, in.get());

    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_BASIC_MSR).Return((1ULL << 55) | (6ULL << 50) | (1ULL << 48));

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        vmxon_intel_x64 vmxon(in);

        EXPECT_EXCEPTION(vmxon.start(), bfn::vmxon_capabilities_failure_error);
    });
}

void
vmxon_ut::test_start_check_vmx_capabilities_true_based_controls_failure()
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager>();
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    setup_intrinsics(mocks, mm, in.get());

    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).With(IA32_VMX_BASIC_MSR).Return((6ULL << 50));

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
    auto mm = mocks.Mock<memory_manager>();
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    setup_intrinsics(mocks, mm, in.get());

    mocks.OnCall(in.get(), intrinsics_intel_x64::cpuid_ecx).With(1).Return(0);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        vmxon_intel_x64 vmxon(in);

        EXPECT_EXCEPTION(vmxon.start(), bfn::vmxon_failure_error);
    });
}

void
vmxon_ut::test_start_virt_to_phys_failure()
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager>();
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    setup_intrinsics(mocks, mm, in.get());

    mocks.OnCall(mm, memory_manager::virt_to_phys).Return(0);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        vmxon_intel_x64 vmxon(in);

        EXPECT_EXCEPTION(vmxon.start(), std::logic_error);
    });
}

void
vmxon_ut::test_stop_success()
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager>();
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    setup_intrinsics(mocks, mm, in.get());

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        vmxon_intel_x64 vmxon(in);

        vmxon.start();
        EXPECT_NO_EXCEPTION(vmxon.stop());
    });
}

void
vmxon_ut::test_stop_stop_twice()
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager>();
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    setup_intrinsics(mocks, mm, in.get());

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        vmxon_intel_x64 vmxon(in);

        vmxon.start();
        EXPECT_NO_EXCEPTION(vmxon.stop());
        EXPECT_NO_EXCEPTION(vmxon.stop());
    });
}

void
vmxon_ut::test_stop_vmxoff_check_failure()
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager>();
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    setup_intrinsics(mocks, mm, in.get());

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        vmxon_intel_x64 vmxon(in);

        vmxon.start();
        mocks.OnCall(in.get(), intrinsics_intel_x64::write_cr4);
        EXPECT_EXCEPTION(vmxon.stop(), bfn::vmxon_failure_error);
    });
}

void
vmxon_ut::test_stop_vmxoff_failure()
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager>();
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    setup_intrinsics(mocks, mm, in.get());

    mocks.OnCall(in.get(), intrinsics_intel_x64::vmxoff).Return(false);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        vmxon_intel_x64 vmxon(in);

        vmxon.start();
        EXPECT_EXCEPTION(vmxon.stop(), bfn::vmxon_failure_error);
    });
}

void
vmxon_ut::test_coveralls_cleanup()
{
    MockRepository mocks;
    mocks.OnCallFunc(posix_memalign).Return(-1);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto ptr = malloc_aligned(4096, 4096);
        EXPECT_TRUE(ptr == nullptr);

        if (ptr)
            free(ptr);
    });
}
