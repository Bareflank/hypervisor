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

#include <gsl/gsl>

#include <test.h>
#include <vmxon/vmxon_intel_x64.h>
#include <memory_manager/memory_manager.h>

#include <intrinsics/cpuid_x64.h>
#include <intrinsics/vmx_intel_x64.h>
#include <intrinsics/crs_intel_x64.h>
#include <intrinsics/msrs_intel_x64.h>

using namespace x64;
using namespace intel_x64;

static uint64_t g_cr0 = 0;
static uint64_t g_cr4 = 0;
static uint64_t g_rflags = 0;
static std::map<uint32_t, uint64_t> g_msrs;
static std::map<uint32_t, uint32_t> g_cpuid;

bool g_vmxon_fails = false;
bool g_vmxoff_fails = false;
bool g_write_cr4_fails = false;
bool virt_to_phys_return_nullptr = false;

extern "C" uint64_t
__read_cr0(void) noexcept
{ return g_cr0; }

extern "C" uint64_t
__read_cr4(void) noexcept
{ return g_cr4; }

extern "C" void
__write_cr4(uint64_t val) noexcept
{
    if (g_write_cr4_fails)
        return;

    g_cr4 = val;
}

extern "C" uint64_t
__read_msr(uint32_t addr) noexcept
{ return g_msrs[addr]; }

extern "C" uint64_t
__read_rflags(void) noexcept
{ return g_rflags; }

extern "C" uint32_t
__cpuid_ecx(uint32_t val) noexcept
{ return g_cpuid[val]; }

extern "C" bool
__vmxon(void *ptr) noexcept
{ (void) ptr; return !g_vmxon_fails; }

extern "C" bool
__vmxoff(void) noexcept
{ return !g_vmxoff_fails; }

static uintptr_t
virtptr_to_physint(void *ptr)
{
    (void) ptr;

    if (virt_to_phys_return_nullptr)
        return 0;

    return 0x0000000ABCDEF0000;
}

static void
setup_intrinsics(MockRepository &mocks, memory_manager *mm)
{
    g_cr0 = 0x0;
    g_cr4 = 0x0;

    // Place no restrictions on the control registers.
    g_msrs[msrs::ia32_vmx_cr0_fixed0::addr] = 0x0;
    g_msrs[msrs::ia32_vmx_cr0_fixed1::addr] = 0xFFFFFFFFFFFFFFFF;
    g_msrs[msrs::ia32_vmx_cr4_fixed0::addr] = 0x0;
    g_msrs[msrs::ia32_vmx_cr4_fixed1::addr] = 0xFFFFFFFFFFFFFFFF;

    // Enable VMX operation
    g_msrs[msrs::ia32_vmx_basic::addr] = (1ULL << 55) | (6ULL << 50);
    g_msrs[msrs::ia32_feature_control::addr] = (0x1ULL << 0);
    g_cpuid[cpuid::feature_information::addr] = cpuid::feature_information::ecx::vmx::mask;

    // Emulate the memory manager
    mocks.OnCallFunc(memory_manager::instance).Return(mm);
    mocks.OnCall(mm, memory_manager::virtptr_to_physint).Do(virtptr_to_physint);
}

void
vmxon_ut::test_start_success()
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager>();

    setup_intrinsics(mocks, mm);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        vmxon_intel_x64 vmxon{};
        EXPECT_NO_EXCEPTION(vmxon.start());
    });
}

void
vmxon_ut::test_start_start_twice()
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager>();

    setup_intrinsics(mocks, mm);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        vmxon_intel_x64 vmxon{};

        EXPECT_NO_EXCEPTION(vmxon.start());
        g_cr4 = 0;
        EXPECT_EXCEPTION(vmxon.start(), std::logic_error);
    });
}

void
vmxon_ut::test_start_execute_vmxon_already_on_failure()
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager>();

    setup_intrinsics(mocks, mm);

    g_cr4 = cr4::vmx_enable_bit::mask;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        vmxon_intel_x64 vmxon{};
        EXPECT_EXCEPTION(vmxon.start(), std::logic_error);
    });
}

void
vmxon_ut::test_start_execute_vmxon_failure()
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager>();

    setup_intrinsics(mocks, mm);

    auto ___ = gsl::finally([&]
    { g_vmxon_fails = false; });

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        vmxon_intel_x64 vmxon{};

        g_vmxon_fails = true;
        EXPECT_EXCEPTION(vmxon.start(), std::runtime_error);
    });
}

void
vmxon_ut::test_start_check_ia32_vmx_cr4_fixed0_msr_failure()
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager>();

    setup_intrinsics(mocks, mm);

    g_msrs[msrs::ia32_vmx_cr4_fixed0::addr] = 0x1;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        vmxon_intel_x64 vmxon{};
        EXPECT_EXCEPTION(vmxon.start(), std::logic_error);
    });
}

void
vmxon_ut::test_start_check_ia32_vmx_cr4_fixed1_msr_failure()
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager>();

    setup_intrinsics(mocks, mm);

    g_cr4 = 0x1;
    g_msrs[msrs::ia32_vmx_cr4_fixed1::addr] = 0xFFFFFFFFFFFFFFF0;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        vmxon_intel_x64 vmxon{};
        EXPECT_EXCEPTION(vmxon.start(), std::logic_error);
    });
}

void
vmxon_ut::test_start_enable_vmx_operation_failure()
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager>();

    setup_intrinsics(mocks, mm);

    g_write_cr4_fails = true;

    auto ___ = gsl::finally([&]
    { g_write_cr4_fails = false; });

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        vmxon_intel_x64 vmxon{};
        EXPECT_EXCEPTION(vmxon.start(), std::logic_error);
    });
}

void
vmxon_ut::test_start_v8086_disabled_failure()
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager>();

    setup_intrinsics(mocks, mm);

    g_rflags = 0xFFFFFFFFFFFFFFFF;

    auto ___ = gsl::finally([&]
    { g_rflags = 0x0; });

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        vmxon_intel_x64 vmxon{};
        EXPECT_EXCEPTION(vmxon.start(), std::logic_error);
    });
}

void
vmxon_ut::test_start_check_ia32_feature_control_msr()
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager>();

    setup_intrinsics(mocks, mm);

    g_msrs[msrs::ia32_feature_control::addr] = 0;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        vmxon_intel_x64 vmxon{};
        EXPECT_EXCEPTION(vmxon.start(), std::logic_error);
    });
}

void
vmxon_ut::test_start_check_ia32_vmx_cr0_fixed0_msr()
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager>();

    setup_intrinsics(mocks, mm);

    g_msrs[msrs::ia32_vmx_cr0_fixed0::addr] = 0x1;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        vmxon_intel_x64 vmxon{};
        EXPECT_EXCEPTION(vmxon.start(), std::logic_error);
    });
}

void
vmxon_ut::test_start_check_ia32_vmx_cr0_fixed1_msr()
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager>();

    setup_intrinsics(mocks, mm);

    g_cr0 = 0x1;
    g_msrs[msrs::ia32_vmx_cr0_fixed1::addr] = 0xFFFFFFFFFFFFFFF0;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        vmxon_intel_x64 vmxon{};
        EXPECT_EXCEPTION(vmxon.start(), std::logic_error);
    });
}

void
vmxon_ut::test_start_check_vmx_capabilities_msr_memtype_failure()
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager>();

    setup_intrinsics(mocks, mm);

    g_msrs[msrs::ia32_vmx_basic::addr] = (1ULL << 55);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        vmxon_intel_x64 vmxon{};
        EXPECT_EXCEPTION(vmxon.start(), std::logic_error);
    });
}

void
vmxon_ut::test_start_check_vmx_capabilities_msr_addr_width_failure()
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager>();

    setup_intrinsics(mocks, mm);

    g_msrs[msrs::ia32_vmx_basic::addr] = (1ULL << 55) | (6ULL << 50) | (1ULL << 48);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        vmxon_intel_x64 vmxon{};
        EXPECT_EXCEPTION(vmxon.start(), std::logic_error);
    });
}

void
vmxon_ut::test_start_check_vmx_capabilities_true_based_controls_failure()
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager>();

    setup_intrinsics(mocks, mm);

    g_msrs[msrs::ia32_vmx_basic::addr] = (6ULL << 50);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        vmxon_intel_x64 vmxon{};
        EXPECT_EXCEPTION(vmxon.start(), std::logic_error);
    });
}

void
vmxon_ut::test_start_check_cpuid_vmx_supported_failure()
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager>();

    setup_intrinsics(mocks, mm);

    g_cpuid[cpuid::feature_information::addr] = 0;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        vmxon_intel_x64 vmxon{};
        EXPECT_EXCEPTION(vmxon.start(), std::logic_error);
    });
}

void
vmxon_ut::test_start_virt_to_phys_failure()
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager>();

    setup_intrinsics(mocks, mm);

    auto ___ = gsl::finally([&]
    { virt_to_phys_return_nullptr = false; });

    virt_to_phys_return_nullptr = true;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        vmxon_intel_x64 vmxon{};
        EXPECT_EXCEPTION(vmxon.start(), std::logic_error);
    });
}

void
vmxon_ut::test_stop_success()
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager>();

    setup_intrinsics(mocks, mm);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        vmxon_intel_x64 vmxon{};

        vmxon.start();
        EXPECT_NO_EXCEPTION(vmxon.stop());
    });
}

void
vmxon_ut::test_stop_stop_twice()
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager>();

    setup_intrinsics(mocks, mm);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        vmxon_intel_x64 vmxon{};

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

    setup_intrinsics(mocks, mm);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        vmxon_intel_x64 vmxon{};
        vmxon.start();

        g_write_cr4_fails = true;

        auto ___ = gsl::finally([&]
        { g_write_cr4_fails = false; });

        EXPECT_EXCEPTION(vmxon.stop(), std::logic_error);
    });
}

void
vmxon_ut::test_stop_vmxoff_failure()
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager>();

    setup_intrinsics(mocks, mm);

    auto ___ = gsl::finally([&]
    { g_vmxoff_fails = false; });

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        vmxon_intel_x64 vmxon{};
        vmxon.start();

        g_vmxoff_fails = true;
        EXPECT_EXCEPTION(vmxon.stop(), std::runtime_error);
    });
}
