//
// Bareflank Hypervisor
// Copyright (C) 2015 Assured Information Security, Inc.
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

#include <catch/catch.hpp>
#include <hippomocks.h>

#include <bfgsl.h>

#include <vmxon/vmxon_intel_x64.h>
#include <memory_manager/memory_manager_x64.h>

#include <intrinsics/x86/common_x64.h>
#include <intrinsics/x86/intel_x64.h>

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

using namespace x64;
using namespace intel_x64;

static intel_x64::cr0::value_type g_cr0 = 0;
static intel_x64::cr4::value_type g_cr4 = 0;
static x64::rflags::value_type g_rflags = 0;
static std::map<intel_x64::msrs::field_type, intel_x64::msrs::value_type> g_msrs;
static std::map<x64::cpuid::field_type, x64::cpuid::value_type> g_cpuid;

bool g_vmxon_fails = false;
bool g_vmxoff_fails = false;
bool g_write_cr4_fails = false;
bool g_virt_to_phys_return_nullptr = false;

static uint64_t
test_read_cr0() noexcept
{
    return g_cr0;
}

static uint64_t
test_read_cr4() noexcept
{
    return g_cr4;
}

static void
test_write_cr4(uint64_t val) noexcept
{
    if (g_write_cr4_fails) {
        return;
    }

    g_cr4 = val;
}

static uint64_t
test_read_msr(uint32_t addr) noexcept
{
    return g_msrs[addr];
}

static void
test_write_msr(uint32_t addr, uint64_t val) noexcept
{
    g_msrs[addr] = val;
}

static uint64_t
test_read_rflags() noexcept
{
    return g_rflags;
}

static uint32_t
test_cpuid_ecx(uint32_t val) noexcept
{
    return g_cpuid[val];
}

static bool
test_vmxon(void *ptr) noexcept
{
    (void) ptr;
    return !g_vmxon_fails;
}

static bool
test_vmxoff() noexcept
{
    return !g_vmxoff_fails;
}

static uintptr_t
virtptr_to_physint(void *ptr)
{
    (void) ptr;
    if (g_virt_to_phys_return_nullptr) {
        throw gsl::fail_fast("");
    }

    return 0x0000000ABCDEF0000;
}

static void
setup_intrinsics(MockRepository &mocks, memory_manager_x64 *mm)
{
    g_cr0 = 0x0;
    g_cr4 = 0x0;

    g_msrs[intel_x64::msrs::ia32_vmx_cr0_fixed0::addr] = 0x0;
    g_msrs[intel_x64::msrs::ia32_vmx_cr0_fixed1::addr] = 0xFFFFFFFFFFFFFFFF;
    g_msrs[intel_x64::msrs::ia32_vmx_cr4_fixed0::addr] = 0x0;
    g_msrs[intel_x64::msrs::ia32_vmx_cr4_fixed1::addr] = 0xFFFFFFFFFFFFFFFF;

    g_msrs[intel_x64::msrs::ia32_vmx_basic::addr] = (1ULL << 55) | (6ULL << 50);
    g_msrs[intel_x64::msrs::ia32_feature_control::addr] = (0x1ULL << 0);
    g_cpuid[intel_x64::cpuid::feature_information::addr] = intel_x64::cpuid::feature_information::ecx::vmx::mask;

    mocks.OnCallFunc(memory_manager_x64::instance).Return(mm);
    mocks.OnCall(mm, memory_manager_x64::virtptr_to_physint).Do(virtptr_to_physint);

    mocks.OnCallFunc(_read_cr0).Do(test_read_cr0);
    mocks.OnCallFunc(_read_cr4).Do(test_read_cr4);
    mocks.OnCallFunc(_write_cr4).Do(test_write_cr4);
    mocks.OnCallFunc(_read_msr).Do(test_read_msr);
    mocks.OnCallFunc(_write_msr).Do(test_write_msr);
    mocks.OnCallFunc(_read_rflags).Do(test_read_rflags);
    mocks.OnCallFunc(_cpuid_ecx).Do(test_cpuid_ecx);
    mocks.OnCallFunc(_vmxon).Do(test_vmxon);
    mocks.OnCallFunc(_vmxoff).Do(test_vmxoff);
}

TEST_CASE("vmxon: start_success")
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager_x64>();

    setup_intrinsics(mocks, mm);

    vmxon_intel_x64 vmxon{};
    CHECK_NOTHROW(vmxon.start());
}

TEST_CASE("vmxon: start_start_twice")
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager_x64>();

    setup_intrinsics(mocks, mm);

    vmxon_intel_x64 vmxon{};

    CHECK_NOTHROW(vmxon.start());
    g_cr4 = 0;
    CHECK_THROWS(vmxon.start());
}

TEST_CASE("vmxon: start_execute_vmxon_failure")
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager_x64>();

    setup_intrinsics(mocks, mm);

    auto ___ = gsl::finally([&]
    { g_vmxon_fails = false; });

    vmxon_intel_x64 vmxon{};

    g_vmxon_fails = true;
    CHECK_THROWS(vmxon.start());
}

TEST_CASE("vmxon: start_check_ia32_vmx_cr4_fixed0_msr_failure")
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager_x64>();

    setup_intrinsics(mocks, mm);

    g_msrs[intel_x64::msrs::ia32_vmx_cr4_fixed0::addr] = 0x1;

    vmxon_intel_x64 vmxon{};
    CHECK_THROWS(vmxon.start());
}

TEST_CASE("vmxon: start_check_ia32_vmx_cr4_fixed1_msr_failure")
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager_x64>();

    setup_intrinsics(mocks, mm);

    g_cr4 = 0x1;
    g_msrs[intel_x64::msrs::ia32_vmx_cr4_fixed1::addr] = 0xFFFFFFFFFFFFFFF0;

    vmxon_intel_x64 vmxon{};
    CHECK_THROWS(vmxon.start());
}

TEST_CASE("vmxon: start_enable_vmx_operation_failure")
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager_x64>();

    setup_intrinsics(mocks, mm);

    g_write_cr4_fails = true;

    auto ___ = gsl::finally([&]
    { g_write_cr4_fails = false; });

    vmxon_intel_x64 vmxon{};
    CHECK_THROWS(vmxon.start());
}

TEST_CASE("vmxon: start_v8086_disabled_failure")
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager_x64>();

    setup_intrinsics(mocks, mm);

    g_rflags = 0xFFFFFFFFFFFFFFFF;

    auto ___ = gsl::finally([&]
    { g_rflags = 0x0; });

    vmxon_intel_x64 vmxon{};
    CHECK_THROWS(vmxon.start());
}

TEST_CASE("vmxon: start_check_ia32_feature_control_msr_unlocked")
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager_x64>();

    setup_intrinsics(mocks, mm);

    g_msrs[intel_x64::msrs::ia32_feature_control::addr] = 0;

    vmxon_intel_x64 vmxon{};
    CHECK_NOTHROW(vmxon.start());
    CHECK(intel_x64::msrs::ia32_feature_control::enable_vmx_outside_smx::is_enabled());
    CHECK(intel_x64::msrs::ia32_feature_control::lock_bit::is_enabled());
}

TEST_CASE("vmxon: start_check_ia32_feature_control_msr_locked")
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager_x64>();

    setup_intrinsics(mocks, mm);

    intel_x64::msrs::ia32_feature_control::lock_bit::enable();

    vmxon_intel_x64 vmxon{};
    CHECK_NOTHROW(vmxon.start());
}

TEST_CASE("vmxon: start_check_ia32_vmx_cr0_fixed0_msr")
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager_x64>();

    setup_intrinsics(mocks, mm);

    g_msrs[intel_x64::msrs::ia32_vmx_cr0_fixed0::addr] = 0x1;

    vmxon_intel_x64 vmxon{};
    CHECK_THROWS(vmxon.start());
}

TEST_CASE("vmxon: start_check_ia32_vmx_cr0_fixed1_msr")
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager_x64>();

    setup_intrinsics(mocks, mm);

    g_cr0 = 0x1;
    g_msrs[intel_x64::msrs::ia32_vmx_cr0_fixed1::addr] = 0xFFFFFFFFFFFFFFF0;

    vmxon_intel_x64 vmxon{};
    CHECK_THROWS(vmxon.start());
}

TEST_CASE("vmxon: start_check_vmx_capabilities_msr_memtype_failure")
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager_x64>();

    setup_intrinsics(mocks, mm);

    g_msrs[intel_x64::msrs::ia32_vmx_basic::addr] = (1ULL << 55);

    vmxon_intel_x64 vmxon{};
    CHECK_THROWS(vmxon.start());
}

TEST_CASE("vmxon: start_check_vmx_capabilities_msr_addr_width_failure")
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager_x64>();

    setup_intrinsics(mocks, mm);

    g_msrs[intel_x64::msrs::ia32_vmx_basic::addr] = (1ULL << 55) | (6ULL << 50) | (1ULL << 48);

    vmxon_intel_x64 vmxon{};
    CHECK_THROWS(vmxon.start());
}

TEST_CASE("vmxon: start_check_vmx_capabilities_true_based_controls_failure")
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager_x64>();

    setup_intrinsics(mocks, mm);

    g_msrs[intel_x64::msrs::ia32_vmx_basic::addr] = (6ULL << 50);

    vmxon_intel_x64 vmxon{};
    CHECK_THROWS(vmxon.start());
}

TEST_CASE("vmxon: start_check_cpuid_vmx_supported_failure")
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager_x64>();

    setup_intrinsics(mocks, mm);

    g_cpuid[intel_x64::cpuid::feature_information::addr] = 0;

    vmxon_intel_x64 vmxon{};
    CHECK_THROWS(vmxon.start());
}

TEST_CASE("vmxon: start_virt_to_phys_failure")
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager_x64>();

    setup_intrinsics(mocks, mm);

    auto ___ = gsl::finally([&]
    { g_virt_to_phys_return_nullptr = false; });

    g_virt_to_phys_return_nullptr = true;

    vmxon_intel_x64 vmxon{};
    CHECK_THROWS(vmxon.start());
}

TEST_CASE("vmxon: stop_success")
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager_x64>();

    setup_intrinsics(mocks, mm);

    vmxon_intel_x64 vmxon{};

    vmxon.start();
    CHECK_NOTHROW(vmxon.stop());
}

TEST_CASE("vmxon: stop_stop_twice")
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager_x64>();

    setup_intrinsics(mocks, mm);

    vmxon_intel_x64 vmxon{};

    vmxon.start();
    CHECK_NOTHROW(vmxon.stop());
    CHECK_NOTHROW(vmxon.stop());
}

TEST_CASE("vmxon: stop_vmxoff_check_failure")
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager_x64>();

    setup_intrinsics(mocks, mm);

    vmxon_intel_x64 vmxon{};
    vmxon.start();

    g_write_cr4_fails = true;

    auto ___ = gsl::finally([&]
    { g_write_cr4_fails = false; });

    CHECK_NOTHROW(vmxon.stop());
}

TEST_CASE("vmxon: stop_vmxoff_failure")
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager_x64>();

    setup_intrinsics(mocks, mm);

    auto ___ = gsl::finally([&]
    { g_vmxoff_fails = false; });

    vmxon_intel_x64 vmxon{};
    vmxon.start();

    g_vmxoff_fails = true;
    CHECK_THROWS(vmxon.stop());
}

#endif
