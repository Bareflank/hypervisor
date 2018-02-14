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

#include <support/arch/intel_x64/test_support.h>

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

auto
setup_vmx_tests(MockRepository &mocks)
{
    setup_msrs();
    setup_cpuid();
    setup_registers();

    return setup_mm(mocks);
}

TEST_CASE("vmx: start_success")
{
    MockRepository mocks;
    auto mm = setup_vmx_tests(mocks);

    CHECK_NOTHROW(bfvmm::intel_x64::vmx{});
}

TEST_CASE("vmx: start_execute_vmxon_failure")
{
    MockRepository mocks;
    auto mm = setup_vmx_tests(mocks);

    g_vmxon_fails = true;
    auto ___ = gsl::finally([&] {
        g_vmxon_fails = false;
    });

    CHECK_THROWS(bfvmm::intel_x64::vmx{});
}

TEST_CASE("vmx: start_check_ia32_vmx_cr4_fixed0_msr_failure")
{
    MockRepository mocks;
    auto mm = setup_vmx_tests(mocks);

    g_msrs[intel_x64::msrs::ia32_vmx_cr4_fixed0::addr] = 0x1;
    CHECK_THROWS(bfvmm::intel_x64::vmx{});
}

TEST_CASE("vmx: start_check_ia32_vmx_cr4_fixed1_msr_failure")
{
    MockRepository mocks;
    auto mm = setup_vmx_tests(mocks);

    g_cr4 = 0x1;
    g_msrs[intel_x64::msrs::ia32_vmx_cr4_fixed1::addr] = 0xFFFFFFFFFFFFFFF0;

    CHECK_THROWS(bfvmm::intel_x64::vmx{});
}

TEST_CASE("vmx: start_enable_vmx_operation_failure")
{
    MockRepository mocks;
    auto mm = setup_vmx_tests(mocks);

    g_write_cr4_fails = true;
    auto ___ = gsl::finally([&] {
        g_write_cr4_fails = false;
    });

    CHECK_THROWS(bfvmm::intel_x64::vmx{});
}

TEST_CASE("vmx: start_v8086_disabled_failure")
{
    MockRepository mocks;
    auto mm = setup_vmx_tests(mocks);

    g_rflags = 0xFFFFFFFFFFFFFFFF;
    CHECK_THROWS(bfvmm::intel_x64::vmx{});
}

TEST_CASE("vmx: start_check_ia32_feature_control_msr_unlocked")
{
    MockRepository mocks;
    auto mm = setup_vmx_tests(mocks);

    g_msrs[intel_x64::msrs::ia32_feature_control::addr] = 0;

    CHECK_NOTHROW(bfvmm::intel_x64::vmx{});
    CHECK(intel_x64::msrs::ia32_feature_control::enable_vmx_outside_smx::is_enabled());
    CHECK(intel_x64::msrs::ia32_feature_control::lock_bit::is_enabled());
}

TEST_CASE("vmx: start_check_ia32_feature_control_msr_locked")
{
    MockRepository mocks;
    auto mm = setup_vmx_tests(mocks);

    intel_x64::msrs::ia32_feature_control::lock_bit::enable();
    CHECK_NOTHROW(bfvmm::intel_x64::vmx{});
}

TEST_CASE("vmx: start_check_ia32_vmx_cr0_fixed0_msr")
{
    MockRepository mocks;
    auto mm = setup_vmx_tests(mocks);

    g_msrs[intel_x64::msrs::ia32_vmx_cr0_fixed0::addr] = 0x1;
    CHECK_THROWS(bfvmm::intel_x64::vmx{});
}

TEST_CASE("vmx: start_check_ia32_vmx_cr0_fixed1_msr")
{
    MockRepository mocks;
    auto mm = setup_vmx_tests(mocks);

    g_cr0 = 0x1;
    g_msrs[intel_x64::msrs::ia32_vmx_cr0_fixed1::addr] = 0xFFFFFFFFFFFFFFF0;

    CHECK_THROWS(bfvmm::intel_x64::vmx{});
}

TEST_CASE("vmx: start_check_vmx_capabilities_msr_memtype_failure")
{
    MockRepository mocks;
    auto mm = setup_vmx_tests(mocks);

    g_msrs[intel_x64::msrs::ia32_vmx_basic::addr] = (1ULL << 55);
    CHECK_THROWS(bfvmm::intel_x64::vmx{});
}

TEST_CASE("vmx: start_check_vmx_capabilities_msr_addr_width_failure")
{
    MockRepository mocks;
    auto mm = setup_vmx_tests(mocks);

    g_msrs[intel_x64::msrs::ia32_vmx_basic::addr] = (1ULL << 55) | (6ULL << 50) | (1ULL << 48);
    CHECK_THROWS(bfvmm::intel_x64::vmx{});
}

TEST_CASE("vmx: start_check_vmx_capabilities_true_based_controls_failure")
{
    MockRepository mocks;
    auto mm = setup_vmx_tests(mocks);

    g_msrs[intel_x64::msrs::ia32_vmx_basic::addr] = (6ULL << 50);
    CHECK_THROWS(bfvmm::intel_x64::vmx{});
}

TEST_CASE("vmx: start_check_cpuid_vmx_supported_failure")
{
    MockRepository mocks;
    auto mm = setup_vmx_tests(mocks);

    g_ecx_cpuid[intel_x64::cpuid::feature_information::addr] = 0;
    CHECK_THROWS(bfvmm::intel_x64::vmx{});
}

TEST_CASE("vmx: start_virt_to_phys_failure")
{
    MockRepository mocks;
    auto mm = setup_vmx_tests(mocks);

    g_virt_to_phys_fails = true;
    auto ___ = gsl::finally([&] {
        g_virt_to_phys_fails = false;
    });

    CHECK_THROWS(bfvmm::intel_x64::vmx{});
}

TEST_CASE("vmx: stop_vmxoff_failure")
{
    MockRepository mocks;
    auto mm = setup_vmx_tests(mocks);

    g_vmxoff_fails = true;
    auto ___ = gsl::finally([&] {
        g_vmxoff_fails = false;
    });

    bfvmm::intel_x64::vmx{};
    CHECK(::intel_x64::cr4::vmx_enable_bit::is_enabled());
}

#endif
