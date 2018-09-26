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

// TIDY_EXCLUSION=-misc-unused-raii
//
// Reason:
//     In this test, we create objects just to make sure that they do not
//     throw during construction, so this test is a false positive
//

#include <catch/catch.hpp>
#include <test/support.h>

TEST_CASE("vmx: start_success")
{
    setup_test_support();
    CHECK_NOTHROW(bfvmm::intel_x64::vmx{});
}

TEST_CASE("vmx: start_execute_vmxon_failure")
{
    setup_test_support();

    g_vmxon_fails = true;
    auto ___ = gsl::finally([&] {
        g_vmxon_fails = false;
    });

    CHECK_THROWS(bfvmm::intel_x64::vmx{});
}

TEST_CASE("vmx: reset")
{
    setup_test_support();

    ::intel_x64::cr4::vmx_enable_bit::enable();
    auto ___ = gsl::finally([&] {
        ::intel_x64::cr4::vmx_enable_bit::disable();
    });

    CHECK_NOTHROW(bfvmm::intel_x64::vmx{});
}

TEST_CASE("vmx: start_check_ia32_vmx_cr4_fixed0_msr_failure")
{
    setup_test_support();

    g_msrs[intel_x64::msrs::ia32_vmx_cr4_fixed0::addr] = 0x1;
    CHECK_THROWS(bfvmm::intel_x64::vmx{});
}

TEST_CASE("vmx: start_check_ia32_vmx_cr4_fixed1_msr_failure")
{
    setup_test_support();

    g_cr4 = 0x1;
    g_msrs[intel_x64::msrs::ia32_vmx_cr4_fixed1::addr] = 0xFFFFFFFFFFFFFFF0;

    CHECK_THROWS(bfvmm::intel_x64::vmx{});
}

TEST_CASE("vmx: start_enable_vmx_operation_failure")
{
    setup_test_support();

    g_write_cr4_fails = true;
    auto ___ = gsl::finally([&] {
        g_write_cr4_fails = false;
    });

    CHECK_THROWS(bfvmm::intel_x64::vmx{});
}

TEST_CASE("vmx: start_v8086_disabled_failure")
{
    setup_test_support();

    g_rflags = 0xFFFFFFFFFFFFFFFF;
    CHECK_THROWS(bfvmm::intel_x64::vmx{});
}

TEST_CASE("vmx: start_check_ia32_feature_control_msr_unlocked")
{
    setup_test_support();

    g_msrs[intel_x64::msrs::ia32_feature_control::addr] = 0;

    CHECK_NOTHROW(bfvmm::intel_x64::vmx{});
    CHECK(intel_x64::msrs::ia32_feature_control::enable_vmx_outside_smx::is_enabled());
    CHECK(intel_x64::msrs::ia32_feature_control::lock_bit::is_enabled());
}

TEST_CASE("vmx: start_check_ia32_feature_control_msr_locked")
{
    setup_test_support();

    intel_x64::msrs::ia32_feature_control::lock_bit::enable();
    CHECK_NOTHROW(bfvmm::intel_x64::vmx{});
}

TEST_CASE("vmx: start_check_ia32_vmx_cr0_fixed0_msr")
{
    setup_test_support();

    g_msrs[intel_x64::msrs::ia32_vmx_cr0_fixed0::addr] = 0x1;
    CHECK_THROWS(bfvmm::intel_x64::vmx{});
}

TEST_CASE("vmx: start_check_ia32_vmx_cr0_fixed1_msr")
{
    setup_test_support();

    g_cr0 = 0x1;
    g_msrs[intel_x64::msrs::ia32_vmx_cr0_fixed1::addr] = 0xFFFFFFFFFFFFFFF0;

    CHECK_THROWS(bfvmm::intel_x64::vmx{});
}

TEST_CASE("vmx: start_check_vmx_capabilities_msr_memtype_failure")
{
    setup_test_support();

    g_msrs[intel_x64::msrs::ia32_vmx_basic::addr] = (1ULL << 55);
    CHECK_THROWS(bfvmm::intel_x64::vmx{});
}

TEST_CASE("vmx: start_check_vmx_capabilities_msr_addr_width_failure")
{
    setup_test_support();

    g_msrs[intel_x64::msrs::ia32_vmx_basic::addr] = (1ULL << 55) | (6ULL << 50) | (1ULL << 48);
    CHECK_THROWS(bfvmm::intel_x64::vmx{});
}

TEST_CASE("vmx: start_check_vmx_capabilities_true_based_controls_failure")
{
    setup_test_support();

    g_msrs[intel_x64::msrs::ia32_vmx_basic::addr] = (6ULL << 50);
    CHECK_THROWS(bfvmm::intel_x64::vmx{});
}

TEST_CASE("vmx: start_check_cpuid_vmx_supported_failure")
{
    setup_test_support();

    g_ecx_cpuid[intel_x64::cpuid::feature_information::addr] = 0;
    CHECK_THROWS(bfvmm::intel_x64::vmx{});
}

TEST_CASE("vmx: stop_vmxoff_failure")
{
    setup_test_support();

    g_vmxoff_fails = true;
    auto ___ = gsl::finally([&] {
        g_vmxoff_fails = false;
    });

    bfvmm::intel_x64::vmx{};
    CHECK(::intel_x64::cr4::vmx_enable_bit::is_enabled());
}
