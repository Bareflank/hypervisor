//
// Copyright (C) 2019 Assured Information Security, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

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
    auto vmx = bfvmm::intel_x64::vmx{};
    CHECK_NOTHROW(vmx.enable());
}

TEST_CASE("vmx: start_execute_vmxon_failure")
{
    setup_test_support();

    g_vmxon_fails = true;
    auto ___ = gsl::finally([&] {
        g_vmxon_fails = false;
    });
    auto vmx = bfvmm::intel_x64::vmx{};
    CHECK_THROWS(vmx.enable());
}

TEST_CASE("vmx: reset")
{
    setup_test_support();

    ::intel_x64::cr4::vmx_enable_bit::enable();
    auto ___ = gsl::finally([&] {
        ::intel_x64::cr4::vmx_enable_bit::disable();
    });

    auto vmx = bfvmm::intel_x64::vmx{};
    CHECK_NOTHROW(vmx.enable());
}

TEST_CASE("vmx: start_check_ia32_vmx_cr4_fixed0_msr_failure")
{
    setup_test_support();

    g_msrs[intel_x64::msrs::ia32_vmx_cr4_fixed0::addr] = 0x1;
    auto vmx = bfvmm::intel_x64::vmx{};
    CHECK_THROWS(vmx.enable());
}

TEST_CASE("vmx: start_check_ia32_vmx_cr4_fixed1_msr_failure")
{
    setup_test_support();

    g_cr4 = 0x1;
    g_msrs[intel_x64::msrs::ia32_vmx_cr4_fixed1::addr] = 0xFFFFFFFFFFFFFFF0;

    auto vmx = bfvmm::intel_x64::vmx{};
    CHECK_THROWS(vmx.enable());
}

TEST_CASE("vmx: start_enable_vmx_operation_failure")
{
    setup_test_support();

    g_write_cr4_fails = true;
    auto ___ = gsl::finally([&] {
        g_write_cr4_fails = false;
    });

    auto vmx = bfvmm::intel_x64::vmx{};
    CHECK_THROWS(vmx.enable());
}

TEST_CASE("vmx: start_v8086_disabled_failure")
{
    setup_test_support();

    g_rflags = 0xFFFFFFFFFFFFFFFF;
    auto vmx = bfvmm::intel_x64::vmx{};
    CHECK_THROWS(vmx.enable());
}

TEST_CASE("vmx: start_check_ia32_feature_control_msr_unlocked")
{
    setup_test_support();

    g_msrs[intel_x64::msrs::ia32_feature_control::addr] = 0;

    auto vmx = bfvmm::intel_x64::vmx{};
    CHECK_NOTHROW(vmx.enable());
    CHECK(intel_x64::msrs::ia32_feature_control::enable_vmx_outside_smx::is_enabled());
    CHECK(intel_x64::msrs::ia32_feature_control::lock_bit::is_enabled());
}

TEST_CASE("vmx: start_check_ia32_feature_control_msr_locked")
{
    setup_test_support();

    intel_x64::msrs::ia32_feature_control::lock_bit::enable();
    auto vmx = bfvmm::intel_x64::vmx{};
    CHECK_NOTHROW(vmx.enable());
}

TEST_CASE("vmx: start_check_ia32_vmx_cr0_fixed0_msr")
{
    setup_test_support();

    g_msrs[intel_x64::msrs::ia32_vmx_cr0_fixed0::addr] = 0x1;
    auto vmx = bfvmm::intel_x64::vmx{};
    CHECK_THROWS(vmx.enable());
}

TEST_CASE("vmx: start_check_ia32_vmx_cr0_fixed1_msr")
{
    setup_test_support();

    g_cr0 = 0x1;
    g_msrs[intel_x64::msrs::ia32_vmx_cr0_fixed1::addr] = 0xFFFFFFFFFFFFFFF0;

    auto vmx = bfvmm::intel_x64::vmx{};
    CHECK_THROWS(vmx.enable());
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

    auto vmx = bfvmm::intel_x64::vmx{};
    vmx.enable();
    CHECK(::intel_x64::cr4::vmx_enable_bit::is_enabled());
}
