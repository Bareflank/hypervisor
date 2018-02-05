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
setup_vmxon_tests(MockRepository &mocks)
{
    setup_msrs();
    setup_cpuid();
    setup_registers();

    return setup_mm(mocks);
}

TEST_CASE("vmxon: start_success")
{
    MockRepository mocks;
    auto mm = setup_vmxon_tests(mocks);

    vmxon_intel_x64 vmxon{};
    CHECK_NOTHROW(vmxon.start());
}

TEST_CASE("vmxon: start_start_twice")
{
    MockRepository mocks;
    auto mm = setup_vmxon_tests(mocks);

    vmxon_intel_x64 vmxon{};

    CHECK_NOTHROW(vmxon.start());
    g_cr4 = 0;
    CHECK_THROWS(vmxon.start());
}

TEST_CASE("vmxon: start_execute_vmxon_failure")
{
    MockRepository mocks;
    auto mm = setup_vmxon_tests(mocks);

    g_vmxon_fails = true;
    auto ___ = gsl::finally([&] {
        g_vmxon_fails = false;
    });

    vmxon_intel_x64 vmxon{};
    CHECK_THROWS(vmxon.start());
}

TEST_CASE("vmxon: start_check_ia32_vmx_cr4_fixed0_msr_failure")
{
    MockRepository mocks;
    auto mm = setup_vmxon_tests(mocks);

    g_msrs[intel_x64::msrs::ia32_vmx_cr4_fixed0::addr] = 0x1;

    vmxon_intel_x64 vmxon{};
    CHECK_THROWS(vmxon.start());
}

TEST_CASE("vmxon: start_check_ia32_vmx_cr4_fixed1_msr_failure")
{
    MockRepository mocks;
    auto mm = setup_vmxon_tests(mocks);

    g_cr4 = 0x1;
    g_msrs[intel_x64::msrs::ia32_vmx_cr4_fixed1::addr] = 0xFFFFFFFFFFFFFFF0;

    vmxon_intel_x64 vmxon{};
    CHECK_THROWS(vmxon.start());
}

TEST_CASE("vmxon: start_enable_vmx_operation_failure")
{
    MockRepository mocks;
    auto mm = setup_vmxon_tests(mocks);

    g_write_cr4_fails = true;
    auto ___ = gsl::finally([&] {
        g_write_cr4_fails = false;
    });

    vmxon_intel_x64 vmxon{};
    CHECK_THROWS(vmxon.start());
}

TEST_CASE("vmxon: start_v8086_disabled_failure")
{
    MockRepository mocks;
    auto mm = setup_vmxon_tests(mocks);

    g_rflags = 0xFFFFFFFFFFFFFFFF;

    vmxon_intel_x64 vmxon{};
    CHECK_THROWS(vmxon.start());
}

TEST_CASE("vmxon: start_check_ia32_feature_control_msr_unlocked")
{
    MockRepository mocks;
    auto mm = setup_vmxon_tests(mocks);

    g_msrs[intel_x64::msrs::ia32_feature_control::addr] = 0;

    vmxon_intel_x64 vmxon{};
    CHECK_NOTHROW(vmxon.start());

    CHECK(intel_x64::msrs::ia32_feature_control::enable_vmx_outside_smx::is_enabled());
    CHECK(intel_x64::msrs::ia32_feature_control::lock_bit::is_enabled());
}

TEST_CASE("vmxon: start_check_ia32_feature_control_msr_locked")
{
    MockRepository mocks;
    auto mm = setup_vmxon_tests(mocks);

    intel_x64::msrs::ia32_feature_control::lock_bit::enable();

    vmxon_intel_x64 vmxon{};
    CHECK_NOTHROW(vmxon.start());
}

TEST_CASE("vmxon: start_check_ia32_vmx_cr0_fixed0_msr")
{
    MockRepository mocks;
    auto mm = setup_vmxon_tests(mocks);

    g_msrs[intel_x64::msrs::ia32_vmx_cr0_fixed0::addr] = 0x1;

    vmxon_intel_x64 vmxon{};
    CHECK_THROWS(vmxon.start());
}

TEST_CASE("vmxon: start_check_ia32_vmx_cr0_fixed1_msr")
{
    MockRepository mocks;
    auto mm = setup_vmxon_tests(mocks);

    g_cr0 = 0x1;
    g_msrs[intel_x64::msrs::ia32_vmx_cr0_fixed1::addr] = 0xFFFFFFFFFFFFFFF0;

    vmxon_intel_x64 vmxon{};
    CHECK_THROWS(vmxon.start());
}

TEST_CASE("vmxon: start_check_vmx_capabilities_msr_memtype_failure")
{
    MockRepository mocks;
    auto mm = setup_vmxon_tests(mocks);

    g_msrs[intel_x64::msrs::ia32_vmx_basic::addr] = (1ULL << 55);

    vmxon_intel_x64 vmxon{};
    CHECK_THROWS(vmxon.start());
}

TEST_CASE("vmxon: start_check_vmx_capabilities_msr_addr_width_failure")
{
    MockRepository mocks;
    auto mm = setup_vmxon_tests(mocks);

    g_msrs[intel_x64::msrs::ia32_vmx_basic::addr] = (1ULL << 55) | (6ULL << 50) | (1ULL << 48);

    vmxon_intel_x64 vmxon{};
    CHECK_THROWS(vmxon.start());
}

TEST_CASE("vmxon: start_check_vmx_capabilities_true_based_controls_failure")
{
    MockRepository mocks;
    auto mm = setup_vmxon_tests(mocks);

    g_msrs[intel_x64::msrs::ia32_vmx_basic::addr] = (6ULL << 50);

    vmxon_intel_x64 vmxon{};
    CHECK_THROWS(vmxon.start());
}

TEST_CASE("vmxon: start_check_cpuid_vmx_supported_failure")
{
    MockRepository mocks;
    auto mm = setup_vmxon_tests(mocks);

    g_ecx_cpuid[intel_x64::cpuid::feature_information::addr] = 0;

    vmxon_intel_x64 vmxon{};
    CHECK_THROWS(vmxon.start());
}

TEST_CASE("vmxon: start_virt_to_phys_failure")
{
    MockRepository mocks;
    auto mm = setup_vmxon_tests(mocks);

    g_virt_to_phys_fails = true;
    auto ___ = gsl::finally([&] {
        g_virt_to_phys_fails = false;
    });

    vmxon_intel_x64 vmxon{};
    CHECK_THROWS(vmxon.start());
}

TEST_CASE("vmxon: stop_success")
{
    MockRepository mocks;
    auto mm = setup_vmxon_tests(mocks);

    vmxon_intel_x64 vmxon{};

    vmxon.start();
    CHECK_NOTHROW(vmxon.stop());
}

TEST_CASE("vmxon: stop_stop_twice")
{
    MockRepository mocks;
    auto mm = setup_vmxon_tests(mocks);

    vmxon_intel_x64 vmxon{};

    vmxon.start();
    CHECK_NOTHROW(vmxon.stop());
    CHECK_NOTHROW(vmxon.stop());
}

TEST_CASE("vmxon: stop_vmxoff_check_failure")
{
    MockRepository mocks;
    auto mm = setup_vmxon_tests(mocks);

    vmxon_intel_x64 vmxon{};
    vmxon.start();

    g_write_cr4_fails = true;
    auto ___ = gsl::finally([&] {
        g_write_cr4_fails = false;
    });

    CHECK_NOTHROW(vmxon.stop());
}

TEST_CASE("vmxon: stop_vmxoff_failure")
{
    MockRepository mocks;
    auto mm = setup_vmxon_tests(mocks);

    g_vmxoff_fails = true;
    auto ___ = gsl::finally([&] {
        g_vmxoff_fails = false;
    });

    vmxon_intel_x64 vmxon{};
    vmxon.start();

    CHECK_THROWS(vmxon.stop());
}

#endif
