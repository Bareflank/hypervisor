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

#include <catch/catch.hpp>
#include <hippomocks.h>

#include <test/support.h>

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

TEST_CASE("wrmsr_debug_ctrl")
{
    setup_test_support();

    emulate_wrmsr(::intel_x64::msrs::ia32_debugctl::addr, 42);
    CHECK(g_vmcs_fields[vmcs_n::guest_ia32_debugctl::addr] == 42);
}

TEST_CASE("wrmsr_pat")
{
    setup_test_support();

    emulate_wrmsr(::x64::msrs::ia32_pat::addr, 42);
    CHECK(g_vmcs_fields[vmcs_n::guest_ia32_pat::addr] == 42);
}

TEST_CASE("wrmsr_efer")
{
    setup_test_support();

    emulate_wrmsr(::intel_x64::msrs::ia32_efer::addr, 42);
    CHECK(g_vmcs_fields[vmcs_n::guest_ia32_efer::addr] == 42);
}

TEST_CASE("wrmsr_perf")
{
    setup_test_support();

    emulate_wrmsr(::intel_x64::msrs::ia32_perf_global_ctrl::addr, 42);
    CHECK(g_vmcs_fields[vmcs_n::guest_ia32_perf_global_ctrl::addr] == 42);
}

TEST_CASE("wrmsr_cs")
{
    setup_test_support();

    emulate_wrmsr(::intel_x64::msrs::ia32_sysenter_cs::addr, 42);
    CHECK(g_vmcs_fields[vmcs_n::guest_ia32_sysenter_cs::addr] == 42);
}

TEST_CASE("wrmsr_esp")
{
    setup_test_support();

    emulate_wrmsr(::intel_x64::msrs::ia32_sysenter_esp::addr, 42);
    CHECK(g_vmcs_fields[vmcs_n::guest_ia32_sysenter_esp::addr] == 42);
}

TEST_CASE("wrmsr_eip")
{
    setup_test_support();

    emulate_wrmsr(::intel_x64::msrs::ia32_sysenter_eip::addr, 42);
    CHECK(g_vmcs_fields[vmcs_n::guest_ia32_sysenter_eip::addr] == 42);
}

TEST_CASE("wrmsr_fs_base")
{
    setup_test_support();

    emulate_wrmsr(::intel_x64::msrs::ia32_fs_base::addr, 42);
    CHECK(g_vmcs_fields[vmcs_n::guest_fs_base::addr] == 42);
}

TEST_CASE("wrmsr_gs_base")
{
    setup_test_support();

    emulate_wrmsr(::intel_x64::msrs::ia32_gs_base::addr, 42);
    CHECK(g_vmcs_fields[vmcs_n::guest_gs_base::addr] == 42);
}

TEST_CASE("wrmsr_default")
{
    setup_test_support();

    emulate_wrmsr(0x10, 42);
    CHECK(g_msrs[0x10] == 42);
}

#endif
