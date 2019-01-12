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

auto
setup_vmcs()
{
    setup_test_support();
    return bfvmm::intel_x64::vmcs{0x0};
}

TEST_CASE("vmcs: construct / destruct")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs();

    CHECK_NOTHROW(bfvmm::intel_x64::vmcs{0});
}

TEST_CASE("vmcs: launch demote success")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs();

    CHECK_NOTHROW(vmcs.launch());
}

TEST_CASE("vmcs: launch demote failure")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs();

    mocks.OnCallFunc(bfvmm::intel_x64::check::all);
    mocks.OnCallFunc(::intel_x64::vmcs::debug::dump);

    g_vmlaunch_fails = true;
    auto ___ = gsl::finally([&] {
        g_vmlaunch_fails = false;
    });

    CHECK_THROWS(vmcs.launch());
}

TEST_CASE("vmcs: launch failure")
{
    MockRepository mocks;
    setup_vmcs();

    mocks.OnCallFunc(bfvmm::intel_x64::check::all);
    mocks.OnCallFunc(::intel_x64::vmcs::debug::dump);

    bfvmm::intel_x64::vmcs vmcs{0xF0000000};
    CHECK_THROWS(vmcs.launch());
}

TEST_CASE("vmcs: load failure")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs();

    g_vmload_fails = true;
    auto ___ = gsl::finally([&] {
        g_vmload_fails = false;
    });

    CHECK_THROWS(vmcs.load());
}

TEST_CASE("vmcs: promote failure")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs();

    ::intel_x64::vmcs::guest_cr3::set(0x1000);
    CHECK_THROWS(vmcs.promote());
}

TEST_CASE("vmcs: resume failure")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs();

    CHECK_THROWS(vmcs.resume());
}

TEST_CASE("vmcs: save state")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs();

    CHECK(vmcs.save_state() != nullptr);
}

#endif
