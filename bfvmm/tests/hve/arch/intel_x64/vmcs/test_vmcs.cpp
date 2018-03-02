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
setup_vmcs(MockRepository &mocks)
{
    setup_msrs();
    setup_mm(mocks);
    setup_pt(mocks);

    return bfvmm::intel_x64::vmcs{0x0};
}

TEST_CASE("vmcs: construct / destruct")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks);

    CHECK_NOTHROW(bfvmm::intel_x64::vmcs{0});
}

TEST_CASE("vmcs: launch demote success")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks);

    CHECK_NOTHROW(vmcs.launch());
}

TEST_CASE("vmcs: launch demote failure")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks);

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
    setup_vmcs(mocks);

    mocks.OnCallFunc(bfvmm::intel_x64::check::all);
    mocks.OnCallFunc(::intel_x64::vmcs::debug::dump);

    bfvmm::intel_x64::vmcs vmcs{0xF0000000};
    CHECK_THROWS(vmcs.launch());
}

TEST_CASE("vmcs: load failure")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks);

    g_vmload_fails = true;
    auto ___ = gsl::finally([&] {
        g_vmload_fails = false;
    });

    CHECK_THROWS(vmcs.load());
}

TEST_CASE("vmcs: promote failure")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks);

    CHECK_THROWS(vmcs.promote());
}

TEST_CASE("vmcs: resume failure")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks);

    CHECK_THROWS(vmcs.resume());
}

TEST_CASE("vmcs: save state")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks);

    CHECK(vmcs.save_state() != nullptr);
}

#endif
