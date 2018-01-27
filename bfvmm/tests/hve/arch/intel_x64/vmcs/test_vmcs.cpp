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

TEST_CASE("vmcs: launch_success")
{
    MockRepository mocks;
    auto mm = setup_mm(mocks);
    auto host_state = setup_vmcs_state(mocks);
    auto guest_state = setup_vmcs_state(mocks);

    setup_msrs();

    vmcs_intel_x64 vmcs{};
    CHECK_NOTHROW(vmcs.launch(host_state, guest_state));
}

TEST_CASE("vmcs: launch_vmlaunch_failure")
{
    MockRepository mocks;
    auto mm = setup_mm(mocks);
    auto host_state = setup_vmcs_state(mocks);
    auto guest_state = setup_vmcs_state(mocks);

    setup_msrs();

    mocks.OnCall(guest_state, vmcs_intel_x64_state::is_guest).Return(true);
    mocks.OnCallFunc(vmcs_launch);

    vmcs_intel_x64 vmcs{};
    CHECK_THROWS(vmcs.launch(host_state, guest_state));
}

TEST_CASE("vmcs: launch_vmlaunch_demote_failure")
{
    MockRepository mocks;
    auto mm = setup_mm(mocks);
    auto host_state = setup_vmcs_state(mocks);
    auto guest_state = setup_vmcs_state(mocks);

    setup_msrs();

    mocks.OnCallFunc(check::all);
    mocks.OnCallFunc(debug::dump);
    mocks.OnCall(guest_state, vmcs_intel_x64_state::is_guest).Return(false);

    g_vmlaunch_fails = true;
    auto ___ = gsl::finally([&] {
        g_vmlaunch_fails = false;
    });

    vmcs_intel_x64 vmcs{};
    CHECK_THROWS(vmcs.launch(host_state, guest_state));
}

TEST_CASE("vmcs: launch_create_vmcs_region_failure")
{
    MockRepository mocks;
    auto mm = setup_mm(mocks);
    auto host_state = setup_vmcs_state(mocks);
    auto guest_state = setup_vmcs_state(mocks);

    setup_msrs();

    g_virt_to_phys_fails = true;
    auto ___ = gsl::finally([&] {
        g_virt_to_phys_fails = false;
    });

    vmcs_intel_x64 vmcs{};
    CHECK_THROWS(vmcs.launch(host_state, guest_state));
}

TEST_CASE("vmcs: launch_create_exit_handler_stack_failure")
{
    MockRepository mocks;
    auto mm = setup_mm(mocks);
    auto host_state = setup_vmcs_state(mocks);
    auto guest_state = setup_vmcs_state(mocks);

    setup_msrs();

    g_new_throws_bad_alloc = STACK_SIZE * 2;
    auto ___ = gsl::finally([&] {
        g_new_throws_bad_alloc = 0;
    });

    vmcs_intel_x64 vmcs{};
    CHECK_THROWS(vmcs.launch(host_state, guest_state));
}

TEST_CASE("vmcs: launch_clear_failure")
{
    MockRepository mocks;
    auto mm = setup_mm(mocks);

    setup_msrs();

    g_vmclear_fails = true;
    auto ___ = gsl::finally([&] {
        g_vmclear_fails = false;
    });

    vmcs_intel_x64 vmcs{};
    CHECK_THROWS(vmcs.clear());
}

TEST_CASE("vmcs: launch_load_failure")
{
    MockRepository mocks;
    auto mm = setup_mm(mocks);

    setup_msrs();

    g_vmload_fails = true;
    auto ___ = gsl::finally([&] {
        g_vmload_fails = false;
    });

    vmcs_intel_x64 vmcs{};
    CHECK_THROWS(vmcs.load());
}

TEST_CASE("vmcs: promote_failure")
{
    MockRepository mocks;
    auto mm = setup_mm(mocks);

    mocks.OnCallFunc(vmcs_promote);

    vmcs_intel_x64 vmcs{};
    CHECK_THROWS(vmcs.promote(reinterpret_cast<char *>(0x1000UL)));
}

TEST_CASE("vmcs: resume_failure")
{
    MockRepository mocks;
    auto mm = setup_mm(mocks);

    mocks.OnCallFunc(vmcs_resume);

    vmcs_intel_x64 vmcs{};
    CHECK_THROWS(vmcs.resume());
}

TEST_CASE("vmcs: clear")
{
    vmcs_intel_x64 vmcs{};
    CHECK_NOTHROW(vmcs.clear());
}

TEST_CASE("vmcs: set_pre_launch_delegate")
{
    vmcs_intel_x64::pre_launch_delegate_t d;

    vmcs_intel_x64 vmcs{};
    CHECK_NOTHROW(vmcs.set_pre_launch_delegate(d));
}

TEST_CASE("vmcs: set_post_launch_delegate")
{
    vmcs_intel_x64::post_launch_delegate_t d;

    vmcs_intel_x64 vmcs{};
    CHECK_NOTHROW(vmcs.set_post_launch_delegate(d));
}

#endif
