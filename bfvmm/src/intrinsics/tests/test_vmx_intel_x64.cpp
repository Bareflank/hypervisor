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
#include <intrinsics/x86/intel_x64.h>

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

TEST_CASE("test name goes here")
{
    CHECK(true);
}

using namespace intel_x64;

uintptr_t g_region = 0;
std::map<vm::field_type, vm::value_type> g_vmcs;

bool g_vmxon_fails = false;
bool g_vmxoff_fails = false;
bool g_vmclear_fails = false;
bool g_vmload_fails = false;
bool g_vmreset_fails = false;
bool g_vmread_fails = false;
bool g_vmwrite_fails = false;
bool g_vmlaunch_fails = false;
bool g_invept_fails = false;
bool g_invvpid_fails = false;

bool
test_vmxon(void *ptr) noexcept
{ (void)ptr; return !g_vmxon_fails; }

bool
test_vmxoff() noexcept
{ return !g_vmxoff_fails; }

bool
test_vmclear(void *ptr) noexcept
{ (void)ptr; return !g_vmclear_fails; }

bool
test_vmptrld(void *ptr) noexcept
{ (void)ptr; return !g_vmload_fails; }

bool
test_vmptrst(void *ptr) noexcept
{ (void)ptr; return !g_vmreset_fails; }

bool
test_vmread(uint64_t field, uint64_t *val) noexcept
{
    if (g_vmread_fails) {
        return false;
    }

    *val = g_vmcs[field];

    return true;
}

bool
test_vmwrite(uint64_t field, uint64_t val) noexcept
{
    if (g_vmwrite_fails) {
        return false;
    }

    g_vmcs[field] = val;

    return true;
}

bool
test_vmlaunch_demote() noexcept
{ return !g_vmlaunch_fails; }

bool
test_invept(uint64_t type, void *ptr) noexcept
{ (void) type; (void) ptr; return !g_invept_fails; }

bool
test_invvpid(uint64_t type, void *ptr) noexcept
{ (void) type; (void) ptr; return !g_invvpid_fails; }

static void
setup_intrinsics(MockRepository &mocks)
{
    mocks.OnCallFunc(_vmxon).Do(test_vmxon);
    mocks.OnCallFunc(_vmxoff).Do(test_vmxoff);
    mocks.OnCallFunc(_vmclear).Do(test_vmclear);
    mocks.OnCallFunc(_vmptrld).Do(test_vmptrld);
    mocks.OnCallFunc(_vmptrst).Do(test_vmptrst);
    mocks.OnCallFunc(_vmread).Do(test_vmread);
    mocks.OnCallFunc(_vmwrite).Do(test_vmwrite);
    mocks.OnCallFunc(_vmlaunch_demote).Do(test_vmlaunch_demote);
    mocks.OnCallFunc(_invept).Do(test_invept);
    mocks.OnCallFunc(_invvpid).Do(test_invvpid);
}

TEST_CASE("vmx_intel_x64_vmxon_nullptr")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    void *invalid_ptr = nullptr;
    CHECK_THROWS(vmx::on(invalid_ptr));
}

TEST_CASE("vmx_intel_x64_vmxon_failure")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    auto ___ = gsl::finally([&]
    { g_vmxon_fails = false; });

    g_vmxon_fails = true;
    CHECK_THROWS(vmx::on(&g_region));
}

TEST_CASE("vmx_intel_x64_vmxon_success")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK_NOTHROW(vmx::on(&g_region));
}

TEST_CASE("vmx_intel_x64_vmxoff_failure")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    auto ___ = gsl::finally([&]
    { g_vmxoff_fails = false; });

    g_vmxoff_fails = true;
    CHECK_THROWS(vmx::off());
}

TEST_CASE("vmx_intel_x64_vmxoff_success")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK_NOTHROW(vmx::off());
}

TEST_CASE("vmx_intel_x64_vmclear_nullptr")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    void *invalid_ptr = nullptr;
    CHECK_THROWS(vm::clear(invalid_ptr));
}

TEST_CASE("vmx_intel_x64_vmclear_failure")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    auto ___ = gsl::finally([&]
    { g_vmclear_fails = false; });

    g_vmclear_fails = true;
    CHECK_THROWS(vm::clear(&g_region));
}

TEST_CASE("vmx_intel_x64_vmclear_success")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK_NOTHROW(vm::clear(&g_region));
}

TEST_CASE("vmx_intel_x64_vmload_nullptr")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    void *invalid_ptr = nullptr;
    CHECK_THROWS(vm::load(invalid_ptr));
}

TEST_CASE("vmx_intel_x64_vmload_failure")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    auto ___ = gsl::finally([&]
    { g_vmload_fails = false; });

    g_vmload_fails = true;
    CHECK_THROWS(vm::load(&g_region));
}

TEST_CASE("vmx_intel_x64_vmload_success")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK_NOTHROW(vm::load(&g_region));
}

TEST_CASE("vmx_intel_x64_vmreset_nullptr")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    void *invalid_ptr = nullptr;
    CHECK_THROWS(vm::reset(invalid_ptr));
}

TEST_CASE("vmx_intel_x64_vmreset_failure")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    auto ___ = gsl::finally([&]
    { g_vmreset_fails = false; });

    g_vmreset_fails = true;
    CHECK_THROWS(vm::reset(&g_region));
}

TEST_CASE("vmx_intel_x64_vmreset_success")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK_NOTHROW(vm::reset(&g_region));
}

TEST_CASE("vmx_intel_x64_vmread_failure")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    auto ___ = gsl::finally([&]
    { g_vmread_fails = false; });

    g_vmread_fails = true;
    CHECK_THROWS(vm::read(10U));
}

TEST_CASE("vmx_intel_x64_vmwrite_failure")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    auto ___ = gsl::finally([&]
    { g_vmwrite_fails = false; });

    g_vmwrite_fails = true;
    CHECK_THROWS(vm::write(10U, 10U));
}

TEST_CASE("vmx_intel_x64_vmread_vmwrite_succcess")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    auto val = 10ULL;

    CHECK_NOTHROW(vm::write(10U, val));
    CHECK_NOTHROW(val = vm::read(10U));
    CHECK(val == 10UL);
}

TEST_CASE("vmx_intel_x64_vmlaunch_demote_success")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK_NOTHROW(vm::launch_demote());
}

TEST_CASE("vmx_intel_x64_vmlaunch_demote_failure")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    auto ___ = gsl::finally([&]
    { g_vmlaunch_fails = false; });

    g_vmlaunch_fails = true;
    CHECK_THROWS(vm::launch_demote());
}

TEST_CASE("vmx_intel_x64_invept")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK_NOTHROW(vmx::invept_single_context(0));
    CHECK_NOTHROW(vmx::invept_global());

    auto ___ = gsl::finally([&]
    { g_invept_fails = false; });

    g_invept_fails = true;
    CHECK_THROWS(vmx::invept_single_context(0));
    CHECK_THROWS(vmx::invept_global());
}

TEST_CASE("vmx_intel_x64_invvpid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK_NOTHROW(vmx::invvpid_individual_address(0, 0));
    CHECK_NOTHROW(vmx::invvpid_single_context(0));
    CHECK_NOTHROW(vmx::invvpid_all_contexts());
    CHECK_NOTHROW(vmx::invvpid_single_context_global(0));

    auto ___ = gsl::finally([&]
    { g_invvpid_fails = false; });

    g_invvpid_fails = true;
    CHECK_THROWS(vmx::invvpid_individual_address(0, 0));
    CHECK_THROWS(vmx::invvpid_single_context(0));
    CHECK_THROWS(vmx::invvpid_all_contexts());
    CHECK_THROWS(vmx::invvpid_single_context_global(0));
}

#endif
