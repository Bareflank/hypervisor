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

#include <map>
#include <intrinsics.h>

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

extern "C" bool
_vmxon(void *ptr) noexcept
{ (void)ptr; return !g_vmxon_fails; }

extern "C" bool
_vmxoff() noexcept
{ return !g_vmxoff_fails; }

extern "C" bool
_vmclear(void *ptr) noexcept
{ (void)ptr; return !g_vmclear_fails; }

extern "C" bool
_vmptrld(void *ptr) noexcept
{ (void)ptr; return !g_vmload_fails; }

extern "C" bool
_vmptrst(void *ptr) noexcept
{ (void)ptr; return !g_vmreset_fails; }

extern "C" bool
_vmread(uint64_t field, uint64_t *value) noexcept
{
    if (g_vmread_fails) {
        return false;
    }

    *value = g_vmcs[field];

    return true;
}

extern "C" bool
_vmwrite(uint64_t field, uint64_t value) noexcept
{
    if (g_vmwrite_fails) {
        return false;
    }

    g_vmcs[field] = value;

    return true;
}

extern "C" bool
_vmlaunch_demote() noexcept
{ return !g_vmlaunch_fails; }

extern "C" bool
_invept(uint64_t type, void *ptr) noexcept
{ (void) type; (void) ptr; return !g_invept_fails; }

extern "C" bool
_invvpid(uint64_t type, void *ptr) noexcept
{ (void) type; (void) ptr; return !g_invvpid_fails; }

TEST_CASE("vmx_intel_x64_vmxon_nullptr")
{
    void *invalid_ptr = nullptr;
    CHECK_THROWS(vmx::on(invalid_ptr));
}

TEST_CASE("vmx_intel_x64_vmxon_failure")
{
    auto ___ = gsl::finally([&]
    { g_vmxon_fails = false; });

    g_vmxon_fails = true;
    CHECK_THROWS(vmx::on(&g_region));
}

TEST_CASE("vmx_intel_x64_vmxon_success")
{
    CHECK_NOTHROW(vmx::on(&g_region));
}

TEST_CASE("vmx_intel_x64_vmxoff_failure")
{
    auto ___ = gsl::finally([&]
    { g_vmxoff_fails = false; });

    g_vmxoff_fails = true;
    CHECK_THROWS(vmx::off());
}

TEST_CASE("vmx_intel_x64_vmxoff_success")
{
    CHECK_NOTHROW(vmx::off());
}

TEST_CASE("vmx_intel_x64_vmclear_nullptr")
{
    void *invalid_ptr = nullptr;
    CHECK_THROWS(vm::clear(invalid_ptr));
}

TEST_CASE("vmx_intel_x64_vmclear_failure")
{
    auto ___ = gsl::finally([&]
    { g_vmclear_fails = false; });

    g_vmclear_fails = true;
    CHECK_THROWS(vm::clear(&g_region));
}

TEST_CASE("vmx_intel_x64_vmclear_success")
{
    CHECK_NOTHROW(vm::clear(&g_region));
}

TEST_CASE("vmx_intel_x64_vmload_nullptr")
{
    void *invalid_ptr = nullptr;
    CHECK_THROWS(vm::load(invalid_ptr));
}

TEST_CASE("vmx_intel_x64_vmload_failure")
{
    auto ___ = gsl::finally([&]
    { g_vmload_fails = false; });

    g_vmload_fails = true;
    CHECK_THROWS(vm::load(&g_region));
}

TEST_CASE("vmx_intel_x64_vmload_success")
{
    CHECK_NOTHROW(vm::load(&g_region));
}

TEST_CASE("vmx_intel_x64_vmreset_nullptr")
{
    void *invalid_ptr = nullptr;
    CHECK_THROWS(vm::reset(invalid_ptr));
}

TEST_CASE("vmx_intel_x64_vmreset_failure")
{
    auto ___ = gsl::finally([&]
    { g_vmreset_fails = false; });

    g_vmreset_fails = true;
    CHECK_THROWS(vm::reset(&g_region));
}

TEST_CASE("vmx_intel_x64_vmreset_success")
{
    CHECK_NOTHROW(vm::reset(&g_region));
}

TEST_CASE("vmx_intel_x64_vmread_failure")
{
    auto ___ = gsl::finally([&]
    { g_vmread_fails = false; });

    g_vmread_fails = true;
    CHECK_THROWS(vm::read(10U));
}

TEST_CASE("vmx_intel_x64_vmwrite_failure")
{
    auto ___ = gsl::finally([&]
    { g_vmwrite_fails = false; });

    g_vmwrite_fails = true;
    CHECK_THROWS(vm::write(10U, 10U));
}

TEST_CASE("vmx_intel_x64_vmread_vmwrite_succcess")
{
    auto val = 10ULL;

    CHECK_NOTHROW(vm::write(10U, val));
    CHECK_NOTHROW(val = vm::read(10U));
    CHECK(val == 10UL);
}

TEST_CASE("vmx_intel_x64_vmlaunch_demote_success")
{
    CHECK_NOTHROW(vm::launch_demote());
}

TEST_CASE("vmx_intel_x64_vmlaunch_demote_failure")
{
    auto ___ = gsl::finally([&]
    { g_vmlaunch_fails = false; });

    g_vmlaunch_fails = true;
    CHECK_THROWS(vm::launch_demote());
}

TEST_CASE("vmx_intel_x64_invept")
{
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
