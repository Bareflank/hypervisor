//
// Bareflank Hypervisor
//
// Copyright (C) 2015 Assured Information Security, Inc.
// Author: Rian Quinn        <quinnr@ainfosec.com>
// Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
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

#include <test.h>
#include <intrinsics/vmx_intel_x64.h>

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
__vmxon(void *ptr) noexcept
{ (void)ptr; return !g_vmxon_fails; }

extern "C" bool
__vmxoff(void) noexcept
{ return !g_vmxoff_fails; }

extern "C" bool
__vmclear(void *ptr) noexcept
{ (void)ptr; return !g_vmclear_fails; }

extern "C" bool
__vmptrld(void *ptr) noexcept
{ (void)ptr; return !g_vmload_fails; }

extern "C" bool
__vmptrst(void *ptr) noexcept
{ (void)ptr; return !g_vmreset_fails; }

extern "C" bool
__vmread(uint64_t field, uint64_t *val) noexcept
{
    if (g_vmread_fails)
        return false;

    *val = g_vmcs[field];

    return true;
}

extern "C" bool
__vmwrite(uint64_t field, uint64_t val) noexcept
{
    if (g_vmwrite_fails)
        return false;

    g_vmcs[field] = val;

    return true;
}

extern "C" bool
__vmlaunch(uint64_t arg1, uint64_t arg2) noexcept
{ (void)arg1; (void)arg2; return !g_vmlaunch_fails; }

extern "C" bool
__vmlaunch_demote(void) noexcept
{ return !g_vmlaunch_fails; }

extern "C" bool
__invept(uint64_t type, void *ptr) noexcept
{ (void) type; (void) ptr; return !g_invept_fails; }

extern "C" bool
__invvpid(uint64_t type, void *ptr) noexcept
{ (void) type; (void) ptr; return !g_invvpid_fails; }

void
intrinsics_ut::test_vmx_intel_x64_vmxon_nullptr()
{
    void *invalid_ptr = nullptr;
    this->expect_exception([&] { vmx::on(invalid_ptr); }, ""_ut_ffe);
}

void
intrinsics_ut::test_vmx_intel_x64_vmxon_failure()
{
    auto ___ = gsl::finally([&]
    { g_vmxon_fails = false; });

    g_vmxon_fails = true;
    this->expect_exception([&] { vmx::on(&g_region); }, ""_ut_ree);
}

void
intrinsics_ut::test_vmx_intel_x64_vmxon_success()
{
    this->expect_no_exception([&] { vmx::on(&g_region); });
}

void
intrinsics_ut::test_vmx_intel_x64_vmxoff_failure()
{
    auto ___ = gsl::finally([&]
    { g_vmxoff_fails = false; });

    g_vmxoff_fails = true;
    this->expect_exception([&] { vmx::off(); }, ""_ut_ree);
}

void
intrinsics_ut::test_vmx_intel_x64_vmxoff_success()
{
    this->expect_no_exception([&] { vmx::off(); });
}

void
intrinsics_ut::test_vmx_intel_x64_vmclear_nullptr()
{
    void *invalid_ptr = nullptr;
    this->expect_exception([&] { vm::clear(invalid_ptr); }, ""_ut_ffe);
}

void
intrinsics_ut::test_vmx_intel_x64_vmclear_failure()
{
    auto ___ = gsl::finally([&]
    { g_vmclear_fails = false; });

    g_vmclear_fails = true;
    this->expect_exception([&] { vm::clear(&g_region); }, ""_ut_ree);
}

void
intrinsics_ut::test_vmx_intel_x64_vmclear_success()
{
    this->expect_no_exception([&] { vm::clear(&g_region); });
}

void
intrinsics_ut::test_vmx_intel_x64_vmload_nullptr()
{
    void *invalid_ptr = nullptr;
    this->expect_exception([&] { vm::load(invalid_ptr); }, ""_ut_ffe);
}

void
intrinsics_ut::test_vmx_intel_x64_vmload_failure()
{
    auto ___ = gsl::finally([&]
    { g_vmload_fails = false; });

    g_vmload_fails = true;
    this->expect_exception([&] { vm::load(&g_region); }, ""_ut_ree);
}

void
intrinsics_ut::test_vmx_intel_x64_vmload_success()
{
    this->expect_no_exception([&] { vm::load(&g_region); });
}

void
intrinsics_ut::test_vmx_intel_x64_vmreset_nullptr()
{
    void *invalid_ptr = nullptr;
    this->expect_exception([&] { vm::reset(invalid_ptr); }, ""_ut_ffe);
}

void
intrinsics_ut::test_vmx_intel_x64_vmreset_failure()
{
    auto ___ = gsl::finally([&]
    { g_vmreset_fails = false; });

    g_vmreset_fails = true;
    this->expect_exception([&] { vm::reset(&g_region); }, ""_ut_ree);
}

void
intrinsics_ut::test_vmx_intel_x64_vmreset_success()
{
    this->expect_no_exception([&] { vm::reset(&g_region); });
}

void
intrinsics_ut::test_vmx_intel_x64_vmread_failure()
{
    auto ___ = gsl::finally([&]
    { g_vmread_fails = false; });

    g_vmread_fails = true;
    this->expect_exception([&] { vm::read(10U); }, ""_ut_ree);
}

void
intrinsics_ut::test_vmx_intel_x64_vmwrite_failure()
{
    auto ___ = gsl::finally([&]
    { g_vmwrite_fails = false; });

    g_vmwrite_fails = true;
    this->expect_exception([&] { vm::write(10U, 10U); }, ""_ut_ree);
}

void
intrinsics_ut::test_vmx_intel_x64_vmread_vmwrite_succcess()
{
    auto val = 10UL;

    this->expect_no_exception([&] { vm::write(10U, val); });
    this->expect_no_exception([&] { val = vm::read(10U); });
    this->expect_true(val == 10UL);
}

void
intrinsics_ut::test_vmx_intel_x64_vmlaunch_failure()
{
    auto ___ = gsl::finally([&]
    { g_vmlaunch_fails = false; });

    g_vmlaunch_fails = true;
    this->expect_exception([&] { vm::launch(0, 0); }, ""_ut_ree);
}

void
intrinsics_ut::test_vmx_intel_x64_vmlaunch_demote_success()
{
    this->expect_no_exception([&] { vm::launch_demote(); });
}

void
intrinsics_ut::test_vmx_intel_x64_vmlaunch_demote_failure()
{
    auto ___ = gsl::finally([&]
    { g_vmlaunch_fails = false; });

    g_vmlaunch_fails = true;
    this->expect_exception([&] { vm::launch_demote(); }, ""_ut_ree);
}

void
intrinsics_ut::test_vmx_intel_x64_vmlaunch_success()
{
    this->expect_no_exception([&] { vm::launch(0, 0); });
}

void
intrinsics_ut::test_vmx_intel_x64_invept()
{
    this->expect_no_exception([&] { vmx::invept_single_context(0); });
    this->expect_no_exception([&] { vmx::invept_global(); });

    auto ___ = gsl::finally([&]
    { g_invept_fails = false; });

    g_invept_fails = true;
    this->expect_exception([&] { vmx::invept_single_context(0); }, ""_ut_ree);
    this->expect_exception([&] { vmx::invept_global(); }, ""_ut_ree);
}

void
intrinsics_ut::test_vmx_intel_x64_invvpid()
{
    this->expect_no_exception([&] { vmx::invvpid_individual_address(0, 0); });
    this->expect_no_exception([&] { vmx::invvpid_single_context(0); });
    this->expect_no_exception([&] { vmx::invvpid_all_contexts(); });
    this->expect_no_exception([&] { vmx::invvpid_single_context_global(0); });

    auto ___ = gsl::finally([&]
    { g_invvpid_fails = false; });

    g_invvpid_fails = true;
    this->expect_exception([&] { vmx::invvpid_individual_address(0, 0); }, ""_ut_ree);
    this->expect_exception([&] { vmx::invvpid_single_context(0); }, ""_ut_ree);
    this->expect_exception([&] { vmx::invvpid_all_contexts(); }, ""_ut_ree);
    this->expect_exception([&] { vmx::invvpid_single_context_global(0); }, ""_ut_ree);
}
