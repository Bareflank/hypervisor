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

#include <catch/catch.hpp>
#include <hippomocks.h>
#include <intrinsics/x86/common_x64.h>
#include <intrinsics/x86/intel_x64.h>

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

TEST_CASE("test name goes here")
{
    CHECK(true);
}

using namespace intel_x64;
using namespace msrs;
using namespace vmcs;
using namespace debug;

std::map<uint32_t, uint64_t> g_msrs;
std::map<uint64_t, uint64_t> g_vmcs_fields;

uint64_t
test_read_msr(uint32_t addr) noexcept
{ return g_msrs[addr]; }

static bool
test_vmread(uint64_t field, uint64_t *val) noexcept
{
    *val = g_vmcs_fields[field];
    return true;
}

static void
setup_intrinsics(MockRepository &mocks)
{
    mocks.OnCallFunc(_read_msr).Do(test_read_msr);
    mocks.OnCallFunc(_vmread).Do(test_vmread);
}

void
proc_ctl_allow1(uint64_t mask)
{ g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] |= mask << 32; }

void
proc_ctl_disallow1(uint64_t mask)
{ g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] &= ~(mask << 32); }

TEST_CASE("debug_dump")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    proc_ctl_disallow1(msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
    CHECK_THROWS(dump());

    proc_ctl_allow1(msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
    CHECK_NOTHROW(dump());
}

#endif
