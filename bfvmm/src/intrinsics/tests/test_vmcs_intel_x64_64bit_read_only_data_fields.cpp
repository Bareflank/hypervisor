//
// Bareflank Hypervisor
//
// Copyright (C) 2015 Assured Information Security, Inc.
// Author: Rian Quinn        <quinnr@ainfosec.com>
// Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
// Author: Connor Davis      <davisc@ainfosec.com>
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
#include <intrinsics/x86/common_x64.h>
#include <test/vmcs_utils.h>

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

using namespace intel_x64;

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

TEST_CASE("test name goes here")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(true);
}

TEST_CASE("vmcs_guest_physical_address")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] =
        msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask << 32;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = msrs::ia32_vmx_procbased_ctls2::enable_ept::mask <<
            32;
    CHECK(vmcs::guest_physical_address::exists());

    g_vmcs_fields[vmcs::guest_physical_address::addr] = 0x1U;
    CHECK(vmcs::guest_physical_address::get() == 0x1U);

    g_vmcs_fields[vmcs::guest_physical_address::addr] = 0x2U;
    CHECK(vmcs::guest_physical_address::get_if_exists() == 0x2U);

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = ~(msrs::ia32_vmx_procbased_ctls2::enable_ept::mask <<
            32);
    CHECK_FALSE(vmcs::guest_physical_address::exists());
    CHECK_THROWS(vmcs::guest_physical_address::get());
    CHECK_NOTHROW(vmcs::guest_physical_address::get_if_exists());
}

#endif
