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

static bool
test_vmwrite(uint64_t field, uint64_t val) noexcept
{
    g_vmcs_fields[field] = val;
    return true;
}

static void
setup_intrinsics(MockRepository &mocks)
{
    mocks.OnCallFunc(_read_msr).Do(test_read_msr);
    mocks.OnCallFunc(_vmread).Do(test_vmread);
    mocks.OnCallFunc(_vmwrite).Do(test_vmwrite);
}

TEST_CASE("test name goes here")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(true);
}

TEST_CASE("vmcs_virtual_processor_identifier")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::virtual_processor_identifier;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask << 32;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = msrs::ia32_vmx_procbased_ctls2::enable_vpid::mask << 32;
    CHECK(exists());

    set(100UL);
    CHECK(get() == 100UL);

    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0x0;
    CHECK_FALSE(exists());
    CHECK_THROWS(set(1UL));
    CHECK_THROWS(get());
    CHECK_NOTHROW(set_if_exists(1UL));
    CHECK_NOTHROW(get_if_exists());

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = msrs::ia32_vmx_procbased_ctls2::enable_vpid::mask << 32;
    CHECK(get() == 200UL);

    dump(0);
}

TEST_CASE("vmcs_posted_interrupt_notification_vector")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::posted_interrupt_notification_vector;

    g_msrs[msrs::ia32_vmx_true_pinbased_ctls::addr] =
        msrs::ia32_vmx_true_pinbased_ctls::process_posted_interrupts::mask << 32;
    CHECK(exists());

    set(100UL);
    CHECK(get() == 100UL);

    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    g_msrs[msrs::ia32_vmx_true_pinbased_ctls::addr] = 0x0;
    CHECK_FALSE(exists());

    dump(0);
}

TEST_CASE("vmcs_eptp_index")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::eptp_index;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] =
        msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask << 32;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] =
        msrs::ia32_vmx_procbased_ctls2::ept_violation_ve::mask << 32;
    CHECK(exists());

    set(100UL);
    CHECK(get() == 100UL);

    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0x0;
    CHECK_FALSE(exists());
    CHECK_THROWS(set(1UL));
    CHECK_THROWS(get());
    CHECK_NOTHROW(set_if_exists(1UL));
    CHECK_NOTHROW(get_if_exists());

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] =
        msrs::ia32_vmx_procbased_ctls2::ept_violation_ve::mask << 32;
    CHECK(get() == 200UL);

    dump(0);
}

#endif
