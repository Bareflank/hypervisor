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

TEST_CASE("vmcs_host_ia32_pat")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::mask <<
            32;
    CHECK(vmcs::host_ia32_pat::exists());

    vmcs::host_ia32_pat::set(1UL);
    CHECK(vmcs::host_ia32_pat::get() == 1UL);

    vmcs::host_ia32_pat::set_if_exists(0UL);
    CHECK(vmcs::host_ia32_pat::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_host_ia32_pat_pa0")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::mask <<
            32;

    vmcs::host_ia32_pat::pa0::set(1UL);
    CHECK(vmcs::host_ia32_pat::pa0::get() == 1UL);

    vmcs::host_ia32_pat::pa0::set_if_exists(0UL);
    CHECK(vmcs::host_ia32_pat::pa0::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_host_ia32_pat_pa0_memory_type")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::host_ia32_pat;
    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::mask <<
            32;

    pa0::memory_type::set(x64::memory_type::uncacheable);
    CHECK(pa0::memory_type::get() == x64::memory_type::uncacheable);

    pa0::memory_type::set(x64::memory_type::write_combining);
    CHECK(pa0::memory_type::get() == x64::memory_type::write_combining);

    pa0::memory_type::set(x64::memory_type::write_through);
    CHECK(pa0::memory_type::get() == x64::memory_type::write_through);

    pa0::memory_type::set_if_exists(x64::memory_type::write_protected);
    CHECK(pa0::memory_type::get_if_exists() == x64::memory_type::write_protected);

    pa0::memory_type::set_if_exists(x64::memory_type::write_back);
    CHECK(pa0::memory_type::get_if_exists() == x64::memory_type::write_back);

    pa0::memory_type::set_if_exists(x64::memory_type::uncacheable_minus);
    CHECK(pa0::memory_type::get_if_exists() == x64::memory_type::uncacheable_minus);
}

TEST_CASE("vmcs_host_ia32_pat_pa0_reserved")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::mask <<
            32;

    vmcs::host_ia32_pat::pa0::reserved::set(1UL);
    CHECK(vmcs::host_ia32_pat::pa0::reserved::get() == 1UL);

    vmcs::host_ia32_pat::pa0::reserved::set_if_exists(0UL);
    CHECK(vmcs::host_ia32_pat::pa0::reserved::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_host_ia32_pat_pa1")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::mask <<
            32;

    vmcs::host_ia32_pat::pa1::set(1UL);
    CHECK(vmcs::host_ia32_pat::pa1::get() == 1UL);

    vmcs::host_ia32_pat::pa1::set_if_exists(0UL);
    CHECK(vmcs::host_ia32_pat::pa1::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_host_ia32_pat_pa1_memory_type")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::host_ia32_pat;
    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::mask <<
            32;

    pa1::memory_type::set(x64::memory_type::uncacheable);
    CHECK(pa1::memory_type::get() == x64::memory_type::uncacheable);

    pa1::memory_type::set(x64::memory_type::write_combining);
    CHECK(pa1::memory_type::get() == x64::memory_type::write_combining);

    pa1::memory_type::set(x64::memory_type::write_through);
    CHECK(pa1::memory_type::get() == x64::memory_type::write_through);

    pa1::memory_type::set_if_exists(x64::memory_type::write_protected);
    CHECK(pa1::memory_type::get_if_exists() == x64::memory_type::write_protected);

    pa1::memory_type::set_if_exists(x64::memory_type::write_back);
    CHECK(pa1::memory_type::get_if_exists() == x64::memory_type::write_back);

    pa1::memory_type::set_if_exists(x64::memory_type::uncacheable_minus);
    CHECK(pa1::memory_type::get_if_exists() == x64::memory_type::uncacheable_minus);
}

TEST_CASE("vmcs_host_ia32_pat_pa1_reserved")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::mask <<
            32;

    vmcs::host_ia32_pat::pa1::reserved::set(1UL);
    CHECK(vmcs::host_ia32_pat::pa1::reserved::get() == 1UL);

    vmcs::host_ia32_pat::pa1::reserved::set_if_exists(0UL);
    CHECK(vmcs::host_ia32_pat::pa1::reserved::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_host_ia32_pat_pa2")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::mask <<
            32;

    vmcs::host_ia32_pat::pa2::set(1UL);
    CHECK(vmcs::host_ia32_pat::pa2::get() == 1UL);

    vmcs::host_ia32_pat::pa2::set_if_exists(0UL);
    CHECK(vmcs::host_ia32_pat::pa2::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_host_ia32_pat_pa2_memory_type")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::host_ia32_pat;
    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::mask <<
            32;

    pa2::memory_type::set(x64::memory_type::uncacheable);
    CHECK(pa2::memory_type::get() == x64::memory_type::uncacheable);

    pa2::memory_type::set(x64::memory_type::write_combining);
    CHECK(pa2::memory_type::get() == x64::memory_type::write_combining);

    pa2::memory_type::set(x64::memory_type::write_through);
    CHECK(pa2::memory_type::get() == x64::memory_type::write_through);

    pa2::memory_type::set_if_exists(x64::memory_type::write_protected);
    CHECK(pa2::memory_type::get_if_exists() == x64::memory_type::write_protected);

    pa2::memory_type::set_if_exists(x64::memory_type::write_back);
    CHECK(pa2::memory_type::get_if_exists() == x64::memory_type::write_back);

    pa2::memory_type::set_if_exists(x64::memory_type::uncacheable_minus);
    CHECK(pa2::memory_type::get_if_exists() == x64::memory_type::uncacheable_minus);
}

TEST_CASE("vmcs_host_ia32_pat_pa2_reserved")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::mask <<
            32;

    vmcs::host_ia32_pat::pa2::reserved::set(1UL);
    CHECK(vmcs::host_ia32_pat::pa2::reserved::get() == 1UL);

    vmcs::host_ia32_pat::pa2::reserved::set_if_exists(0UL);
    CHECK(vmcs::host_ia32_pat::pa2::reserved::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_host_ia32_pat_pa3")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::mask <<
            32;

    vmcs::host_ia32_pat::pa3::set(1UL);
    CHECK(vmcs::host_ia32_pat::pa3::get() == 1UL);

    vmcs::host_ia32_pat::pa3::set_if_exists(0UL);
    CHECK(vmcs::host_ia32_pat::pa3::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_host_ia32_pat_pa3_memory_type")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::host_ia32_pat;
    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::mask <<
            32;

    pa3::memory_type::set(x64::memory_type::uncacheable);
    CHECK(pa3::memory_type::get() == x64::memory_type::uncacheable);

    pa3::memory_type::set(x64::memory_type::write_combining);
    CHECK(pa3::memory_type::get() == x64::memory_type::write_combining);

    pa3::memory_type::set(x64::memory_type::write_through);
    CHECK(pa3::memory_type::get() == x64::memory_type::write_through);

    pa3::memory_type::set_if_exists(x64::memory_type::write_protected);
    CHECK(pa3::memory_type::get_if_exists() == x64::memory_type::write_protected);

    pa3::memory_type::set_if_exists(x64::memory_type::write_back);
    CHECK(pa3::memory_type::get_if_exists() == x64::memory_type::write_back);

    pa3::memory_type::set_if_exists(x64::memory_type::uncacheable_minus);
    CHECK(pa3::memory_type::get_if_exists() == x64::memory_type::uncacheable_minus);
}

TEST_CASE("vmcs_host_ia32_pat_pa3_reserved")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::mask <<
            32;

    vmcs::host_ia32_pat::pa3::reserved::set(1UL);
    CHECK(vmcs::host_ia32_pat::pa3::reserved::get() == 1UL);

    vmcs::host_ia32_pat::pa3::reserved::set_if_exists(0UL);
    CHECK(vmcs::host_ia32_pat::pa3::reserved::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_host_ia32_pat_pa4")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::mask <<
            32;

    vmcs::host_ia32_pat::pa4::set(1UL);
    CHECK(vmcs::host_ia32_pat::pa4::get() == 1UL);

    vmcs::host_ia32_pat::pa4::set_if_exists(0UL);
    CHECK(vmcs::host_ia32_pat::pa4::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_host_ia32_pat_pa4_memory_type")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::host_ia32_pat;
    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::mask <<
            32;

    pa4::memory_type::set(x64::memory_type::uncacheable);
    CHECK(pa4::memory_type::get() == x64::memory_type::uncacheable);

    pa4::memory_type::set(x64::memory_type::write_combining);
    CHECK(pa4::memory_type::get() == x64::memory_type::write_combining);

    pa4::memory_type::set(x64::memory_type::write_through);
    CHECK(pa4::memory_type::get() == x64::memory_type::write_through);

    pa4::memory_type::set_if_exists(x64::memory_type::write_protected);
    CHECK(pa4::memory_type::get_if_exists() == x64::memory_type::write_protected);

    pa4::memory_type::set_if_exists(x64::memory_type::write_back);
    CHECK(pa4::memory_type::get_if_exists() == x64::memory_type::write_back);

    pa4::memory_type::set_if_exists(x64::memory_type::uncacheable_minus);
    CHECK(pa4::memory_type::get_if_exists() == x64::memory_type::uncacheable_minus);
}

TEST_CASE("vmcs_host_ia32_pat_pa4_reserved")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::mask <<
            32;

    vmcs::host_ia32_pat::pa4::reserved::set(1UL);
    CHECK(vmcs::host_ia32_pat::pa4::reserved::get() == 1UL);

    vmcs::host_ia32_pat::pa4::reserved::set_if_exists(0UL);
    CHECK(vmcs::host_ia32_pat::pa4::reserved::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_host_ia32_pat_pa5")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::mask <<
            32;

    vmcs::host_ia32_pat::pa5::set(1UL);
    CHECK(vmcs::host_ia32_pat::pa5::get() == 1UL);

    vmcs::host_ia32_pat::pa5::set_if_exists(0UL);
    CHECK(vmcs::host_ia32_pat::pa5::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_host_ia32_pat_pa5_memory_type")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::host_ia32_pat;
    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::mask <<
            32;

    pa5::memory_type::set(x64::memory_type::uncacheable);
    CHECK(pa5::memory_type::get() == x64::memory_type::uncacheable);

    pa5::memory_type::set(x64::memory_type::write_combining);
    CHECK(pa5::memory_type::get() == x64::memory_type::write_combining);

    pa5::memory_type::set(x64::memory_type::write_through);
    CHECK(pa5::memory_type::get() == x64::memory_type::write_through);

    pa5::memory_type::set_if_exists(x64::memory_type::write_protected);
    CHECK(pa5::memory_type::get_if_exists() == x64::memory_type::write_protected);

    pa5::memory_type::set_if_exists(x64::memory_type::write_back);
    CHECK(pa5::memory_type::get_if_exists() == x64::memory_type::write_back);

    pa5::memory_type::set_if_exists(x64::memory_type::uncacheable_minus);
    CHECK(pa5::memory_type::get_if_exists() == x64::memory_type::uncacheable_minus);
}

TEST_CASE("vmcs_host_ia32_pat_pa5_reserved")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::mask <<
            32;

    vmcs::host_ia32_pat::pa5::reserved::set(1UL);
    CHECK(vmcs::host_ia32_pat::pa5::reserved::get() == 1UL);

    vmcs::host_ia32_pat::pa5::reserved::set_if_exists(0UL);
    CHECK(vmcs::host_ia32_pat::pa5::reserved::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_host_ia32_pat_pa6")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::mask <<
            32;

    vmcs::host_ia32_pat::pa6::set(1UL);
    CHECK(vmcs::host_ia32_pat::pa6::get() == 1UL);

    vmcs::host_ia32_pat::pa6::set_if_exists(0UL);
    CHECK(vmcs::host_ia32_pat::pa6::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_host_ia32_pat_pa6_memory_type")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::host_ia32_pat;
    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::mask <<
            32;

    pa6::memory_type::set(x64::memory_type::uncacheable);
    CHECK(pa6::memory_type::get() == x64::memory_type::uncacheable);

    pa6::memory_type::set(x64::memory_type::write_combining);
    CHECK(pa6::memory_type::get() == x64::memory_type::write_combining);

    pa6::memory_type::set(x64::memory_type::write_through);
    CHECK(pa6::memory_type::get() == x64::memory_type::write_through);

    pa6::memory_type::set_if_exists(x64::memory_type::write_protected);
    CHECK(pa6::memory_type::get_if_exists() == x64::memory_type::write_protected);

    pa6::memory_type::set_if_exists(x64::memory_type::write_back);
    CHECK(pa6::memory_type::get_if_exists() == x64::memory_type::write_back);

    pa6::memory_type::set_if_exists(x64::memory_type::uncacheable_minus);
    CHECK(pa6::memory_type::get_if_exists() == x64::memory_type::uncacheable_minus);
}

TEST_CASE("vmcs_host_ia32_pat_pa6_reserved")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::mask <<
            32;

    vmcs::host_ia32_pat::pa6::reserved::set(1UL);
    CHECK(vmcs::host_ia32_pat::pa6::reserved::get() == 1UL);

    vmcs::host_ia32_pat::pa6::reserved::set_if_exists(0UL);
    CHECK(vmcs::host_ia32_pat::pa6::reserved::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_host_ia32_pat_pa7")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::mask <<
            32;

    vmcs::host_ia32_pat::pa7::set(1UL);
    CHECK(vmcs::host_ia32_pat::pa7::get() == 1UL);

    vmcs::host_ia32_pat::pa7::set_if_exists(0UL);
    CHECK(vmcs::host_ia32_pat::pa7::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_host_ia32_pat_pa7_memory_type")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::host_ia32_pat;
    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::mask <<
            32;

    pa7::memory_type::set(x64::memory_type::uncacheable);
    CHECK(pa7::memory_type::get() == x64::memory_type::uncacheable);

    pa7::memory_type::set(x64::memory_type::write_combining);
    CHECK(pa7::memory_type::get() == x64::memory_type::write_combining);

    pa7::memory_type::set(x64::memory_type::write_through);
    CHECK(pa7::memory_type::get() == x64::memory_type::write_through);

    pa7::memory_type::set_if_exists(x64::memory_type::write_protected);
    CHECK(pa7::memory_type::get_if_exists() == x64::memory_type::write_protected);

    pa7::memory_type::set_if_exists(x64::memory_type::write_back);
    CHECK(pa7::memory_type::get_if_exists() == x64::memory_type::write_back);

    pa7::memory_type::set_if_exists(x64::memory_type::uncacheable_minus);
    CHECK(pa7::memory_type::get_if_exists() == x64::memory_type::uncacheable_minus);
}

TEST_CASE("vmcs_host_ia32_pat_pa7_reserved")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::mask <<
            32;

    vmcs::host_ia32_pat::pa7::reserved::set(1UL);
    CHECK(vmcs::host_ia32_pat::pa7::reserved::get() == 1UL);

    vmcs::host_ia32_pat::pa7::reserved::set_if_exists(0UL);
    CHECK(vmcs::host_ia32_pat::pa7::reserved::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_host_ia32_efer")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_efer::mask
            << 32;
    CHECK(vmcs::host_ia32_efer::exists());

    vmcs::host_ia32_efer::set(1UL);
    CHECK(vmcs::host_ia32_efer::get() == 1UL);

    vmcs::host_ia32_efer::set_if_exists(0UL);
    CHECK(vmcs::host_ia32_efer::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_host_ia32_efer_sce")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_efer::mask
            << 32;

    vmcs::host_ia32_efer::sce::enable();
    CHECK(vmcs::host_ia32_efer::sce::is_enabled());

    vmcs::host_ia32_efer::sce::disable();
    CHECK(vmcs::host_ia32_efer::sce::is_disabled());

    vmcs::host_ia32_efer::sce::enable_if_exists();
    CHECK(vmcs::host_ia32_efer::sce::is_enabled_if_exists());

    vmcs::host_ia32_efer::sce::disable_if_exists();
    CHECK(vmcs::host_ia32_efer::sce::is_disabled_if_exists());
}

TEST_CASE("vmcs_host_ia32_efer_lme")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_efer::mask
            << 32;

    vmcs::host_ia32_efer::lme::enable();
    CHECK(vmcs::host_ia32_efer::lme::is_enabled());

    vmcs::host_ia32_efer::lme::disable();
    CHECK(vmcs::host_ia32_efer::lme::is_disabled());

    vmcs::host_ia32_efer::lme::enable_if_exists();
    CHECK(vmcs::host_ia32_efer::lme::is_enabled_if_exists());

    vmcs::host_ia32_efer::lme::disable_if_exists();
    CHECK(vmcs::host_ia32_efer::lme::is_disabled_if_exists());
}

TEST_CASE("vmcs_host_ia32_efer_lma")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_efer::mask
            << 32;

    vmcs::host_ia32_efer::lma::enable();
    CHECK(vmcs::host_ia32_efer::lma::is_enabled());

    vmcs::host_ia32_efer::lma::disable();
    CHECK(vmcs::host_ia32_efer::lma::is_disabled());

    vmcs::host_ia32_efer::lma::enable_if_exists();
    CHECK(vmcs::host_ia32_efer::lma::is_enabled_if_exists());

    vmcs::host_ia32_efer::lma::disable_if_exists();
    CHECK(vmcs::host_ia32_efer::lma::is_disabled_if_exists());
}

TEST_CASE("vmcs_host_ia32_efer_nxe")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_efer::mask
            << 32;

    vmcs::host_ia32_efer::nxe::enable();
    CHECK(vmcs::host_ia32_efer::nxe::is_enabled());

    vmcs::host_ia32_efer::nxe::disable();
    CHECK(vmcs::host_ia32_efer::nxe::is_disabled());

    vmcs::host_ia32_efer::nxe::enable_if_exists();
    CHECK(vmcs::host_ia32_efer::nxe::is_enabled_if_exists());

    vmcs::host_ia32_efer::nxe::disable_if_exists();
    CHECK(vmcs::host_ia32_efer::nxe::is_disabled_if_exists());
}

TEST_CASE("vmcs_host_ia32_efer_reserved")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_efer::mask
            << 32;

    vmcs::host_ia32_efer::reserved::set(0xEU);
    CHECK(vmcs::host_ia32_efer::reserved::get() == 0xEU);

    vmcs::host_ia32_efer::reserved::set_if_exists(0x0U);
    CHECK(vmcs::host_ia32_efer::reserved::get_if_exists() == 0x0U);
}

TEST_CASE("vmcs_host_ia32_perf_global_ctrl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |=
        msrs::ia32_vmx_true_exit_ctls::load_ia32_perf_global_ctrl::mask << 32;
    CHECK(vmcs::host_ia32_perf_global_ctrl::exists());

    vmcs::host_ia32_perf_global_ctrl::set(1UL);
    CHECK(vmcs::host_ia32_perf_global_ctrl::get() == 1UL);

    vmcs::host_ia32_perf_global_ctrl::set_if_exists(0UL);
    CHECK(vmcs::host_ia32_perf_global_ctrl::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_host_ia32_perf_global_ctrl_reserved")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |=
        msrs::ia32_vmx_true_exit_ctls::load_ia32_perf_global_ctrl::mask << 32;
    CHECK(vmcs::host_ia32_perf_global_ctrl::exists());

    vmcs::host_ia32_perf_global_ctrl::reserved::set(0xCUL);
    CHECK(vmcs::host_ia32_perf_global_ctrl::reserved::get() == 0xCUL);

    vmcs::host_ia32_perf_global_ctrl::reserved::set_if_exists(0UL);
    CHECK(vmcs::host_ia32_perf_global_ctrl::reserved::get_if_exists() == 0UL);
}

#endif
