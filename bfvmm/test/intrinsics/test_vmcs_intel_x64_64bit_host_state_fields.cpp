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

TEST_CASE("vmcs_host_ia32_pat")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::host_ia32_pat;

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::mask << 32;

    CHECK(exists());
    set(100UL);
    CHECK(get() == 100UL);
    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    dump(0);
}

TEST_CASE("vmcs_host_ia32_pat_pa0")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::host_ia32_pat;

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::mask
            << 32;

    pa0::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(pa0::get() == (pa0::mask >> pa0::from));

    pa0::set(pa0::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(pa0::get(pa0::mask) == (pa0::mask >> pa0::from));

    pa0::set_if_exists(0xFFFFFFFFFFFFFFFFULL);
    CHECK(pa0::get_if_exists() == (pa0::mask >> pa0::from));
}

TEST_CASE("vmcs_host_ia32_pat_pa0_memory_type")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::host_ia32_pat;
    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::mask
            << 32;

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

    pa0::memory_type::set(pa0::memory_type::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(pa0::memory_type::get(pa0::memory_type::mask) == (pa0::memory_type::mask >> pa0::memory_type::from));
}

TEST_CASE("vmcs_host_ia32_pat_pa0_reserved")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::host_ia32_pat;

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::mask
            << 32;

    pa0::reserved::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(pa0::reserved::get() == (pa0::reserved::mask >> pa0::reserved::from));

    pa0::reserved::set(pa0::reserved::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(pa0::reserved::get(pa0::reserved::mask) == (pa0::reserved::mask >> pa0::reserved::from));

    pa0::reserved::set_if_exists(0xFFFFFFFFFFFFFFFFULL);
    CHECK(pa0::reserved::get_if_exists() == (pa0::reserved::mask >> pa0::reserved::from));
}

TEST_CASE("vmcs_host_ia32_pat_pa1")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::host_ia32_pat;

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::mask
            << 32;

    pa1::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(pa1::get() == (pa1::mask >> pa1::from));

    pa1::set(pa1::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(pa1::get(pa1::mask) == (pa1::mask >> pa1::from));

    pa1::set_if_exists(0xFFFFFFFFFFFFFFFFULL);
    CHECK(pa1::get_if_exists() == (pa1::mask >> pa1::from));
}

TEST_CASE("vmcs_host_ia32_pat_pa1_memory_type")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::host_ia32_pat;
    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::mask
            << 32;

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

    pa1::memory_type::set(pa1::memory_type::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(pa1::memory_type::get(pa1::memory_type::mask) == (pa1::memory_type::mask >> pa1::memory_type::from));
}

TEST_CASE("vmcs_host_ia32_pat_pa1_reserved")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::host_ia32_pat;

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::mask
            << 32;

    pa1::reserved::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(pa1::reserved::get() == (pa1::reserved::mask >> pa1::reserved::from));

    pa1::reserved::set(pa1::reserved::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(pa1::reserved::get(pa1::reserved::mask) == (pa1::reserved::mask >> pa1::reserved::from));

    pa1::reserved::set_if_exists(0xFFFFFFFFFFFFFFFFULL);
    CHECK(pa1::reserved::get_if_exists() == (pa1::reserved::mask >> pa1::reserved::from));
}

TEST_CASE("vmcs_host_ia32_pat_pa2")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::host_ia32_pat;

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::mask
            << 32;

    pa2::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(pa2::get() == (pa2::mask >> pa2::from));

    pa2::set(pa2::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(pa2::get(pa2::mask) == (pa2::mask >> pa2::from));

    pa2::set_if_exists(0xFFFFFFFFFFFFFFFFULL);
    CHECK(pa2::get_if_exists() == (pa2::mask >> pa2::from));
}

TEST_CASE("vmcs_host_ia32_pat_pa2_memory_type")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::host_ia32_pat;
    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::mask
            << 32;

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

    pa2::memory_type::set(pa2::memory_type::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(pa2::memory_type::get(pa2::memory_type::mask) == (pa2::memory_type::mask >> pa2::memory_type::from));
}

TEST_CASE("vmcs_host_ia32_pat_pa2_reserved")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::host_ia32_pat;

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::mask
            << 32;

    pa2::reserved::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(pa2::reserved::get() == (pa2::reserved::mask >> pa2::reserved::from));

    pa2::reserved::set(pa2::reserved::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(pa2::reserved::get(pa2::reserved::mask) == (pa2::reserved::mask >> pa2::reserved::from));

    pa2::reserved::set_if_exists(0xFFFFFFFFFFFFFFFFULL);
    CHECK(pa2::reserved::get_if_exists() == (pa2::reserved::mask >> pa2::reserved::from));
}

TEST_CASE("vmcs_host_ia32_pat_pa3")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::host_ia32_pat;

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::mask
            << 32;

    pa3::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(pa3::get() == (pa3::mask >> pa3::from));

    pa3::set(pa3::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(pa3::get(pa3::mask) == (pa3::mask >> pa3::from));

    pa3::set_if_exists(0xFFFFFFFFFFFFFFFFULL);
    CHECK(pa3::get_if_exists() == (pa3::mask >> pa3::from));
}

TEST_CASE("vmcs_host_ia32_pat_pa3_memory_type")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::host_ia32_pat;
    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::mask
            << 32;

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

    pa3::memory_type::set(pa3::memory_type::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(pa3::memory_type::get(pa3::memory_type::mask) == (pa3::memory_type::mask >> pa3::memory_type::from));
}

TEST_CASE("vmcs_host_ia32_pat_pa3_reserved")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::host_ia32_pat;

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::mask
            << 32;

    pa3::reserved::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(pa3::reserved::get() == (pa3::reserved::mask >> pa3::reserved::from));

    pa3::reserved::set(pa3::reserved::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(pa3::reserved::get(pa3::reserved::mask) == (pa3::reserved::mask >> pa3::reserved::from));

    pa3::reserved::set_if_exists(0xFFFFFFFFFFFFFFFFULL);
    CHECK(pa3::reserved::get_if_exists() == (pa3::reserved::mask >> pa3::reserved::from));
}

TEST_CASE("vmcs_host_ia32_pat_pa4")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::host_ia32_pat;

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::mask
            << 32;

    pa4::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(pa4::get() == (pa4::mask >> pa4::from));

    pa4::set(pa4::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(pa4::get(pa4::mask) == (pa4::mask >> pa4::from));

    pa4::set_if_exists(0xFFFFFFFFFFFFFFFFULL);
    CHECK(pa4::get_if_exists() == (pa4::mask >> pa4::from));
}

TEST_CASE("vmcs_host_ia32_pat_pa4_memory_type")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::host_ia32_pat;
    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::mask
            << 32;

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

    pa4::memory_type::set(pa4::memory_type::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(pa4::memory_type::get(pa4::memory_type::mask) == (pa4::memory_type::mask >> pa4::memory_type::from));
}

TEST_CASE("vmcs_host_ia32_pat_pa4_reserved")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::host_ia32_pat;

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::mask
            << 32;

    pa4::reserved::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(pa4::reserved::get() == (pa4::reserved::mask >> pa4::reserved::from));

    pa4::reserved::set(pa4::reserved::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(pa4::reserved::get(pa4::reserved::mask) == (pa4::reserved::mask >> pa4::reserved::from));

    pa4::reserved::set_if_exists(0xFFFFFFFFFFFFFFFFULL);
    CHECK(pa4::reserved::get_if_exists() == (pa4::reserved::mask >> pa4::reserved::from));
}

TEST_CASE("vmcs_host_ia32_pat_pa5")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::host_ia32_pat;

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::mask
            << 32;

    pa5::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(pa5::get() == (pa5::mask >> pa5::from));

    pa5::set(pa5::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(pa5::get(pa5::mask) == (pa5::mask >> pa5::from));

    pa5::set_if_exists(0xFFFFFFFFFFFFFFFFULL);
    CHECK(pa5::get_if_exists() == (pa5::mask >> pa5::from));
}

TEST_CASE("vmcs_host_ia32_pat_pa5_memory_type")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::host_ia32_pat;
    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::mask
            << 32;

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

    pa5::memory_type::set(pa5::memory_type::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(pa5::memory_type::get(pa5::memory_type::mask) == (pa5::memory_type::mask >> pa5::memory_type::from));
}

TEST_CASE("vmcs_host_ia32_pat_pa5_reserved")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::host_ia32_pat;

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::mask
            << 32;

    pa5::reserved::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(pa5::reserved::get() == (pa5::reserved::mask >> pa5::reserved::from));

    pa5::reserved::set(pa5::reserved::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(pa5::reserved::get(pa5::reserved::mask) == (pa5::reserved::mask >> pa5::reserved::from));

    pa5::reserved::set_if_exists(0xFFFFFFFFFFFFFFFFULL);
    CHECK(pa5::reserved::get_if_exists() == (pa5::reserved::mask >> pa5::reserved::from));
}

TEST_CASE("vmcs_host_ia32_pat_pa6")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::host_ia32_pat;

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::mask
            << 32;

    pa6::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(pa6::get() == (pa6::mask >> pa6::from));

    pa6::set(pa6::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(pa6::get(pa6::mask) == (pa6::mask >> pa6::from));

    pa6::set_if_exists(0xFFFFFFFFFFFFFFFFULL);
    CHECK(pa6::get_if_exists() == (pa6::mask >> pa6::from));
}

TEST_CASE("vmcs_host_ia32_pat_pa6_memory_type")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::host_ia32_pat;
    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::mask
            << 32;

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

    pa6::memory_type::set(pa6::memory_type::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(pa6::memory_type::get(pa6::memory_type::mask) == (pa6::memory_type::mask >> pa6::memory_type::from));
}

TEST_CASE("vmcs_host_ia32_pat_pa6_reserved")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::host_ia32_pat;

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::mask
            << 32;

    pa6::reserved::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(pa6::reserved::get() == (pa6::reserved::mask >> pa6::reserved::from));

    pa6::reserved::set(pa6::reserved::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(pa6::reserved::get(pa6::reserved::mask) == (pa6::reserved::mask >> pa6::reserved::from));

    pa6::reserved::set_if_exists(0xFFFFFFFFFFFFFFFFULL);
    CHECK(pa6::reserved::get_if_exists() == (pa6::reserved::mask >> pa6::reserved::from));
}

TEST_CASE("vmcs_host_ia32_pat_pa7")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::host_ia32_pat;

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::mask
            << 32;

    pa7::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(pa7::get() == (pa7::mask >> pa7::from));

    pa7::set(pa7::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(pa7::get(pa7::mask) == (pa7::mask >> pa7::from));

    pa7::set_if_exists(0xFFFFFFFFFFFFFFFFULL);
    CHECK(pa7::get_if_exists() == (pa7::mask >> pa7::from));
}

TEST_CASE("vmcs_host_ia32_pat_pa7_memory_type")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::host_ia32_pat;
    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::mask
            << 32;

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

    pa7::memory_type::set(pa7::memory_type::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(pa7::memory_type::get(pa7::memory_type::mask) == (pa7::memory_type::mask >> pa7::memory_type::from));
}

TEST_CASE("vmcs_host_ia32_pat_pa7_reserved")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::host_ia32_pat;

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::mask
            << 32;

    pa7::reserved::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(pa7::reserved::get() == (pa7::reserved::mask >> pa7::reserved::from));

    pa7::reserved::set(pa7::reserved::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(pa7::reserved::get(pa7::reserved::mask) == (pa7::reserved::mask >> pa7::reserved::from));

    pa7::reserved::set_if_exists(0xFFFFFFFFFFFFFFFFULL);
    CHECK(pa7::reserved::get_if_exists() == (pa7::reserved::mask >> pa7::reserved::from));
}

TEST_CASE("vmcs_host_ia32_efer")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::host_ia32_efer;

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_efer::mask << 32;
    CHECK(exists());

    set(100UL);
    CHECK(get() == 100UL);
    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    dump(0);
}

TEST_CASE("vmcs_host_ia32_efer_sce")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::host_ia32_efer;

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_efer::mask
            << 32;

    sce::set(true);
    CHECK(sce::is_enabled());
    sce::set(false);
    CHECK(sce::is_disabled());

    sce::set(sce::mask, true);
    CHECK(sce::is_enabled(sce::mask));
    sce::set(0x0, false);
    CHECK(sce::is_disabled(0x0));

    sce::set_if_exists(true);
    CHECK(sce::is_enabled_if_exists());
    sce::set_if_exists(false);
    CHECK(sce::is_disabled_if_exists());
}

TEST_CASE("vmcs_host_ia32_efer_lme")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::host_ia32_efer;

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_efer::mask
            << 32;

    lme::set(true);
    CHECK(lme::is_enabled());
    lme::set(false);
    CHECK(lme::is_disabled());

    lme::set(lme::mask, true);
    CHECK(lme::is_enabled(lme::mask));
    lme::set(0x0, false);
    CHECK(lme::is_disabled(0x0));

    lme::set_if_exists(true);
    CHECK(lme::is_enabled_if_exists());
    lme::set_if_exists(false);
    CHECK(lme::is_disabled_if_exists());
}

TEST_CASE("vmcs_host_ia32_efer_lma")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::host_ia32_efer;

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_efer::mask
            << 32;

    lma::set(true);
    CHECK(lma::is_enabled());
    lma::set(false);
    CHECK(lma::is_disabled());

    lma::set(lma::mask, true);
    CHECK(lma::is_enabled(lma::mask));
    lma::set(0x0, false);
    CHECK(lma::is_disabled(0x0));

    lma::set_if_exists(true);
    CHECK(lma::is_enabled_if_exists());
    lma::set_if_exists(false);
    CHECK(lma::is_disabled_if_exists());
}

TEST_CASE("vmcs_host_ia32_efer_nxe")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::host_ia32_efer;

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_efer::mask
            << 32;

    nxe::set(true);
    CHECK(nxe::is_enabled());
    nxe::set(false);
    CHECK(nxe::is_disabled());

    nxe::set(nxe::mask, true);
    CHECK(nxe::is_enabled(nxe::mask));
    nxe::set(0x0, false);
    CHECK(nxe::is_disabled(0x0));

    nxe::set_if_exists(true);
    CHECK(nxe::is_enabled_if_exists());
    nxe::set_if_exists(false);
    CHECK(nxe::is_disabled_if_exists());
}

TEST_CASE("vmcs_host_ia32_efer_reserved")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::host_ia32_efer;

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_efer::mask
            << 32;

    reserved::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(reserved::get() == (reserved::mask >> reserved::from));

    reserved::set(reserved::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(reserved::get(reserved::mask) == (reserved::mask >> reserved::from));

    reserved::set_if_exists(0xFFFFFFFFFFFFFFFFULL);
    CHECK(reserved::get_if_exists() == (reserved::mask >> reserved::from));
}

TEST_CASE("vmcs_host_ia32_perf_global_ctrl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::host_ia32_perf_global_ctrl;

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |=
        msrs::ia32_vmx_true_exit_ctls::load_ia32_perf_global_ctrl::mask << 32;

    CHECK(exists());
    set(100UL);
    CHECK(get() == 100UL);
    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    dump(0);
}

TEST_CASE("vmcs_host_ia32_perf_global_ctrl_reserved")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::host_ia32_perf_global_ctrl;

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |=
        msrs::ia32_vmx_true_exit_ctls::load_ia32_perf_global_ctrl::mask << 32;

    reserved::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(reserved::get() == (reserved::mask >> reserved::from));

    reserved::set(reserved::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(reserved::get(reserved::mask) == (reserved::mask >> reserved::from));

    reserved::set_if_exists(0xFFFFFFFFFFFFFFFFULL);
    CHECK(reserved::get_if_exists() == (reserved::mask >> reserved::from));
}

#endif
