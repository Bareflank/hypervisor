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

#include <catch/catch.hpp>
#include <intrinsics/x86/common_x64.h>
#include <hippomocks.h>

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

using namespace x64;

std::map<msrs::field_type, msrs::value_type> g_msrs;

extern "C" uint64_t
test_read_msr(uint32_t addr) noexcept
{ return g_msrs[addr]; }

extern "C" void
test_write_msr(uint32_t addr, uint64_t val) noexcept
{ g_msrs[addr] = val; }

static void
setup_intrinsics(MockRepository &mocks)
{
    mocks.OnCallFunc(_read_msr).Do(test_read_msr);
    mocks.OnCallFunc(_write_msr).Do(test_write_msr);
}

TEST_CASE("ia32_p5_mc_addr")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000000UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(msrs::ia32_p5_mc_addr::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_p5_mc_type")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000001UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(msrs::ia32_p5_mc_type::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_tsc")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000010UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(msrs::ia32_tsc::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_apic_base")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    msrs::ia32_apic_base::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(msrs::ia32_apic_base::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_apic_base_bsp_flag")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    msrs::ia32_apic_base::bsp_flag::set(true);
    CHECK(msrs::ia32_apic_base::bsp_flag::get());

    msrs::ia32_apic_base::bsp_flag::set(false);
    CHECK_FALSE(msrs::ia32_apic_base::bsp_flag::get());
}

TEST_CASE("ia32_apic_base_enable_x2apic")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    msrs::ia32_apic_base::enable_x2apic::set(true);
    CHECK(msrs::ia32_apic_base::enable_x2apic::get());

    msrs::ia32_apic_base::enable_x2apic::set(false);
    CHECK_FALSE(msrs::ia32_apic_base::enable_x2apic::get());
}

TEST_CASE("ia32_apic_base_apic_global_enable")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    msrs::ia32_apic_base::apic_global_enable::set(true);
    CHECK(msrs::ia32_apic_base::apic_global_enable::get());

    msrs::ia32_apic_base::apic_global_enable::set(false);
    CHECK_FALSE(msrs::ia32_apic_base::apic_global_enable::get());
}

TEST_CASE("ia32_apic_base_apic_base")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    msrs::ia32_apic_base::apic_base::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(msrs::ia32_apic_base::apic_base::get() == 0x000FFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mperf")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    msrs::ia32_mperf::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(msrs::ia32_mperf::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mperf_tsc_freq_clock_count")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    msrs::ia32_mperf::tsc_freq_clock_count::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(msrs::ia32_mperf::tsc_freq_clock_count::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_aperf")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    msrs::ia32_aperf::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(msrs::ia32_aperf::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_aperf_actual_freq_clock_count")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    msrs::ia32_aperf::actual_freq_clock_count::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(msrs::ia32_aperf::actual_freq_clock_count::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mtrrcap")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x000000FEUL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(msrs::ia32_mtrrcap::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mtrrcap_vcnt")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x000000FEUL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(msrs::ia32_mtrrcap::vcnt::get() == 0x00000000000000FFULL);
}

TEST_CASE("ia32_mtrrcap_fixed_range_mtrr")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x000000FEUL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(msrs::ia32_mtrrcap::fixed_range_mtrr::get());

    g_msrs[0x000000FEUL] = 0x0000000000000000ULL;
    CHECK_FALSE(msrs::ia32_mtrrcap::fixed_range_mtrr::get());
}

TEST_CASE("ia32_mtrrcap_wc")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x000000FEUL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(msrs::ia32_mtrrcap::wc::get());

    g_msrs[0x000000FEUL] = 0x0000000000000000ULL;
    CHECK_FALSE(msrs::ia32_mtrrcap::wc::get());
}

TEST_CASE("ia32_mtrrcap_smrr")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x000000FEUL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(msrs::ia32_mtrrcap::smrr::get());

    g_msrs[0x000000FEUL] = 0x0000000000000000ULL;
    CHECK_FALSE(msrs::ia32_mtrrcap::smrr::get());
}

TEST_CASE("ia32_sysenter_cs")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    msrs::ia32_sysenter_cs::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(msrs::ia32_sysenter_cs::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_sysenter_cs_cs_selector")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    msrs::ia32_sysenter_cs::cs_selector::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(msrs::ia32_sysenter_cs::cs_selector::get() == 0x000000000000FFFFULL);
}

TEST_CASE("ia32_sysenter_esp")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    msrs::ia32_sysenter_esp::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(msrs::ia32_sysenter_esp::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_sysenter_eip")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    msrs::ia32_sysenter_eip::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(msrs::ia32_sysenter_eip::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mcg_cap")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000179UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(msrs::ia32_mcg_cap::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mcg_cap_count")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000179UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(msrs::ia32_mcg_cap::count::get() == 0x00000000000000FFULL);
}

TEST_CASE("ia32_mcg_cap_mcg_ctl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000179UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(msrs::ia32_mcg_cap::mcg_ctl::get());

    g_msrs[0x00000179UL] = 0x0000000000000000ULL;
    CHECK_FALSE(msrs::ia32_mcg_cap::mcg_ctl::get());
}

TEST_CASE("ia32_mcg_cap_mcg_ext")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000179UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(msrs::ia32_mcg_cap::mcg_ext::get());

    g_msrs[0x00000179UL] = 0x0000000000000000ULL;
    CHECK_FALSE(msrs::ia32_mcg_cap::mcg_ext::get());
}

TEST_CASE("ia32_mcg_cap_mcg_cmci")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000179UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(msrs::ia32_mcg_cap::mcg_cmci::get());

    g_msrs[0x00000179UL] = 0x0000000000000000ULL;
    CHECK_FALSE(msrs::ia32_mcg_cap::mcg_cmci::get());
}

TEST_CASE("ia32_mcg_cap_mcg_tes")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000179UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(msrs::ia32_mcg_cap::mcg_tes::get());

    g_msrs[0x00000179UL] = 0x0000000000000000ULL;
    CHECK_FALSE(msrs::ia32_mcg_cap::mcg_tes::get());
}

TEST_CASE("ia32_mcg_cap_mcg_ext_cnt")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000179UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(msrs::ia32_mcg_cap::mcg_ext_cnt::get() == 0x00000000000000FFULL);
}

TEST_CASE("ia32_mcg_cap_mcg_ser")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000179UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(msrs::ia32_mcg_cap::mcg_ser::get());

    g_msrs[0x00000179UL] = 0x0000000000000000ULL;
    CHECK_FALSE(msrs::ia32_mcg_cap::mcg_ser::get());
}

TEST_CASE("ia32_mcg_cap_mcg_elog")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000179UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(msrs::ia32_mcg_cap::mcg_elog::get());

    g_msrs[0x00000179UL] = 0x0000000000000000ULL;
    CHECK_FALSE(msrs::ia32_mcg_cap::mcg_elog::get());
}

TEST_CASE("ia32_mcg_cap_mcg_lmce")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000179UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(msrs::ia32_mcg_cap::mcg_lmce::get());

    g_msrs[0x00000179UL] = 0x0000000000000000ULL;
    CHECK_FALSE(msrs::ia32_mcg_cap::mcg_lmce::get());
}

TEST_CASE("ia32_mcg_status")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    msrs::ia32_mcg_status::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(msrs::ia32_mcg_status::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mcg_status_ripv")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    msrs::ia32_mcg_status::ripv::set(true);
    CHECK(msrs::ia32_mcg_status::ripv::get());

    msrs::ia32_mcg_status::ripv::set(false);
    CHECK_FALSE(msrs::ia32_mcg_status::ripv::get());
}

TEST_CASE("ia32_mcg_status_eipv")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    msrs::ia32_mcg_status::eipv::set(true);
    CHECK(msrs::ia32_mcg_status::eipv::get());

    msrs::ia32_mcg_status::eipv::set(false);
    CHECK_FALSE(msrs::ia32_mcg_status::eipv::get());
}

TEST_CASE("ia32_mcg_status_mcip")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    msrs::ia32_mcg_status::mcip::set(true);
    CHECK(msrs::ia32_mcg_status::mcip::get());

    msrs::ia32_mcg_status::mcip::set(false);
    CHECK_FALSE(msrs::ia32_mcg_status::mcip::get());
}

TEST_CASE("ia32_mcg_status_lmce_s")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    msrs::ia32_mcg_status::lmce_s::set(true);
    CHECK(msrs::ia32_mcg_status::lmce_s::get());

    msrs::ia32_mcg_status::lmce_s::set(false);
    CHECK_FALSE(msrs::ia32_mcg_status::lmce_s::get());
}

TEST_CASE("ia32_mcg_ctl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    msrs::ia32_mcg_ctl::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(msrs::ia32_mcg_ctl::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_pat")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    msrs::ia32_pat::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(msrs::ia32_pat::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("test_ia32_pat")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    msrs::ia32_pat::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(msrs::ia32_pat::get() == 0xFFFFFFFFFFFFFFFFULL);

    msrs::ia32_pat::dump();

    msrs::ia32_pat::set(0x0UL);
    CHECK(msrs::ia32_pat::get() == 0x0UL);
}

TEST_CASE("test_ia32_pat_pa0")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    msrs::ia32_pat::pa0::set(6UL);
    CHECK(msrs::ia32_pat::pa0::get() == 6UL);
    CHECK(msrs::ia32_pat::pa0::get(0x0000000000000006ULL) == 6UL);

    msrs::ia32_pat::pa0::set(4UL);
    CHECK(msrs::ia32_pat::pa0::get() == 4UL);
    CHECK(msrs::ia32_pat::pa0::get(0x0000000000000004ULL) == 4UL);
}

TEST_CASE("test_ia32_pat_pa1")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    msrs::ia32_pat::pa1::set(6UL);
    CHECK(msrs::ia32_pat::pa1::get() == 6UL);
    CHECK(msrs::ia32_pat::pa1::get(0x0000000000000600ULL) == 6UL);

    msrs::ia32_pat::pa1::set(4UL);
    CHECK(msrs::ia32_pat::pa1::get() == 4UL);
    CHECK(msrs::ia32_pat::pa1::get(0x0000000000000400ULL) == 4UL);
}

TEST_CASE("test_ia32_pat_pa2")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    msrs::ia32_pat::pa2::set(6UL);
    CHECK(msrs::ia32_pat::pa2::get() == 6UL);
    CHECK(msrs::ia32_pat::pa2::get(0x0000000000060000ULL) == 6UL);

    msrs::ia32_pat::pa2::set(4UL);
    CHECK(msrs::ia32_pat::pa2::get() == 4UL);
    CHECK(msrs::ia32_pat::pa2::get(0x0000000000040000ULL) == 4UL);
}

TEST_CASE("test_ia32_pat_pa3")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    msrs::ia32_pat::pa3::set(6UL);
    CHECK(msrs::ia32_pat::pa3::get() == 6UL);
    CHECK(msrs::ia32_pat::pa3::get(0x0000000006000000ULL) == 6UL);

    msrs::ia32_pat::pa3::set(4UL);
    CHECK(msrs::ia32_pat::pa3::get() == 4UL);
    CHECK(msrs::ia32_pat::pa3::get(0x0000000004000000ULL) == 4UL);
}

TEST_CASE("test_ia32_pat_pa4")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    msrs::ia32_pat::pa4::set(6UL);
    CHECK(msrs::ia32_pat::pa4::get() == 6UL);
    CHECK(msrs::ia32_pat::pa4::get(0x0000000600000000ULL) == 6UL);

    msrs::ia32_pat::pa4::set(4UL);
    CHECK(msrs::ia32_pat::pa4::get() == 4UL);
    CHECK(msrs::ia32_pat::pa4::get(0x0000000400000000ULL) == 4UL);
}

TEST_CASE("test_ia32_pat_pa5")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    msrs::ia32_pat::pa5::set(6UL);
    CHECK(msrs::ia32_pat::pa5::get() == 6UL);
    CHECK(msrs::ia32_pat::pa5::get(0x0000060000000000ULL) == 6UL);

    msrs::ia32_pat::pa5::set(4UL);
    CHECK(msrs::ia32_pat::pa5::get() == 4UL);
    CHECK(msrs::ia32_pat::pa5::get(0x0000040000000000ULL) == 4UL);
}

TEST_CASE("test_ia32_pat_pa6")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    msrs::ia32_pat::pa6::set(6UL);
    CHECK(msrs::ia32_pat::pa6::get() == 6UL);
    CHECK(msrs::ia32_pat::pa6::get(0x0006000000000000ULL) == 6UL);

    msrs::ia32_pat::pa6::set(4UL);
    CHECK(msrs::ia32_pat::pa6::get() == 4UL);
    CHECK(msrs::ia32_pat::pa6::get(0x0004000000000000ULL) == 4UL);
}

TEST_CASE("test_ia32_pat_pa7")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    msrs::ia32_pat::pa7::set(6UL);
    CHECK(msrs::ia32_pat::pa7::get() == 6UL);
    CHECK(msrs::ia32_pat::pa7::get(0x0600000000000000ULL) == 6UL);

    msrs::ia32_pat::pa7::set(4UL);
    CHECK(msrs::ia32_pat::pa7::get() == 4UL);
    CHECK(msrs::ia32_pat::pa7::get(0x0400000000000000ULL) == 4UL);
}

TEST_CASE("test_ia32_pat_pa")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    msrs::ia32_pat::pa0::set(0UL);
    msrs::ia32_pat::pa1::set(1UL);
    msrs::ia32_pat::pa2::set(2UL);
    msrs::ia32_pat::pa3::set(3UL);
    msrs::ia32_pat::pa4::set(4UL);
    msrs::ia32_pat::pa5::set(5UL);
    msrs::ia32_pat::pa6::set(6UL);
    msrs::ia32_pat::pa7::set(7UL);

    CHECK(msrs::ia32_pat::pa(0UL) == 0UL);
    CHECK(msrs::ia32_pat::pa(1UL) == 1UL);
    CHECK(msrs::ia32_pat::pa(2UL) == 2UL);
    CHECK(msrs::ia32_pat::pa(3UL) == 3UL);
    CHECK(msrs::ia32_pat::pa(4UL) == 4UL);
    CHECK(msrs::ia32_pat::pa(5UL) == 5UL);
    CHECK(msrs::ia32_pat::pa(6UL) == 6UL);
    CHECK(msrs::ia32_pat::pa(7UL) == 7UL);
    CHECK_THROWS(msrs::ia32_pat::pa(8UL));

    CHECK(msrs::ia32_pat::pa(0x0000000000000000ULL, 0UL) == 0UL);
    CHECK(msrs::ia32_pat::pa(0x0000000000000100ULL, 1UL) == 1UL);
    CHECK(msrs::ia32_pat::pa(0x0000000000020000ULL, 2UL) == 2UL);
    CHECK(msrs::ia32_pat::pa(0x0000000003000000ULL, 3UL) == 3UL);
    CHECK(msrs::ia32_pat::pa(0x0000000400000000ULL, 4UL) == 4UL);
    CHECK(msrs::ia32_pat::pa(0x0000050000000000ULL, 5UL) == 5UL);
    CHECK(msrs::ia32_pat::pa(0x0006000000000000ULL, 6UL) == 6UL);
    CHECK(msrs::ia32_pat::pa(0x0700000000000000ULL, 7UL) == 7UL);
    CHECK_THROWS(msrs::ia32_pat::pa(0x8000000000000000ULL, 8UL));
}

TEST_CASE("ia32_mc0_ctl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000400UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(msrs::ia32_mc0_ctl::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc0_status")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000401UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(msrs::ia32_mc0_status::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc0_addr")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000402UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(msrs::ia32_mc0_addr::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc0_misc")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000403UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(msrs::ia32_mc0_misc::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc1_ctl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000404UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(msrs::ia32_mc1_ctl::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc1_status")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000405UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(msrs::ia32_mc1_status::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc1_addr")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000406UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(msrs::ia32_mc1_addr::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc1_misc")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000407UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(msrs::ia32_mc1_misc::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc2_ctl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000408UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(msrs::ia32_mc2_ctl::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc2_status")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000409UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(msrs::ia32_mc2_status::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc2_addr")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000040AUL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(msrs::ia32_mc2_addr::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc2_misc")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000040BUL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(msrs::ia32_mc2_misc::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc3_ctl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000040CUL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(msrs::ia32_mc3_ctl::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc3_status")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000040DUL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(msrs::ia32_mc3_status::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc3_addr")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000040EUL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(msrs::ia32_mc3_addr::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc3_misc")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x0000040FUL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(msrs::ia32_mc3_misc::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc4_ctl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000410UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(msrs::ia32_mc4_ctl::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc4_status")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000411UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(msrs::ia32_mc4_status::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc4_addr")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000412UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(msrs::ia32_mc4_addr::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc4_misc")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000413UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(msrs::ia32_mc4_misc::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc5_ctl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000414UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(msrs::ia32_mc5_ctl::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc5_status")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000415UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(msrs::ia32_mc5_status::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc5_addr")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000416UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(msrs::ia32_mc5_addr::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_mc5_misc")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[0x00000417UL] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(msrs::ia32_mc5_misc::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_star")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    msrs::ia32_star::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(msrs::ia32_star::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_lstar")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    msrs::ia32_lstar::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(msrs::ia32_lstar::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_fmask")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    msrs::ia32_fmask::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(msrs::ia32_fmask::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_kernel_gs_base")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    msrs::ia32_kernel_gs_base::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(msrs::ia32_kernel_gs_base::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_tsc_aux")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    msrs::ia32_tsc_aux::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(msrs::ia32_tsc_aux::get() == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("ia32_tsc_aux_aux")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    msrs::ia32_tsc_aux::aux::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(msrs::ia32_tsc_aux::aux::get() == 0x00000000FFFFFFFFULL);
}

#endif
