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
#include <intrinsics/x86/common_x64.h>
#include <hippomocks.h>

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

using namespace x64;

TEST_CASE("test name goes here")
{
    CHECK(true);
}

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

    using namespace msrs::ia32_p5_mc_addr;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_p5_mc_type")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace msrs::ia32_p5_mc_type;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_tsc")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace msrs::ia32_tsc;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mperf")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace msrs::ia32_mperf;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mperf_tsc_freq_clock_count")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace msrs::ia32_mperf;

    tsc_freq_clock_count::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(tsc_freq_clock_count::get() == (tsc_freq_clock_count::mask >> tsc_freq_clock_count::from));

    tsc_freq_clock_count::set(tsc_freq_clock_count::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(tsc_freq_clock_count::get(tsc_freq_clock_count::mask) == (tsc_freq_clock_count::mask >> tsc_freq_clock_count::from));
}

TEST_CASE("ia32_aperf")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace msrs::ia32_aperf;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_aperf_actual_freq_clock_count")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace msrs::ia32_aperf;

    actual_freq_clock_count::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(actual_freq_clock_count::get() == (actual_freq_clock_count::mask >> actual_freq_clock_count::from));

    actual_freq_clock_count::set(actual_freq_clock_count::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(actual_freq_clock_count::get(actual_freq_clock_count::mask) == (actual_freq_clock_count::mask >> actual_freq_clock_count::from));
}

TEST_CASE("ia32_mtrrcap")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace msrs::ia32_mtrrcap;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mtrrcap_vcnt")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace msrs::ia32_mtrrcap;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(vcnt::get() == (vcnt::mask >> vcnt::from));

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(vcnt::get(vcnt::mask) == (vcnt::mask >> vcnt::from));
}

TEST_CASE("ia32_mtrrcap_fixed_range_mtrr")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace msrs::ia32_mtrrcap;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(fixed_range_mtrr::is_enabled());
    g_msrs[addr] = 0x0;
    CHECK(fixed_range_mtrr::is_disabled());

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(fixed_range_mtrr::is_enabled(fixed_range_mtrr::mask));
    g_msrs[addr] = 0x0;
    CHECK(fixed_range_mtrr::is_disabled(0x0));
}

TEST_CASE("ia32_mtrrcap_wc")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace msrs::ia32_mtrrcap;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(wc::is_enabled());
    g_msrs[addr] = 0x0;
    CHECK(wc::is_disabled());

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(wc::is_enabled(wc::mask));
    g_msrs[addr] = 0x0;
    CHECK(wc::is_disabled(0x0));
}

TEST_CASE("ia32_mtrrcap_smrr")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace msrs::ia32_mtrrcap;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(smrr::is_enabled());
    g_msrs[addr] = 0x0;
    CHECK(smrr::is_disabled());

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(smrr::is_enabled(smrr::mask));
    g_msrs[addr] = 0x0;
    CHECK(smrr::is_disabled(0x0));
}

TEST_CASE("ia32_sysenter_cs")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace msrs::ia32_sysenter_cs;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_sysenter_cs_cs_selector")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace msrs::ia32_sysenter_cs;

    cs_selector::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(cs_selector::get() == (cs_selector::mask >> cs_selector::from));

    cs_selector::set(cs_selector::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(cs_selector::get(cs_selector::mask) == (cs_selector::mask >> cs_selector::from));
}

TEST_CASE("ia32_sysenter_esp")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace msrs::ia32_sysenter_esp;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_sysenter_eip")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace msrs::ia32_sysenter_eip;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mcg_cap")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace msrs::ia32_mcg_cap;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mcg_cap_count")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace msrs::ia32_mcg_cap;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(count::get() == (count::mask >> count::from));

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(count::get(count::mask) == (count::mask >> count::from));
}

TEST_CASE("ia32_mcg_cap_mcg_ctl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace msrs::ia32_mcg_cap;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(mcg_ctl::is_enabled());
    g_msrs[addr] = 0x0;
    CHECK(mcg_ctl::is_disabled());

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(mcg_ctl::is_enabled(mcg_ctl::mask));
    g_msrs[addr] = 0x0;
    CHECK(mcg_ctl::is_disabled(0x0));
}

TEST_CASE("ia32_mcg_cap_mcg_ext")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace msrs::ia32_mcg_cap;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(mcg_ext::is_enabled());
    g_msrs[addr] = 0x0;
    CHECK(mcg_ext::is_disabled());

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(mcg_ext::is_enabled(mcg_ext::mask));
    g_msrs[addr] = 0x0;
    CHECK(mcg_ext::is_disabled(0x0));
}

TEST_CASE("ia32_mcg_cap_mcg_cmci")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace msrs::ia32_mcg_cap;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(mcg_cmci::is_enabled());
    g_msrs[addr] = 0x0;
    CHECK(mcg_cmci::is_disabled());

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(mcg_cmci::is_enabled(mcg_cmci::mask));
    g_msrs[addr] = 0x0;
    CHECK(mcg_cmci::is_disabled(0x0));
}

TEST_CASE("ia32_mcg_cap_mcg_tes")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace msrs::ia32_mcg_cap;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(mcg_tes::is_enabled());
    g_msrs[addr] = 0x0;
    CHECK(mcg_tes::is_disabled());

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(mcg_tes::is_enabled(mcg_tes::mask));
    g_msrs[addr] = 0x0;
    CHECK(mcg_tes::is_disabled(0x0));
}

TEST_CASE("ia32_mcg_cap_mcg_ext_cnt")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace msrs::ia32_mcg_cap;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(mcg_ext_cnt::get() == (mcg_ext_cnt::mask >> mcg_ext_cnt::from));

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(mcg_ext_cnt::get(mcg_ext_cnt::mask) == (mcg_ext_cnt::mask >> mcg_ext_cnt::from));
}

TEST_CASE("ia32_mcg_cap_mcg_ser")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace msrs::ia32_mcg_cap;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(mcg_ser::is_enabled());
    g_msrs[addr] = 0x0;
    CHECK(mcg_ser::is_disabled());

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(mcg_ser::is_enabled(mcg_ser::mask));
    g_msrs[addr] = 0x0;
    CHECK(mcg_ser::is_disabled(0x0));
}

TEST_CASE("ia32_mcg_cap_mcg_elog")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace msrs::ia32_mcg_cap;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(mcg_elog::is_enabled());
    g_msrs[addr] = 0x0;
    CHECK(mcg_elog::is_disabled());

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(mcg_elog::is_enabled(mcg_elog::mask));
    g_msrs[addr] = 0x0;
    CHECK(mcg_elog::is_disabled(0x0));
}

TEST_CASE("ia32_mcg_cap_mcg_lmce")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace msrs::ia32_mcg_cap;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(mcg_lmce::is_enabled());
    g_msrs[addr] = 0x0;
    CHECK(mcg_lmce::is_disabled());

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(mcg_lmce::is_enabled(mcg_lmce::mask));
    g_msrs[addr] = 0x0;
    CHECK(mcg_lmce::is_disabled(0x0));
}

TEST_CASE("ia32_mcg_status")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace msrs::ia32_mcg_status;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mcg_status_ripv")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace msrs::ia32_mcg_status;

    ripv::enable();
    CHECK(ripv::is_enabled());
    ripv::disable();
    CHECK(ripv::is_disabled());

    ripv::enable(ripv::mask);
    CHECK(ripv::is_enabled(ripv::mask));
    ripv::disable(0x0);
    CHECK(ripv::is_disabled(0x0));
}

TEST_CASE("ia32_mcg_status_eipv")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace msrs::ia32_mcg_status;

    eipv::enable();
    CHECK(eipv::is_enabled());
    eipv::disable();
    CHECK(eipv::is_disabled());

    eipv::enable(eipv::mask);
    CHECK(eipv::is_enabled(eipv::mask));
    eipv::disable(0x0);
    CHECK(eipv::is_disabled(0x0));
}

TEST_CASE("ia32_mcg_status_mcip")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace msrs::ia32_mcg_status;

    mcip::enable();
    CHECK(mcip::is_enabled());
    mcip::disable();
    CHECK(mcip::is_disabled());

    mcip::enable(mcip::mask);
    CHECK(mcip::is_enabled(mcip::mask));
    mcip::disable(0x0);
    CHECK(mcip::is_disabled(0x0));
}

TEST_CASE("ia32_mcg_status_lmce_s")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace msrs::ia32_mcg_status;

    lmce_s::enable();
    CHECK(lmce_s::is_enabled());
    lmce_s::disable();
    CHECK(lmce_s::is_disabled());

    lmce_s::enable(lmce_s::mask);
    CHECK(lmce_s::is_enabled(lmce_s::mask));
    lmce_s::disable(0x0);
    CHECK(lmce_s::is_disabled(0x0));
}

TEST_CASE("ia32_mcg_ctl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace msrs::ia32_mcg_ctl;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_pat")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace msrs::ia32_pat;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_pat_pa0")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace msrs::ia32_pat;

    pa0::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(pa0::get() == (pa0::mask >> pa0::from));

    pa0::set(pa0::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(pa0::get(pa0::mask) == (pa0::mask >> pa0::from));
}

TEST_CASE("ia32_pat_pa1")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace msrs::ia32_pat;

    pa1::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(pa1::get() == (pa1::mask >> pa1::from));

    pa1::set(pa1::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(pa1::get(pa1::mask) == (pa1::mask >> pa1::from));
}

TEST_CASE("ia32_pat_pa2")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace msrs::ia32_pat;

    pa2::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(pa2::get() == (pa2::mask >> pa2::from));

    pa2::set(pa2::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(pa2::get(pa2::mask) == (pa2::mask >> pa2::from));
}

TEST_CASE("ia32_pat_pa3")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace msrs::ia32_pat;

    pa3::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(pa3::get() == (pa3::mask >> pa3::from));

    pa3::set(pa3::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(pa3::get(pa3::mask) == (pa3::mask >> pa3::from));
}

TEST_CASE("ia32_pat_pa4")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace msrs::ia32_pat;

    pa4::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(pa4::get() == (pa4::mask >> pa4::from));

    pa4::set(pa4::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(pa4::get(pa4::mask) == (pa4::mask >> pa4::from));
}

TEST_CASE("ia32_pat_pa5")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace msrs::ia32_pat;

    pa5::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(pa5::get() == (pa5::mask >> pa5::from));

    pa5::set(pa5::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(pa5::get(pa5::mask) == (pa5::mask >> pa5::from));
}

TEST_CASE("ia32_pat_pa6")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace msrs::ia32_pat;

    pa6::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(pa6::get() == (pa6::mask >> pa6::from));

    pa6::set(pa6::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(pa6::get(pa6::mask) == (pa6::mask >> pa6::from));
}

TEST_CASE("ia32_pat_pa7")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace msrs::ia32_pat;

    pa7::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(pa7::get() == (pa7::mask >> pa7::from));

    pa7::set(pa7::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(pa7::get(pa7::mask) == (pa7::mask >> pa7::from));
}

TEST_CASE("ia32_pat_pa")
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

    using namespace msrs::ia32_mc0_ctl;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc0_status")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace msrs::ia32_mc0_status;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc0_addr")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace msrs::ia32_mc0_addr;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc0_misc")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace msrs::ia32_mc0_misc;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc1_ctl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace msrs::ia32_mc1_ctl;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc1_status")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace msrs::ia32_mc1_status;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc1_addr")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace msrs::ia32_mc1_addr;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc1_misc")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace msrs::ia32_mc1_misc;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc2_ctl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace msrs::ia32_mc2_ctl;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc2_status")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace msrs::ia32_mc2_status;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc2_addr")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace msrs::ia32_mc2_addr;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc2_misc")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace msrs::ia32_mc2_misc;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc3_ctl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace msrs::ia32_mc3_ctl;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc3_status")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace msrs::ia32_mc3_status;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc3_addr")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace msrs::ia32_mc3_addr;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc3_misc")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace msrs::ia32_mc3_misc;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc4_ctl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace msrs::ia32_mc4_ctl;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc4_status")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace msrs::ia32_mc4_status;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc4_addr")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace msrs::ia32_mc4_addr;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc4_misc")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace msrs::ia32_mc4_misc;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc5_ctl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace msrs::ia32_mc5_ctl;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc5_status")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace msrs::ia32_mc5_status;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc5_addr")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace msrs::ia32_mc5_addr;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_mc5_misc")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace msrs::ia32_mc5_misc;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_star")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace msrs::ia32_star;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_lstar")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace msrs::ia32_lstar;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_fmask")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace msrs::ia32_fmask;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_kernel_gs_base")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace msrs::ia32_kernel_gs_base;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_tsc_aux")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace msrs::ia32_tsc_aux;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_tsc_aux_aux")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace msrs::ia32_tsc_aux;

    aux::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(aux::get() == (aux::mask >> aux::from));

    aux::set(aux::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(aux::get(aux::mask) == (aux::mask >> aux::from));
}

#endif
