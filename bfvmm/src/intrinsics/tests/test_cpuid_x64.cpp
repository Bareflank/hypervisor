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
#include <intrinsics/x86/intel_x64.h>
#include <map>
#include <hippomocks.h>

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

using namespace x64;

std::map<cpuid::field_type, cpuid::value_type> g_eax_cpuid;
std::map<cpuid::field_type, cpuid::value_type> g_ebx_cpuid;
std::map<cpuid::field_type, cpuid::value_type> g_ecx_cpuid;
std::map<cpuid::field_type, cpuid::value_type> g_edx_cpuid;

extern "C" uint32_t __cpuid_eax(uint32_t val) noexcept;
extern "C" uint32_t __cpuid_ebx(uint32_t val) noexcept;
extern "C" uint32_t __cpuid_ecx(uint32_t val) noexcept;
extern "C" uint32_t __cpuid_edx(uint32_t val) noexcept;
extern "C" void __cpuid(void *eax, void *ebx, void *ecx, void *edx) noexcept;

struct cpuid_regs {
    cpuid::value_type eax;
    cpuid::value_type ebx;
    cpuid::value_type ecx;
    cpuid::value_type edx;
};

struct cpuid_regs g_regs;

extern "C" uint32_t
test_cpuid_eax(uint32_t val) noexcept
{ return g_eax_cpuid[val]; }
extern "C" uint32_t
test_cpuid_ebx(uint32_t val) noexcept
{ return g_ebx_cpuid[val]; }

extern "C" uint32_t
test_cpuid_ecx(uint32_t val) noexcept
{ return g_ecx_cpuid[val]; }

extern "C" uint32_t
test_cpuid_edx(uint32_t val) noexcept
{ return g_edx_cpuid[val]; }

static void
setup_intrinsics(MockRepository &mocks)
{
    mocks.OnCallFunc(_cpuid_eax).Do(test_cpuid_eax);
    mocks.OnCallFunc(_cpuid_ebx).Do(test_cpuid_ebx);
    mocks.OnCallFunc(_cpuid_ecx).Do(test_cpuid_ecx);
    mocks.OnCallFunc(_cpuid_edx).Do(test_cpuid_edx);
}

TEST_CASE("intrinsics: cpuid_addr_size_phys")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_eax_cpuid[0x80000008ULL] = 0xFFFFFFFF;
    CHECK(cpuid::addr_size::phys::get() == 0xFF);
}

TEST_CASE("intrinsics: cpuid_addr_size_linear")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_eax_cpuid[0x80000008ULL] = 0xFFFFFFFF;
    CHECK(cpuid::addr_size::linear::get() == 0xFF);
}

TEST_CASE("intrinsics: cpuid_feature_information_ecx_sse3")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ecx_cpuid[0x00000001ULL] = 0x1UL << 0;
    CHECK(cpuid::feature_information::ecx::sse3::get());

    g_ecx_cpuid[0x00000001ULL] = ~(0x1U << 0);
    CHECK_FALSE(cpuid::feature_information::ecx::sse3::get());
}

TEST_CASE("intrinsics: cpuid_feature_information_ecx_pclmulqdq")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ecx_cpuid[0x00000001ULL] = 0x1UL << 1;
    CHECK(cpuid::feature_information::ecx::pclmulqdq::get());

    g_ecx_cpuid[0x00000001ULL] = ~(0x1U << 1);
    CHECK_FALSE(cpuid::feature_information::ecx::pclmulqdq::get());
}

TEST_CASE("intrinsics: cpuid_feature_information_ecx_dtes64")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ecx_cpuid[0x00000001ULL] = 0x1UL << 2;
    CHECK(cpuid::feature_information::ecx::dtes64::get());

    g_ecx_cpuid[0x00000001ULL] = ~(0x1U << 2);
    CHECK_FALSE(cpuid::feature_information::ecx::dtes64::get());
}

TEST_CASE("intrinsics: cpuid_feature_information_ecx_monitor")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ecx_cpuid[0x00000001ULL] = 0x1UL << 3;
    CHECK(cpuid::feature_information::ecx::monitor::get());

    g_ecx_cpuid[0x00000001ULL] = ~(0x1U << 3);
    CHECK_FALSE(cpuid::feature_information::ecx::monitor::get());
}

TEST_CASE("intrinsics: cpuid_feature_information_ecx_ds_cpl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ecx_cpuid[0x00000001ULL] = 0x1UL << 4;
    CHECK(cpuid::feature_information::ecx::ds_cpl::get());

    g_ecx_cpuid[0x00000001ULL] = ~(0x1U << 4);
    CHECK_FALSE(cpuid::feature_information::ecx::ds_cpl::get());
}

TEST_CASE("intrinsics: cpuid_feature_information_ecx_vmx")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ecx_cpuid[0x00000001ULL] = 0x1UL << 5;
    CHECK(cpuid::feature_information::ecx::vmx::get());

    g_ecx_cpuid[0x00000001ULL] = ~(0x1U << 5);
    CHECK_FALSE(cpuid::feature_information::ecx::vmx::get());
}

TEST_CASE("intrinsics: cpuid_feature_information_ecx_smx")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ecx_cpuid[0x00000001ULL] = 0x1UL << 6;
    CHECK(cpuid::feature_information::ecx::smx::get());

    g_ecx_cpuid[0x00000001ULL] = ~(0x1U << 6);
    CHECK_FALSE(cpuid::feature_information::ecx::smx::get());
}

TEST_CASE("intrinsics: cpuid_feature_information_ecx_eist")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ecx_cpuid[0x00000001ULL] = 0x1UL << 7;
    CHECK(cpuid::feature_information::ecx::eist::get());

    g_ecx_cpuid[0x00000001ULL] = ~(0x1U << 7);
    CHECK_FALSE(cpuid::feature_information::ecx::eist::get());
}

TEST_CASE("intrinsics: cpuid_feature_information_ecx_tm2")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ecx_cpuid[0x00000001ULL] = 0x1UL << 8;
    CHECK(cpuid::feature_information::ecx::tm2::get());

    g_ecx_cpuid[0x00000001ULL] = ~(0x1U << 8);
    CHECK_FALSE(cpuid::feature_information::ecx::tm2::get());
}

TEST_CASE("intrinsics: cpuid_feature_information_ecx_ssse3")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ecx_cpuid[0x00000001ULL] = 0x1UL << 9;
    CHECK(cpuid::feature_information::ecx::ssse3::get());

    g_ecx_cpuid[0x00000001ULL] = ~(0x1U << 9);
    CHECK_FALSE(cpuid::feature_information::ecx::ssse3::get());
}

TEST_CASE("intrinsics: cpuid_feature_information_ecx_cnxt_id")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ecx_cpuid[0x00000001ULL] = 0x1UL << 10;
    CHECK(cpuid::feature_information::ecx::cnxt_id::get());

    g_ecx_cpuid[0x00000001ULL] = ~(0x1U << 10);
    CHECK_FALSE(cpuid::feature_information::ecx::cnxt_id::get());
}

TEST_CASE("intrinsics: cpuid_feature_information_ecx_sdbg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ecx_cpuid[0x00000001ULL] = 0x1UL << 11;
    CHECK(cpuid::feature_information::ecx::sdbg::get());

    g_ecx_cpuid[0x00000001ULL] = ~(0x1U << 11);
    CHECK_FALSE(cpuid::feature_information::ecx::sdbg::get());
}

TEST_CASE("intrinsics: cpuid_feature_information_ecx_fma")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ecx_cpuid[0x00000001ULL] = 0x1UL << 12;
    CHECK(cpuid::feature_information::ecx::fma::get());

    g_ecx_cpuid[0x00000001ULL] = ~(0x1U << 12);
    CHECK_FALSE(cpuid::feature_information::ecx::fma::get());
}

TEST_CASE("intrinsics: cpuid_feature_information_ecx_cmpxchg16b")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ecx_cpuid[0x00000001ULL] = 0x1UL << 13;
    CHECK(cpuid::feature_information::ecx::cmpxchg16b::get());

    g_ecx_cpuid[0x00000001ULL] = ~(0x1U << 13);
    CHECK_FALSE(cpuid::feature_information::ecx::cmpxchg16b::get());
}

TEST_CASE("intrinsics: cpuid_feature_information_ecx_xtpr_update_control")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ecx_cpuid[0x00000001ULL] = 0x1UL << 14;
    CHECK(cpuid::feature_information::ecx::xtpr_update_control::get());

    g_ecx_cpuid[0x00000001ULL] = ~(0x1U << 14);
    CHECK_FALSE(cpuid::feature_information::ecx::xtpr_update_control::get());
}

TEST_CASE("intrinsics: cpuid_feature_information_ecx_pdcm")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ecx_cpuid[0x00000001ULL] = 0x1UL << 15;
    CHECK(cpuid::feature_information::ecx::pdcm::get());

    g_ecx_cpuid[0x00000001ULL] = ~(0x1U << 15);
    CHECK_FALSE(cpuid::feature_information::ecx::pdcm::get());
}

TEST_CASE("intrinsics: cpuid_feature_information_ecx_pcid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ecx_cpuid[0x00000001ULL] = 0x1UL << 17;
    CHECK(cpuid::feature_information::ecx::pcid::get());

    g_ecx_cpuid[0x00000001ULL] = ~(0x1U << 17);
    CHECK_FALSE(cpuid::feature_information::ecx::pcid::get());
}

TEST_CASE("intrinsics: cpuid_feature_information_ecx_dca")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ecx_cpuid[0x00000001ULL] = 0x1UL << 18;
    CHECK(cpuid::feature_information::ecx::dca::get());

    g_ecx_cpuid[0x00000001ULL] = ~(0x1U << 18);
    CHECK_FALSE(cpuid::feature_information::ecx::dca::get());
}

TEST_CASE("intrinsics: cpuid_feature_information_ecx_sse41")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ecx_cpuid[0x00000001ULL] = 0x1UL << 19;
    CHECK(cpuid::feature_information::ecx::sse41::get());

    g_ecx_cpuid[0x00000001ULL] = ~(0x1U << 19);
    CHECK_FALSE(cpuid::feature_information::ecx::sse41::get());
}

TEST_CASE("intrinsics: cpuid_feature_information_ecx_sse42")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ecx_cpuid[0x00000001ULL] = 0x1UL << 20;
    CHECK(cpuid::feature_information::ecx::sse42::get());

    g_ecx_cpuid[0x00000001ULL] = ~(0x1U << 20);
    CHECK_FALSE(cpuid::feature_information::ecx::sse42::get());
}

TEST_CASE("intrinsics: cpuid_feature_information_ecx_x2apic")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ecx_cpuid[0x00000001ULL] = 0x1UL << 21;
    CHECK(cpuid::feature_information::ecx::x2apic::get());

    g_ecx_cpuid[0x00000001ULL] = ~(0x1U << 21);
    CHECK_FALSE(cpuid::feature_information::ecx::x2apic::get());
}

TEST_CASE("intrinsics: cpuid_feature_information_ecx_movbe")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ecx_cpuid[0x00000001ULL] = 0x1UL << 22;
    CHECK(cpuid::feature_information::ecx::movbe::get());

    g_ecx_cpuid[0x00000001ULL] = ~(0x1U << 22);
    CHECK_FALSE(cpuid::feature_information::ecx::movbe::get());
}

TEST_CASE("intrinsics: cpuid_feature_information_ecx_popcnt")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ecx_cpuid[0x00000001ULL] = 0x1UL << 23;
    CHECK(cpuid::feature_information::ecx::popcnt::get());

    g_ecx_cpuid[0x00000001ULL] = ~(0x1U << 23);
    CHECK_FALSE(cpuid::feature_information::ecx::popcnt::get());
}

TEST_CASE("intrinsics: cpuid_feature_information_ecx_tsc_deadline")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ecx_cpuid[0x00000001ULL] = 0x1UL << 24;
    CHECK(cpuid::feature_information::ecx::tsc_deadline::get());

    g_ecx_cpuid[0x00000001ULL] = ~(0x1U << 24);
    CHECK_FALSE(cpuid::feature_information::ecx::tsc_deadline::get());
}

TEST_CASE("intrinsics: cpuid_feature_information_ecx_aesni")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ecx_cpuid[0x00000001ULL] = 0x1UL << 25;
    CHECK(cpuid::feature_information::ecx::aesni::get());

    g_ecx_cpuid[0x00000001ULL] = ~(0x1U << 25);
    CHECK_FALSE(cpuid::feature_information::ecx::aesni::get());
}

TEST_CASE("intrinsics: cpuid_feature_information_ecx_xsave")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ecx_cpuid[0x00000001ULL] = 0x1UL << 26;
    CHECK(cpuid::feature_information::ecx::xsave::get());

    g_ecx_cpuid[0x00000001ULL] = ~(0x1U << 26);
    CHECK_FALSE(cpuid::feature_information::ecx::xsave::get());
}

TEST_CASE("intrinsics: cpuid_feature_information_ecx_osxsave")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ecx_cpuid[0x00000001ULL] = 0x1UL << 27;
    CHECK(cpuid::feature_information::ecx::osxsave::get());

    g_ecx_cpuid[0x00000001ULL] = ~(0x1U << 27);
    CHECK_FALSE(cpuid::feature_information::ecx::osxsave::get());
}

TEST_CASE("intrinsics: cpuid_feature_information_ecx_avx")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ecx_cpuid[0x00000001ULL] = 0x1UL << 28;
    CHECK(cpuid::feature_information::ecx::avx::get());

    g_ecx_cpuid[0x00000001ULL] = ~(0x1U << 28);
    CHECK_FALSE(cpuid::feature_information::ecx::avx::get());
}

TEST_CASE("intrinsics: cpuid_feature_information_ecx_f16c")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ecx_cpuid[0x00000001ULL] = 0x1UL << 29;
    CHECK(cpuid::feature_information::ecx::f16c::get());

    g_ecx_cpuid[0x00000001ULL] = ~(0x1U << 29);
    CHECK_FALSE(cpuid::feature_information::ecx::f16c::get());
}

TEST_CASE("intrinsics: cpuid_feature_information_ecx_rdrand")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ecx_cpuid[0x00000001ULL] = 0x1UL << 30;
    CHECK(cpuid::feature_information::ecx::rdrand::get());

    g_ecx_cpuid[0x00000001ULL] = ~(0x1U << 30);
    CHECK_FALSE(cpuid::feature_information::ecx::rdrand::get());
}

TEST_CASE("intrinsics: cpuid_feature_information_ecx_dump")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ecx_cpuid[0x00000001ULL] = 0xFFFFFFFFU;
    cpuid::feature_information::ecx::dump();
}

TEST_CASE("intrinsics: cpuid_extended_feature_flags_subleaf0_eax_max_input")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_eax_cpuid[0x00000007ULL] = 0xFFFFFFFF;
    CHECK(cpuid::extended_feature_flags::subleaf0::eax::max_input::get() == 0xFFFFFFFF);
}

TEST_CASE("intrinsics: cpuid_extended_feature_flags_subleaf0_ebx_fsgsbase")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ebx_cpuid[0x00000007ULL] = 0x1UL << 0;
    CHECK(cpuid::extended_feature_flags::subleaf0::ebx::fsgsbase::get());

    g_ebx_cpuid[0x00000007ULL] = ~(0x1U << 0);
    CHECK_FALSE(cpuid::extended_feature_flags::subleaf0::ebx::fsgsbase::get());
}

TEST_CASE("intrinsics: cpuid_extended_feature_flags_subleaf0_ebx_ia32_tsc_adjust")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ebx_cpuid[0x00000007ULL] = 0x1UL << 1;
    CHECK(cpuid::extended_feature_flags::subleaf0::ebx::ia32_tsc_adjust::get());

    g_ebx_cpuid[0x00000007ULL] = ~(0x1U << 1);
    CHECK_FALSE(cpuid::extended_feature_flags::subleaf0::ebx::ia32_tsc_adjust::get());
}

TEST_CASE("intrinsics: cpuid_extended_feature_flags_subleaf0_ebx_sgx")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ebx_cpuid[0x00000007ULL] = 0x1UL << 2;
    CHECK(cpuid::extended_feature_flags::subleaf0::ebx::sgx::get());

    g_ebx_cpuid[0x00000007ULL] = ~(0x1U << 2);
    CHECK_FALSE(cpuid::extended_feature_flags::subleaf0::ebx::sgx::get());
}

TEST_CASE("intrinsics: cpuid_extended_feature_flags_subleaf0_ebx_bmi1")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ebx_cpuid[0x00000007ULL] = 0x1UL << 3;
    CHECK(cpuid::extended_feature_flags::subleaf0::ebx::bmi1::get());

    g_ebx_cpuid[0x00000007ULL] = ~(0x1U << 3);
    CHECK_FALSE(cpuid::extended_feature_flags::subleaf0::ebx::bmi1::get());
}

TEST_CASE("intrinsics: cpuid_extended_feature_flags_subleaf0_ebx_hle")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ebx_cpuid[0x00000007ULL] = 0x1UL << 4;
    CHECK(cpuid::extended_feature_flags::subleaf0::ebx::hle::get());

    g_ebx_cpuid[0x00000007ULL] = ~(0x1U << 4);
    CHECK_FALSE(cpuid::extended_feature_flags::subleaf0::ebx::hle::get());
}

TEST_CASE("intrinsics: cpuid_extended_feature_flags_subleaf0_ebx_avx2")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ebx_cpuid[0x00000007ULL] = 0x1UL << 5;
    CHECK(cpuid::extended_feature_flags::subleaf0::ebx::avx2::get());

    g_ebx_cpuid[0x00000007ULL] = ~(0x1U << 5);
    CHECK_FALSE(cpuid::extended_feature_flags::subleaf0::ebx::avx2::get());
}

TEST_CASE("intrinsics: cpuid_extended_feature_flags_subleaf0_ebx_fdp_excptn_only")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ebx_cpuid[0x00000007ULL] = 0x1UL << 6;
    CHECK(cpuid::extended_feature_flags::subleaf0::ebx::fdp_excptn_only::get());

    g_ebx_cpuid[0x00000007ULL] = ~(0x1U << 6);
    CHECK_FALSE(cpuid::extended_feature_flags::subleaf0::ebx::fdp_excptn_only::get());
}

TEST_CASE("intrinsics: cpuid_extended_feature_flags_subleaf0_ebx_smep")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ebx_cpuid[0x00000007ULL] = 0x1UL << 7;
    CHECK(cpuid::extended_feature_flags::subleaf0::ebx::smep::get());

    g_ebx_cpuid[0x00000007ULL] = ~(0x1U << 7);
    CHECK_FALSE(cpuid::extended_feature_flags::subleaf0::ebx::smep::get());
}

TEST_CASE("intrinsics: cpuid_extended_feature_flags_subleaf0_ebx_bmi2")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ebx_cpuid[0x00000007ULL] = 0x1UL << 8;
    CHECK(cpuid::extended_feature_flags::subleaf0::ebx::bmi2::get());

    g_ebx_cpuid[0x00000007ULL] = ~(0x1U << 8);
    CHECK_FALSE(cpuid::extended_feature_flags::subleaf0::ebx::bmi2::get());
}

TEST_CASE("intrinsics: cpuid_extended_feature_flags_subleaf0_ebx_movsb")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ebx_cpuid[0x00000007ULL] = 0x1UL << 9;
    CHECK(cpuid::extended_feature_flags::subleaf0::ebx::movsb::get());

    g_ebx_cpuid[0x00000007ULL] = ~(0x1U << 9);
    CHECK_FALSE(cpuid::extended_feature_flags::subleaf0::ebx::movsb::get());
}

TEST_CASE("intrinsics: cpuid_extended_feature_flags_subleaf0_ebx_invpcid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ebx_cpuid[0x00000007ULL] = 0x1UL << 10;
    CHECK(cpuid::extended_feature_flags::subleaf0::ebx::invpcid::get());

    g_ebx_cpuid[0x00000007ULL] = ~(0x1U << 10);
    CHECK_FALSE(cpuid::extended_feature_flags::subleaf0::ebx::invpcid::get());
}

TEST_CASE("intrinsics: cpuid_extended_feature_flags_subleaf0_ebx_rtm")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ebx_cpuid[0x00000007ULL] = 0x1UL << 11;
    CHECK(cpuid::extended_feature_flags::subleaf0::ebx::rtm::get());

    g_ebx_cpuid[0x00000007ULL] = ~(0x1U << 11);
    CHECK_FALSE(cpuid::extended_feature_flags::subleaf0::ebx::rtm::get());
}

TEST_CASE("intrinsics: cpuid_extended_feature_flags_subleaf0_ebx_rtm_m")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ebx_cpuid[0x00000007ULL] = 0x1UL << 12;
    CHECK(cpuid::extended_feature_flags::subleaf0::ebx::rtm_m::get());

    g_ebx_cpuid[0x00000007ULL] = ~(0x1U << 12);
    CHECK_FALSE(cpuid::extended_feature_flags::subleaf0::ebx::rtm_m::get());
}

TEST_CASE("intrinsics: cpuid_extended_feature_flags_subleaf0_ebx_fpucs_fpuds")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ebx_cpuid[0x00000007ULL] = 0x1UL << 13;
    CHECK(cpuid::extended_feature_flags::subleaf0::ebx::fpucs_fpuds::get());

    g_ebx_cpuid[0x00000007ULL] = ~(0x1U << 13);
    CHECK_FALSE(cpuid::extended_feature_flags::subleaf0::ebx::fpucs_fpuds::get());
}

TEST_CASE("intrinsics: cpuid_extended_feature_flags_subleaf0_ebx_mpx")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ebx_cpuid[0x00000007ULL] = 0x1UL << 14;
    CHECK(cpuid::extended_feature_flags::subleaf0::ebx::mpx::get());

    g_ebx_cpuid[0x00000007ULL] = ~(0x1U << 14);
    CHECK_FALSE(cpuid::extended_feature_flags::subleaf0::ebx::mpx::get());
}

TEST_CASE("intrinsics: cpuid_extended_feature_flags_subleaf0_ebx_rdt_a")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ebx_cpuid[0x00000007ULL] = 0x1UL << 15;
    CHECK(cpuid::extended_feature_flags::subleaf0::ebx::rdt_a::get());

    g_ebx_cpuid[0x00000007ULL] = ~(0x1U << 15);
    CHECK_FALSE(cpuid::extended_feature_flags::subleaf0::ebx::rdt_a::get());
}

TEST_CASE("intrinsics: cpuid_extended_feature_flags_subleaf0_ebx_rdseed")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ebx_cpuid[0x00000007ULL] = 0x1UL << 18;
    CHECK(cpuid::extended_feature_flags::subleaf0::ebx::rdseed::get());

    g_ebx_cpuid[0x00000007ULL] = ~(0x1U << 18);
    CHECK_FALSE(cpuid::extended_feature_flags::subleaf0::ebx::rdseed::get());
}

TEST_CASE("intrinsics: cpuid_extended_feature_flags_subleaf0_ebx_adx")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ebx_cpuid[0x00000007ULL] = 0x1UL << 19;
    CHECK(cpuid::extended_feature_flags::subleaf0::ebx::adx::get());

    g_ebx_cpuid[0x00000007ULL] = ~(0x1U << 19);
    CHECK_FALSE(cpuid::extended_feature_flags::subleaf0::ebx::adx::get());
}

TEST_CASE("intrinsics: cpuid_extended_feature_flags_subleaf0_ebx_smap")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ebx_cpuid[0x00000007ULL] = 0x1UL << 20;
    CHECK(cpuid::extended_feature_flags::subleaf0::ebx::smap::get());

    g_ebx_cpuid[0x00000007ULL] = ~(0x1U << 20);
    CHECK_FALSE(cpuid::extended_feature_flags::subleaf0::ebx::smap::get());
}

TEST_CASE("intrinsics: cpuid_extended_feature_flags_subleaf0_ebx_clflushopt")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ebx_cpuid[0x00000007ULL] = 0x1UL << 23;
    CHECK(cpuid::extended_feature_flags::subleaf0::ebx::clflushopt::get());

    g_ebx_cpuid[0x00000007ULL] = ~(0x1U << 23);
    CHECK_FALSE(cpuid::extended_feature_flags::subleaf0::ebx::clflushopt::get());
}

TEST_CASE("intrinsics: cpuid_extended_feature_flags_subleaf0_ebx_clwb")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ebx_cpuid[0x00000007ULL] = 0x1UL << 24;
    CHECK(cpuid::extended_feature_flags::subleaf0::ebx::clwb::get());

    g_ebx_cpuid[0x00000007ULL] = ~(0x1U << 24);
    CHECK_FALSE(cpuid::extended_feature_flags::subleaf0::ebx::clwb::get());
}

TEST_CASE("intrinsics: cpuid_extended_feature_flags_subleaf0_ebx_trace")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ebx_cpuid[0x00000007ULL] = 0x1UL << 25;
    CHECK(cpuid::extended_feature_flags::subleaf0::ebx::trace::get());

    g_ebx_cpuid[0x00000007ULL] = ~(0x1U << 25);
    CHECK_FALSE(cpuid::extended_feature_flags::subleaf0::ebx::trace::get());
}

TEST_CASE("intrinsics: cpuid_extended_feature_flags_subleaf0_ebx_sha")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ebx_cpuid[0x00000007ULL] = 0x1UL << 29;
    CHECK(cpuid::extended_feature_flags::subleaf0::ebx::sha::get());

    g_ebx_cpuid[0x00000007ULL] = ~(0x1U << 29);
    CHECK_FALSE(cpuid::extended_feature_flags::subleaf0::ebx::sha::get());
}

TEST_CASE("intrinsics: cpuid_extended_feature_flags_subleaf0_ecx_prefetchwt1")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ecx_cpuid[0x00000007ULL] = 0x1UL << 0;
    CHECK(cpuid::extended_feature_flags::subleaf0::ecx::prefetchwt1::get());

    g_ecx_cpuid[0x00000007ULL] = ~(0x1U << 0);
    CHECK_FALSE(cpuid::extended_feature_flags::subleaf0::ecx::prefetchwt1::get());
}

TEST_CASE("intrinsics: cpuid_extended_feature_flags_subleaf0_ecx_umip")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ecx_cpuid[0x00000007ULL] = 0x1UL << 2;
    CHECK(cpuid::extended_feature_flags::subleaf0::ecx::umip::get());

    g_ecx_cpuid[0x00000007ULL] = ~(0x1U << 2);
    CHECK_FALSE(cpuid::extended_feature_flags::subleaf0::ecx::umip::get());
}

TEST_CASE("intrinsics: cpuid_extended_feature_flags_subleaf0_ecx_pku")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ecx_cpuid[0x00000007ULL] = 0x1UL << 3;
    CHECK(cpuid::extended_feature_flags::subleaf0::ecx::pku::get());

    g_ecx_cpuid[0x00000007ULL] = ~(0x1U << 3);
    CHECK_FALSE(cpuid::extended_feature_flags::subleaf0::ecx::pku::get());
}

TEST_CASE("intrinsics: cpuid_extended_feature_flags_subleaf0_ecx_ospke")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ecx_cpuid[0x00000007ULL] = 0x1UL << 4;
    CHECK(cpuid::extended_feature_flags::subleaf0::ecx::ospke::get());

    g_ecx_cpuid[0x00000007ULL] = ~(0x1U << 4);
    CHECK_FALSE(cpuid::extended_feature_flags::subleaf0::ecx::ospke::get());
}

TEST_CASE("intrinsics: cpuid_extended_feature_flags_subleaf0_ecx_mawau")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ecx_cpuid[0x00000007ULL] = 0xFFFFFFFFU;
    CHECK(cpuid::extended_feature_flags::subleaf0::ecx::mawau::get() == 0x1F);
}

TEST_CASE("intrinsics: cpuid_extended_feature_flags_subleaf0_ecx_rdpid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ecx_cpuid[0x00000007ULL] = 0x1UL << 22;
    CHECK(cpuid::extended_feature_flags::subleaf0::ecx::rdpid::get());

    g_ecx_cpuid[0x00000007ULL] = ~(0x1U << 22);
    CHECK_FALSE(cpuid::extended_feature_flags::subleaf0::ecx::rdpid::get());
}

TEST_CASE("intrinsics: cpuid_extended_feature_flags_subleaf0_ecx_sgx_lc")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ecx_cpuid[0x00000007ULL] = 0x1UL << 30;
    CHECK(cpuid::extended_feature_flags::subleaf0::ecx::sgx_lc::get());

    g_ecx_cpuid[0x00000007ULL] = ~(0x1U << 30);
    CHECK_FALSE(cpuid::extended_feature_flags::subleaf0::ecx::sgx_lc::get());
}

TEST_CASE("intrinsics: cpuid_arch_perf_monitoring_eax_version_id")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_eax_cpuid[0x0000000AULL] = 0x87654321ULL;
    CHECK(cpuid::arch_perf_monitoring::eax::version_id::get() == 0x00000021ULL);
}

TEST_CASE("intrinsics: cpuid_arch_perf_monitoring_eax_gppmc_count")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_eax_cpuid[0x0000000AULL] = 0x87654321ULL;
    CHECK(cpuid::arch_perf_monitoring::eax::gppmc_count::get() == 0x00000043ULL);
}

TEST_CASE("intrinsics: cpuid_arch_perf_monitoring_eax_gppmc_bit_width")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_eax_cpuid[0x0000000AULL] = 0x87654321ULL;
    CHECK(cpuid::arch_perf_monitoring::eax::gppmc_bit_width::get() == 0x00000065ULL);
}

TEST_CASE("intrinsics: cpuid_arch_perf_monitoring_eax_ebx_enumeration_length")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_eax_cpuid[0x0000000AULL] = 0x87654321ULL;
    CHECK(cpuid::arch_perf_monitoring::eax::ebx_enumeration_length::get() == 0x00000087ULL);
}

TEST_CASE("intrinsics: cpuid_arch_perf_monitoring_ebx_core_cycle_event")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ebx_cpuid[0x0000000AULL] = 0x1U << 0;
    CHECK(cpuid::arch_perf_monitoring::ebx::core_cycle_event::get());

    g_ebx_cpuid[0x0000000AULL] = ~(0x1U << 0);
    CHECK_FALSE(cpuid::arch_perf_monitoring::ebx::core_cycle_event::get());
}

TEST_CASE("intrinsics: cpuid_arch_perf_monitoring_ebx_instr_retired_event")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ebx_cpuid[0x0000000AULL] = (0x1U << 1);
    CHECK(cpuid::arch_perf_monitoring::ebx::instr_retired_event::get());

    g_ebx_cpuid[0x0000000AULL] = ~(0x1U << 1);
    CHECK_FALSE(cpuid::arch_perf_monitoring::ebx::instr_retired_event::get());
}

TEST_CASE("intrinsics: cpuid_arch_perf_monitoring_ebx_reference_cycles_event")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ebx_cpuid[0x0000000AULL] = (0x1U << 2);
    CHECK(cpuid::arch_perf_monitoring::ebx::reference_cycles_event::get());

    g_ebx_cpuid[0x0000000AULL] = ~(0x1U << 2);
    CHECK_FALSE(cpuid::arch_perf_monitoring::ebx::reference_cycles_event::get());
}

TEST_CASE("intrinsics: cpuid_arch_perf_monitoring_ebx_llc_reference_event")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ebx_cpuid[0x0000000AULL] = (0x1U << 3);
    CHECK(cpuid::arch_perf_monitoring::ebx::llc_reference_event::get());

    g_ebx_cpuid[0x0000000AULL] = ~(0x1U << 3);
    CHECK_FALSE(cpuid::arch_perf_monitoring::ebx::llc_reference_event::get());
}

TEST_CASE("intrinsics: cpuid_arch_perf_monitoring_ebx_llc_misses_event")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ebx_cpuid[0x0000000AULL] = (0x1U << 4);
    CHECK(cpuid::arch_perf_monitoring::ebx::llc_misses_event::get());

    g_ebx_cpuid[0x0000000AULL] = ~(0x1U << 4);
    CHECK_FALSE(cpuid::arch_perf_monitoring::ebx::llc_misses_event::get());
}

TEST_CASE("intrinsics: cpuid_arch_perf_monitoring_ebx_branch_instr_retired_event")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ebx_cpuid[0x0000000AULL] = (0x1U << 5);
    CHECK(cpuid::arch_perf_monitoring::ebx::branch_instr_retired_event::get());

    g_ebx_cpuid[0x0000000AULL] = ~(0x1U << 5);
    CHECK_FALSE(cpuid::arch_perf_monitoring::ebx::branch_instr_retired_event::get());
}

TEST_CASE("intrinsics: cpuid_arch_perf_monitoring_ebx_branch_mispredict_retired_event")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ebx_cpuid[0x0000000AULL] = (0x1U << 6);
    CHECK(cpuid::arch_perf_monitoring::ebx::branch_mispredict_retired_event::get());

    g_ebx_cpuid[0x0000000AULL] = ~(0x1U << 6);
    CHECK_FALSE(cpuid::arch_perf_monitoring::ebx::branch_mispredict_retired_event::get());
}

TEST_CASE("intrinsics: cpuid_arch_perf_monitoring_edx_ffpmc_count")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_edx_cpuid[0x0000000AULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::arch_perf_monitoring::edx::ffpmc_count::get() == 0x0000001FULL);
}

TEST_CASE("intrinsics: cpuid_arch_perf_monitoring_edx_ffpmc_bit_width")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_edx_cpuid[0x0000000AULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::arch_perf_monitoring::edx::ffpmc_bit_width::get() == 0x000000FFULL);
}

TEST_CASE("intrinsics: cpuid_basic_cpuid_info_eax_max_input_value")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_eax_cpuid[0x00000000ULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::basic_cpuid_info::eax::max_input_value::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_extend_cpuid_info_eax_max_input_value")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_eax_cpuid[0x80000000ULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::extend_cpuid_info::eax::max_input_value::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_processor_string_1_eax_part_1")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_eax_cpuid[0x80000002ULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::processor_string_1::eax::part_1::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_processor_string_1_ebx_part_2")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ebx_cpuid[0x80000002ULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::processor_string_1::ebx::part_2::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_processor_string_1_ecx_part_3")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ecx_cpuid[0x80000002ULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::processor_string_1::ecx::part_3::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_processor_string_1_edx_part_4")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_edx_cpuid[0x80000002ULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::processor_string_1::edx::part_4::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_processor_string_2_eax_part_1")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_eax_cpuid[0x80000003ULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::processor_string_2::eax::part_1::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_processor_string_2_ebx_part_2")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ebx_cpuid[0x80000003ULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::processor_string_2::ebx::part_2::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_processor_string_2_ecx_part_3")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ecx_cpuid[0x80000003ULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::processor_string_2::ecx::part_3::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_processor_string_2_edx_part_4")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_edx_cpuid[0x80000003ULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::processor_string_2::edx::part_4::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_processor_string_3_eax_part_1")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_eax_cpuid[0x80000004ULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::processor_string_3::eax::part_1::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_processor_string_3_ebx_part_2")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ebx_cpuid[0x80000004ULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::processor_string_3::ebx::part_2::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_processor_string_3_ecx_part_3")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ecx_cpuid[0x80000004ULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::processor_string_3::ecx::part_3::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_processor_string_3_edx_part_4")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_edx_cpuid[0x80000004ULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::processor_string_3::edx::part_4::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_intel_cache_tlb_info_eax_info")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_eax_cpuid[0x00000002ULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::intel::cache_tlb_info::eax::info::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_intel_cache_tlb_info_ebx_info")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ebx_cpuid[0x00000002ULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::intel::cache_tlb_info::ebx::info::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_intel_cache_tlb_info_ecx_info")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ecx_cpuid[0x00000002ULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::intel::cache_tlb_info::ecx::info::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_intel_cache_tlb_info_edx_info")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_edx_cpuid[0x00000002ULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::intel::cache_tlb_info::edx::info::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_intel_serial_num_ecx_bits")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ecx_cpuid[0x00000003ULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::intel::serial_num::ecx::bits::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_intel_serial_num_edx_bits")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_edx_cpuid[0x00000003ULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::intel::serial_num::edx::bits::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_intel_cache_parameters_eax_cache_type")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_eax_cpuid[0x00000004ULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::intel::cache_parameters::eax::cache_type::get() == 0x0000001FULL);
}

TEST_CASE("intrinsics: cpuid_intel_cache_parameters_eax_cache_level")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_eax_cpuid[0x00000004ULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::intel::cache_parameters::eax::cache_level::get() == 0x00000007ULL);
}

TEST_CASE("intrinsics: cpuid_intel_cache_parameters_eax_self_init_level")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_eax_cpuid[0x00000004ULL] = (0x1U << 8);
    CHECK(cpuid::intel::cache_parameters::eax::self_init_level::get());

    g_eax_cpuid[0x00000004ULL] = ~(0x1U << 8);
    CHECK_FALSE(cpuid::intel::cache_parameters::eax::self_init_level::get());
}

TEST_CASE("intrinsics: cpuid_intel_cache_parameters_eax_fully_associative")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_eax_cpuid[0x00000004ULL] = (0x1U << 9);
    CHECK(cpuid::intel::cache_parameters::eax::fully_associative::get());

    g_eax_cpuid[0x00000004ULL] = ~(0x1U << 9);
    CHECK_FALSE(cpuid::intel::cache_parameters::eax::fully_associative::get());
}

TEST_CASE("intrinsics: cpuid_intel_cache_parameters_eax_max_ids_logical")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_eax_cpuid[0x00000004ULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::intel::cache_parameters::eax::max_ids_logical::get() == 0x00000FFFULL);
}

TEST_CASE("intrinsics: cpuid_intel_cache_parameters_eax_max_ids_physical")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_eax_cpuid[0x00000004ULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::intel::cache_parameters::eax::max_ids_physical::get() == 0x0000003FULL);
}

TEST_CASE("intrinsics: cpuid_intel_cache_parameters_ebx_l")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ebx_cpuid[0x00000004ULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::intel::cache_parameters::ebx::l::get() == 0x00000FFFULL);
}

TEST_CASE("intrinsics: cpuid_intel_cache_parameters_ebx_p")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ebx_cpuid[0x00000004ULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::intel::cache_parameters::ebx::p::get() == 0x000003FFULL);
}

TEST_CASE("intrinsics: cpuid_intel_cache_parameters_ebx_w")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ebx_cpuid[0x00000004ULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::intel::cache_parameters::ebx::w::get() == 0x000003FFULL);
}

TEST_CASE("intrinsics: cpuid_intel_cache_parameters_ecx_num_sets")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ecx_cpuid[0x00000004ULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::intel::cache_parameters::ecx::num_sets::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_intel_cache_parameters_edx_wbinvd_invd")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_edx_cpuid[0x00000004ULL] = (0x1U << 0);
    CHECK(cpuid::intel::cache_parameters::edx::wbinvd_invd::get());

    g_edx_cpuid[0x00000004ULL] = ~(0x1U << 0);
    CHECK_FALSE(cpuid::intel::cache_parameters::edx::wbinvd_invd::get());
}

TEST_CASE("intrinsics: cpuid_intel_cache_parameters_edx_cache_inclusiveness")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_edx_cpuid[0x00000004ULL] = (0x1U << 1);
    CHECK(cpuid::intel::cache_parameters::edx::cache_inclusiveness::get());

    g_edx_cpuid[0x00000004ULL] = ~(0x1U << 1);
    CHECK_FALSE(cpuid::intel::cache_parameters::edx::cache_inclusiveness::get());
}

TEST_CASE("intrinsics: cpuid_intel_cache_parameters_edx_complex_cache_indexing")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_edx_cpuid[0x00000004ULL] = (0x1U << 2);
    CHECK(cpuid::intel::cache_parameters::edx::complex_cache_indexing::get());

    g_edx_cpuid[0x00000004ULL] = ~(0x1U << 2);
    CHECK_FALSE(cpuid::intel::cache_parameters::edx::complex_cache_indexing::get());
}

TEST_CASE("intrinsics: cpuid_intel_monitor_mwait_eax_min_line_size")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_eax_cpuid[0x00000005ULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::intel::monitor_mwait::eax::min_line_size::get() == 0x0000FFFFULL);
}

TEST_CASE("intrinsics: cpuid_intel_monitor_mwait_ebx_max_line_size")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ebx_cpuid[0x00000005ULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::intel::monitor_mwait::ebx::max_line_size::get() == 0x0000FFFFULL);
}

TEST_CASE("intrinsics: cpuid_intel_monitor_mwait_ecx_enum_mwait_extensions")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ecx_cpuid[0x00000005ULL] = (0x1U << 0);
    CHECK(cpuid::intel::monitor_mwait::ecx::enum_mwait_extensions::get());

    g_ecx_cpuid[0x00000005ULL] = ~(0x1U << 0);
    CHECK_FALSE(cpuid::intel::monitor_mwait::ecx::enum_mwait_extensions::get());
}

TEST_CASE("intrinsics: cpuid_intel_monitor_mwait_ecx_interrupt_break_event")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ecx_cpuid[0x00000005ULL] = (0x1U << 1);
    CHECK(cpuid::intel::monitor_mwait::ecx::interrupt_break_event::get());

    g_ecx_cpuid[0x00000005ULL] = ~(0x1U << 1);
    CHECK_FALSE(cpuid::intel::monitor_mwait::ecx::interrupt_break_event::get());
}

TEST_CASE("intrinsics: cpuid_intel_monitor_mwait_edx_num_c0")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_edx_cpuid[0x00000005ULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::intel::monitor_mwait::edx::num_c0::get() == 0x0000000FULL);
}

TEST_CASE("intrinsics: cpuid_intel_monitor_mwait_edx_num_c1")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_edx_cpuid[0x00000005ULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::intel::monitor_mwait::edx::num_c1::get() == 0x0000000FULL);
}

TEST_CASE("intrinsics: cpuid_intel_monitor_mwait_edx_num_c2")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_edx_cpuid[0x00000005ULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::intel::monitor_mwait::edx::num_c2::get() == 0x0000000FULL);
}

TEST_CASE("intrinsics: cpuid_intel_monitor_mwait_edx_num_c3")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_edx_cpuid[0x00000005ULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::intel::monitor_mwait::edx::num_c3::get() == 0x0000000FULL);
}

TEST_CASE("intrinsics: cpuid_intel_monitor_mwait_edx_num_c4")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_edx_cpuid[0x00000005ULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::intel::monitor_mwait::edx::num_c4::get() == 0x0000000FULL);
}

TEST_CASE("intrinsics: cpuid_intel_monitor_mwait_edx_num_c5")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_edx_cpuid[0x00000005ULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::intel::monitor_mwait::edx::num_c5::get() == 0x0000000FULL);
}

TEST_CASE("intrinsics: cpuid_intel_monitor_mwait_edx_num_c6")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_edx_cpuid[0x00000005ULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::intel::monitor_mwait::edx::num_c6::get() == 0x0000000FULL);
}

TEST_CASE("intrinsics: cpuid_intel_monitor_mwait_edx_num_c7")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_edx_cpuid[0x00000005ULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::intel::monitor_mwait::edx::num_c7::get() == 0x0000000FULL);
}

TEST_CASE("intrinsics: cpuid_intel_therm_power_management_eax_temp_sensor")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_eax_cpuid[0x00000006ULL] = (0x1U << 0);
    CHECK(cpuid::intel::therm_power_management::eax::temp_sensor::get());

    g_eax_cpuid[0x00000006ULL] = ~(0x1U << 0);
    CHECK_FALSE(cpuid::intel::therm_power_management::eax::temp_sensor::get());
}

TEST_CASE("intrinsics: cpuid_intel_therm_power_management_eax_intel_turbo")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_eax_cpuid[0x00000006ULL] = (0x1U << 1);
    CHECK(cpuid::intel::therm_power_management::eax::intel_turbo::get());

    g_eax_cpuid[0x00000006ULL] = ~(0x1U << 1);
    CHECK_FALSE(cpuid::intel::therm_power_management::eax::intel_turbo::get());
}

TEST_CASE("intrinsics: cpuid_intel_therm_power_management_eax_arat")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_eax_cpuid[0x00000006ULL] = (0x1U << 2);
    CHECK(cpuid::intel::therm_power_management::eax::arat::get());

    g_eax_cpuid[0x00000006ULL] = ~(0x1U << 2);
    CHECK_FALSE(cpuid::intel::therm_power_management::eax::arat::get());
}

TEST_CASE("intrinsics: cpuid_intel_therm_power_management_eax_pln")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_eax_cpuid[0x00000006ULL] = (0x1U << 4);
    CHECK(cpuid::intel::therm_power_management::eax::pln::get());

    g_eax_cpuid[0x00000006ULL] = ~(0x1U << 4);
    CHECK_FALSE(cpuid::intel::therm_power_management::eax::pln::get());
}

TEST_CASE("intrinsics: cpuid_intel_therm_power_management_eax_ecmd")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_eax_cpuid[0x00000006ULL] = (0x1U << 5);
    CHECK(cpuid::intel::therm_power_management::eax::ecmd::get());

    g_eax_cpuid[0x00000006ULL] = ~(0x1U << 5);
    CHECK_FALSE(cpuid::intel::therm_power_management::eax::ecmd::get());
}

TEST_CASE("intrinsics: cpuid_intel_therm_power_management_eax_ptm")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_eax_cpuid[0x00000006ULL] = (0x1U << 6);
    CHECK(cpuid::intel::therm_power_management::eax::ptm::get());

    g_eax_cpuid[0x00000006ULL] = ~(0x1U << 6);
    CHECK_FALSE(cpuid::intel::therm_power_management::eax::ptm::get());
}

TEST_CASE("intrinsics: cpuid_intel_therm_power_management_eax_hwp")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_eax_cpuid[0x00000006ULL] = (0x1U << 7);
    CHECK(cpuid::intel::therm_power_management::eax::hwp::get());

    g_eax_cpuid[0x00000006ULL] = ~(0x1U << 7);
    CHECK_FALSE(cpuid::intel::therm_power_management::eax::hwp::get());
}

TEST_CASE("intrinsics: cpuid_intel_therm_power_management_eax_hwp_notification")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_eax_cpuid[0x00000006ULL] = (0x1U << 8);
    CHECK(cpuid::intel::therm_power_management::eax::hwp_notification::get());

    g_eax_cpuid[0x00000006ULL] = ~(0x1U << 8);
    CHECK_FALSE(cpuid::intel::therm_power_management::eax::hwp_notification::get());
}

TEST_CASE("intrinsics: cpuid_intel_therm_power_management_eax_hwp_activity_window")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_eax_cpuid[0x00000006ULL] = (0x1U << 9);
    CHECK(cpuid::intel::therm_power_management::eax::hwp_activity_window::get());

    g_eax_cpuid[0x00000006ULL] = ~(0x1U << 9);
    CHECK_FALSE(cpuid::intel::therm_power_management::eax::hwp_activity_window::get());
}

TEST_CASE("intrinsics: cpuid_intel_therm_power_management_eax_hwp_energy_perf")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_eax_cpuid[0x00000006ULL] = (0x1U << 10);
    CHECK(cpuid::intel::therm_power_management::eax::hwp_energy_perf::get());

    g_eax_cpuid[0x00000006ULL] = ~(0x1U << 10);
    CHECK_FALSE(cpuid::intel::therm_power_management::eax::hwp_energy_perf::get());
}

TEST_CASE("intrinsics: cpuid_intel_therm_power_management_eax_hwp_package_request")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_eax_cpuid[0x00000006ULL] = (0x1U << 11);
    CHECK(cpuid::intel::therm_power_management::eax::hwp_package_request::get());

    g_eax_cpuid[0x00000006ULL] = ~(0x1U << 11);
    CHECK_FALSE(cpuid::intel::therm_power_management::eax::hwp_package_request::get());
}

TEST_CASE("intrinsics: cpuid_intel_therm_power_management_eax_hdc")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_eax_cpuid[0x00000006ULL] = (0x1U << 13);
    CHECK(cpuid::intel::therm_power_management::eax::hdc::get());

    g_eax_cpuid[0x00000006ULL] = ~(0x1U << 13);
    CHECK_FALSE(cpuid::intel::therm_power_management::eax::hdc::get());
}

TEST_CASE("intrinsics: cpuid_intel_therm_power_management_ebx_num_interrupts")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ebx_cpuid[0x00000006ULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::intel::therm_power_management::ebx::num_interrupts::get() == 0x0000000FULL);
}

TEST_CASE("intrinsics: cpuid_intel_therm_power_management_ecx_hardware_feedback")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ecx_cpuid[0x00000006ULL] = (0x1U << 0);
    CHECK(cpuid::intel::therm_power_management::ecx::hardware_feedback::get());

    g_ecx_cpuid[0x00000006ULL] = ~(0x1U << 0);
    CHECK_FALSE(cpuid::intel::therm_power_management::ecx::hardware_feedback::get());
}

TEST_CASE("intrinsics: cpuid_intel_therm_power_management_ecx_energy_perf_bias")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ecx_cpuid[0x00000006ULL] = (0x1U << 3);
    CHECK(cpuid::intel::therm_power_management::ecx::energy_perf_bias::get());

    g_ecx_cpuid[0x00000006ULL] = ~(0x1U << 3);
    CHECK_FALSE(cpuid::intel::therm_power_management::ecx::energy_perf_bias::get());
}

TEST_CASE("intrinsics: cpuid_intel_access_cache_eax_ia32_platform_dca_cap")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_eax_cpuid[0x00000009ULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::intel::access_cache::eax::ia32_platform_dca_cap::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_intel_topology_enumeration_eax_x2apic_shift")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_eax_cpuid[0x0000000BULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::intel::topology_enumeration::eax::x2apic_shift::get() == 0x0000001FULL);
}

TEST_CASE("intrinsics: cpuid_intel_topology_enumeration_ebx_num_processors")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ebx_cpuid[0x0000000BULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::intel::topology_enumeration::ebx::num_processors::get() == 0x0000FFFFULL);
}

TEST_CASE("intrinsics: cpuid_intel_topology_enumeration_ecx_level_number")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ecx_cpuid[0x0000000BULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::intel::topology_enumeration::ecx::level_number::get() == 0x000000FFULL);
}

TEST_CASE("intrinsics: cpuid_intel_topology_enumeration_ecx_level_type")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ecx_cpuid[0x0000000BULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::intel::topology_enumeration::ecx::level_type::get() == 0x000000FFULL);
}

TEST_CASE("intrinsics: cpuid_intel_topology_enumeration_edx_x2apic_id")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_edx_cpuid[0x0000000BULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::intel::topology_enumeration::edx::x2apic_id::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_intel_extended_state_enum_mainleaf_eax_supported_bits")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_eax_cpuid[0x0000000DULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::intel::extended_state_enum::mainleaf::eax::supported_bits::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_intel_extended_state_enum_mainleaf_ebx_max_size")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ebx_cpuid[0x0000000DULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::intel::extended_state_enum::mainleaf::ebx::max_size::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_intel_extended_state_enum_mainleaf_ecx_max_size")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ecx_cpuid[0x0000000DULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::intel::extended_state_enum::mainleaf::ecx::max_size::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_intel_extended_state_enum_mainleaf_edx_supported_bits")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_edx_cpuid[0x0000000DULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::intel::extended_state_enum::mainleaf::edx::supported_bits::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_intel_extended_state_enum_subleaf0_eax_xsaveopt")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_eax_cpuid[0x0000000DULL] = (0x1U << 0);
    CHECK(cpuid::intel::extended_state_enum::subleaf0::eax::xsaveopt::get());

    g_eax_cpuid[0x0000000DULL] = ~(0x1U << 0);
    CHECK_FALSE(cpuid::intel::extended_state_enum::subleaf0::eax::xsaveopt::get());
}

TEST_CASE("intrinsics: cpuid_intel_extended_state_enum_subleaf0_eax_xsavec")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_eax_cpuid[0x0000000DULL] = (0x1U << 1);
    CHECK(cpuid::intel::extended_state_enum::subleaf0::eax::xsavec::get());

    g_eax_cpuid[0x0000000DULL] = ~(0x1U << 1);
    CHECK_FALSE(cpuid::intel::extended_state_enum::subleaf0::eax::xsavec::get());
}

TEST_CASE("intrinsics: cpuid_intel_extended_state_enum_subleaf0_eax_xgetbv")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_eax_cpuid[0x0000000DULL] = (0x1U << 2);
    CHECK(cpuid::intel::extended_state_enum::subleaf0::eax::xgetbv::get());

    g_eax_cpuid[0x0000000DULL] = ~(0x1U << 2);
    CHECK_FALSE(cpuid::intel::extended_state_enum::subleaf0::eax::xgetbv::get());
}

TEST_CASE("intrinsics: cpuid_intel_extended_state_enum_subleaf0_eax_xsaves_xrstors")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_eax_cpuid[0x0000000DULL] = (0x1U << 3);
    CHECK(cpuid::intel::extended_state_enum::subleaf0::eax::xsaves_xrstors::get());

    g_eax_cpuid[0x0000000DULL] = ~(0x1U << 3);
    CHECK_FALSE(cpuid::intel::extended_state_enum::subleaf0::eax::xsaves_xrstors::get());
}

TEST_CASE("intrinsics: cpuid_intel_extended_state_enum_subleaf0_ebx_xsave_size")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ebx_cpuid[0x0000000DULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::intel::extended_state_enum::subleaf0::ebx::xsave_size::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_intel_extended_state_enum_subleaf0_ecx_supported_bits")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ecx_cpuid[0x0000000DULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::intel::extended_state_enum::subleaf0::ecx::supported_bits::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_intel_extended_state_enum_subleaf0_edx_supported_bits")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_edx_cpuid[0x0000000DULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::intel::extended_state_enum::subleaf0::edx::supported_bits::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_intel_extended_state_enum_subleafn_eax_save_area_size")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_eax_cpuid[0x0000000DULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::intel::extended_state_enum::subleafn::eax::save_area_size::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_intel_extended_state_enum_subleafn_ebx_save_area_offset")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ebx_cpuid[0x0000000DULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::intel::extended_state_enum::subleafn::ebx::save_area_offset::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_intel_extended_state_enum_subleafn_ecx_n_supported")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ecx_cpuid[0x0000000DULL] = (0x1U << 0);
    CHECK(cpuid::intel::extended_state_enum::subleafn::ecx::n_supported::get());

    g_ecx_cpuid[0x0000000DULL] = ~(0x1U << 0);
    CHECK_FALSE(cpuid::intel::extended_state_enum::subleafn::ecx::n_supported::get());
}

TEST_CASE("intrinsics: cpuid_intel_extended_state_enum_subleafn_ecx_location")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ecx_cpuid[0x0000000DULL] = (0x1U << 1);
    CHECK(cpuid::intel::extended_state_enum::subleafn::ecx::location::get());

    g_ecx_cpuid[0x0000000DULL] = ~(0x1U << 1);
    CHECK_FALSE(cpuid::intel::extended_state_enum::subleafn::ecx::location::get());
}

TEST_CASE("intrinsics: cpuid_intel_intel_rdt_subleaf0_ebx_rmid_max_range")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ebx_cpuid[0x0000000FULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::intel::intel_rdt::subleaf0::ebx::rmid_max_range::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_intel_intel_rdt_subleaf0_edx_l3_rdt")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_edx_cpuid[0x0000000FULL] = (0x1U << 1);
    CHECK(cpuid::intel::intel_rdt::subleaf0::edx::l3_rdt::get());

    g_edx_cpuid[0x0000000FULL] = ~(0x1U << 1);
    CHECK_FALSE(cpuid::intel::intel_rdt::subleaf0::edx::l3_rdt::get());
}

TEST_CASE("intrinsics: cpuid_intel_intel_rdt_subleaf1_ebx_conversion_factor")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ebx_cpuid[0x0000000FULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::intel::intel_rdt::subleaf1::ebx::conversion_factor::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_intel_intel_rdt_subleaf1_ecx_rmid_max_range")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ecx_cpuid[0x0000000FULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::intel::intel_rdt::subleaf1::ecx::rmid_max_range::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_intel_intel_rdt_subleaf1_edx_l3_occupancy")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_edx_cpuid[0x0000000FULL] = (0x1U << 0);
    CHECK(cpuid::intel::intel_rdt::subleaf1::edx::l3_occupancy::get());

    g_edx_cpuid[0x0000000FULL] = ~(0x1U << 0);
    CHECK_FALSE(cpuid::intel::intel_rdt::subleaf1::edx::l3_occupancy::get());
}

TEST_CASE("intrinsics: cpuid_intel_intel_rdt_subleaf1_edx_l3_total_bandwith")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_edx_cpuid[0x0000000FULL] = (0x1U << 1);
    CHECK(cpuid::intel::intel_rdt::subleaf1::edx::l3_total_bandwith::get());

    g_edx_cpuid[0x0000000FULL] = ~(0x1U << 1);
    CHECK_FALSE(cpuid::intel::intel_rdt::subleaf1::edx::l3_total_bandwith::get());
}

TEST_CASE("intrinsics: cpuid_intel_intel_rdt_subleaf1_edx_l3_local_bandwith")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_edx_cpuid[0x0000000FULL] = (0x1U << 2);
    CHECK(cpuid::intel::intel_rdt::subleaf1::edx::l3_local_bandwith::get());

    g_edx_cpuid[0x0000000FULL] = ~(0x1U << 2);
    CHECK_FALSE(cpuid::intel::intel_rdt::subleaf1::edx::l3_local_bandwith::get());
}

TEST_CASE("intrinsics: cpuid_intel_allocation_enumeration_subleaf0_ebx_l3_cache")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ebx_cpuid[0x00000010ULL] = (0x1U << 1);
    CHECK(cpuid::intel::allocation_enumeration::subleaf0::ebx::l3_cache::get());

    g_ebx_cpuid[0x00000010ULL] = ~(0x1U << 1);
    CHECK_FALSE(cpuid::intel::allocation_enumeration::subleaf0::ebx::l3_cache::get());
}

TEST_CASE("intrinsics: cpuid_intel_allocation_enumeration_subleaf0_ebx_l2_cache")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ebx_cpuid[0x00000010ULL] = (0x1U << 2);
    CHECK(cpuid::intel::allocation_enumeration::subleaf0::ebx::l2_cache::get());

    g_ebx_cpuid[0x00000010ULL] = ~(0x1U << 2);
    CHECK_FALSE(cpuid::intel::allocation_enumeration::subleaf0::ebx::l2_cache::get());
}

TEST_CASE("intrinsics: cpuid_intel_allocation_enumeration_subleaf0_ebx_mem_bandwidth")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ebx_cpuid[0x00000010ULL] = (0x1U << 3);
    CHECK(cpuid::intel::allocation_enumeration::subleaf0::ebx::mem_bandwidth::get());

    g_ebx_cpuid[0x00000010ULL] = ~(0x1U << 3);
    CHECK_FALSE(cpuid::intel::allocation_enumeration::subleaf0::ebx::mem_bandwidth::get());
}

TEST_CASE("intrinsics: cpuid_intel_allocation_enumeration_subleaf1_eax_mask_length")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_eax_cpuid[0x00000010ULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::intel::allocation_enumeration::subleaf1::eax::mask_length::get() == 0x0000001FULL);
}

TEST_CASE("intrinsics: cpuid_intel_allocation_enumeration_subleaf1_ebx_map")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ebx_cpuid[0x00000010ULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::intel::allocation_enumeration::subleaf1::ebx::map::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_intel_allocation_enumeration_subleaf1_ecx_data_prio")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ecx_cpuid[0x00000010ULL] = (0x1U << 2);
    CHECK(cpuid::intel::allocation_enumeration::subleaf1::ecx::data_prio::get());

    g_ecx_cpuid[0x00000010ULL] = ~(0x1U << 2);
    CHECK_FALSE(cpuid::intel::allocation_enumeration::subleaf1::ecx::data_prio::get());
}

TEST_CASE("intrinsics: cpuid_intel_allocation_enumeration_subleaf1_edx_max_cos")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_edx_cpuid[0x00000010ULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::intel::allocation_enumeration::subleaf1::edx::max_cos::get() == 0x0000FFFFULL);
}

TEST_CASE("intrinsics: cpuid_intel_allocation_enumeration_subleaf2_eax_mask_length")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_eax_cpuid[0x00000010ULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::intel::allocation_enumeration::subleaf2::eax::mask_length::get() == 0x0000001FULL);
}

TEST_CASE("intrinsics: cpuid_intel_allocation_enumeration_subleaf2_ebx_map")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ebx_cpuid[0x00000010ULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::intel::allocation_enumeration::subleaf2::ebx::map::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_intel_allocation_enumeration_subleaf2_edx_max_cos")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_edx_cpuid[0x00000010ULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::intel::allocation_enumeration::subleaf2::edx::max_cos::get() == 0x0000FFFFULL);
}

TEST_CASE("intrinsics: cpuid_intel_allocation_enumeration_subleaf3_eax_max_throttle")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_eax_cpuid[0x00000010ULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::intel::allocation_enumeration::subleaf3::eax::max_throttle::get() == 0x00000FFFULL);
}

TEST_CASE("intrinsics: cpuid_intel_allocation_enumeration_subleaf3_ecx_linear")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ecx_cpuid[0x00000010ULL] = (0x1U << 2);
    CHECK(cpuid::intel::allocation_enumeration::subleaf3::ecx::linear::get());

    g_ecx_cpuid[0x00000010ULL] = ~(0x1U << 2);
    CHECK_FALSE(cpuid::intel::allocation_enumeration::subleaf3::ecx::linear::get());
}

TEST_CASE("intrinsics: cpuid_intel_allocation_enumeration_subleaf3_edx_max_cos")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_edx_cpuid[0x00000010ULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::intel::allocation_enumeration::subleaf3::edx::max_cos::get() == 0x0000FFFFULL);
}

TEST_CASE("intrinsics: cpuid_intel_intel_sgx_subleaf0_eax_sgx1")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_eax_cpuid[0x00000012ULL] = (0x1U << 0);
    CHECK(cpuid::intel::intel_sgx::subleaf0::eax::sgx1::get());

    g_eax_cpuid[0x00000012ULL] = ~(0x1U << 0);
    CHECK_FALSE(cpuid::intel::intel_sgx::subleaf0::eax::sgx1::get());
}

TEST_CASE("intrinsics: cpuid_intel_intel_sgx_subleaf0_eax_sgx2")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_eax_cpuid[0x00000012ULL] = (0x1U << 1);
    CHECK(cpuid::intel::intel_sgx::subleaf0::eax::sgx2::get());

    g_eax_cpuid[0x00000012ULL] = ~(0x1U << 1);
    CHECK_FALSE(cpuid::intel::intel_sgx::subleaf0::eax::sgx2::get());
}

TEST_CASE("intrinsics: cpuid_intel_intel_sgx_subleaf0_ebx_miscselect")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ebx_cpuid[0x00000012ULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::intel::intel_sgx::subleaf0::ebx::miscselect::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_intel_intel_sgx_subleaf0_edx_mes_not64")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_edx_cpuid[0x00000012ULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::intel::intel_sgx::subleaf0::edx::mes_not64::get() == 0x000000FFULL);
}

TEST_CASE("intrinsics: cpuid_intel_intel_sgx_subleaf0_edx_mes_64")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_edx_cpuid[0x00000012ULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::intel::intel_sgx::subleaf0::edx::mes_64::get() == 0x000000FFULL);
}

TEST_CASE("intrinsics: cpuid_intel_intel_sgx_subleaf1_part1")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_eax_cpuid[0x00000012ULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::intel::intel_sgx::subleaf1::part1::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_intel_intel_sgx_subleaf1_part2")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ebx_cpuid[0x00000012ULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::intel::intel_sgx::subleaf1::part2::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_intel_intel_sgx_subleaf1_part3")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ecx_cpuid[0x00000012ULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::intel::intel_sgx::subleaf1::part3::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_intel_intel_sgx_subleaf1_part4")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_edx_cpuid[0x00000012ULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::intel::intel_sgx::subleaf1::part4::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_intel_intel_sgx_subleaf2_eax_subleaf_type")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_eax_cpuid[0x00000012ULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::intel::intel_sgx::subleaf2::eax::subleaf_type::get() == 0x0000000FULL);
}

TEST_CASE("intrinsics: cpuid_intel_intel_sgx_subleaf2_eax_address")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_eax_cpuid[0x00000012ULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::intel::intel_sgx::subleaf2::eax::address::get() == 0x000FFFFFULL);
}

TEST_CASE("intrinsics: cpuid_intel_intel_sgx_subleaf2_ebx_address")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ebx_cpuid[0x00000012ULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::intel::intel_sgx::subleaf2::ebx::address::get() == 0x000FFFFFULL);
}

TEST_CASE("intrinsics: cpuid_intel_intel_sgx_subleaf2_ecx_epc_property")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ecx_cpuid[0x00000012ULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::intel::intel_sgx::subleaf2::ecx::epc_property::get() == 0x0000000FULL);
}

TEST_CASE("intrinsics: cpuid_intel_intel_sgx_subleaf2_ecx_epc_size")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ecx_cpuid[0x00000012ULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::intel::intel_sgx::subleaf2::ecx::epc_size::get() == 0x000FFFFFULL);
}

TEST_CASE("intrinsics: cpuid_intel_intel_sgx_subleaf2_edx_epc_size")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_edx_cpuid[0x00000012ULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::intel::intel_sgx::subleaf2::edx::epc_size::get() == 0x000FFFFFULL);
}

TEST_CASE("intrinsics: cpuid_intel_trace_enumeration_mainleaf_eax_max_subleaf")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_eax_cpuid[0x00000014ULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::intel::trace_enumeration::mainleaf::eax::max_subleaf::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_intel_trace_enumeration_mainleaf_ebx_ia32_rtit_ctlcr3filter")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ebx_cpuid[0x00000014ULL] = (0x1U << 0);
    CHECK(cpuid::intel::trace_enumeration::mainleaf::ebx::ia32_rtit_ctlcr3filter::get());

    g_ebx_cpuid[0x00000014ULL] = ~(0x1U << 0);
    CHECK_FALSE(cpuid::intel::trace_enumeration::mainleaf::ebx::ia32_rtit_ctlcr3filter::get());
}

TEST_CASE("intrinsics: cpuid_intel_trace_enumeration_mainleaf_ebx_configurable_psb")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ebx_cpuid[0x00000014ULL] = (0x1U << 1);
    CHECK(cpuid::intel::trace_enumeration::mainleaf::ebx::configurable_psb::get());

    g_ebx_cpuid[0x00000014ULL] = ~(0x1U << 1);
    CHECK_FALSE(cpuid::intel::trace_enumeration::mainleaf::ebx::configurable_psb::get());
}

TEST_CASE("intrinsics: cpuid_intel_trace_enumeration_mainleaf_ebx_ip_filtering")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ebx_cpuid[0x00000014ULL] = (0x1U << 2);
    CHECK(cpuid::intel::trace_enumeration::mainleaf::ebx::ip_filtering::get());

    g_ebx_cpuid[0x00000014ULL] = ~(0x1U << 2);
    CHECK_FALSE(cpuid::intel::trace_enumeration::mainleaf::ebx::ip_filtering::get());
}

TEST_CASE("intrinsics: cpuid_intel_trace_enumeration_mainleaf_ebx_mtc_timing_packet")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ebx_cpuid[0x00000014ULL] = (0x1U << 3);
    CHECK(cpuid::intel::trace_enumeration::mainleaf::ebx::mtc_timing_packet::get());

    g_ebx_cpuid[0x00000014ULL] = ~(0x1U << 3);
    CHECK_FALSE(cpuid::intel::trace_enumeration::mainleaf::ebx::mtc_timing_packet::get());
}

TEST_CASE("intrinsics: cpuid_intel_trace_enumeration_mainleaf_ebx_ptwrite")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ebx_cpuid[0x00000014ULL] = (0x1U << 4);
    CHECK(cpuid::intel::trace_enumeration::mainleaf::ebx::ptwrite::get());

    g_ebx_cpuid[0x00000014ULL] = ~(0x1U << 4);
    CHECK_FALSE(cpuid::intel::trace_enumeration::mainleaf::ebx::ptwrite::get());
}

TEST_CASE("intrinsics: cpuid_intel_trace_enumeration_mainleaf_ebx_power_event_trace")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ebx_cpuid[0x00000014ULL] = (0x1U << 5);
    CHECK(cpuid::intel::trace_enumeration::mainleaf::ebx::power_event_trace::get());

    g_ebx_cpuid[0x00000014ULL] = ~(0x1U << 5);
    CHECK_FALSE(cpuid::intel::trace_enumeration::mainleaf::ebx::power_event_trace::get());
}

TEST_CASE("intrinsics: cpuid_intel_trace_enumeration_mainleaf_ecx_trading_enabled")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ecx_cpuid[0x00000014ULL] = (0x1U << 0);
    CHECK(cpuid::intel::trace_enumeration::mainleaf::ecx::trading_enabled::get());

    g_ecx_cpuid[0x00000014ULL] = ~(0x1U << 0);
    CHECK_FALSE(cpuid::intel::trace_enumeration::mainleaf::ecx::trading_enabled::get());
}

TEST_CASE("intrinsics: cpuid_intel_trace_enumeration_mainleaf_ecx_topa_entry")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ecx_cpuid[0x00000014ULL] = (0x1U << 1);
    CHECK(cpuid::intel::trace_enumeration::mainleaf::ecx::topa_entry::get());

    g_ecx_cpuid[0x00000014ULL] = ~(0x1U << 1);
    CHECK_FALSE(cpuid::intel::trace_enumeration::mainleaf::ecx::topa_entry::get());
}

TEST_CASE("intrinsics: cpuid_intel_trace_enumeration_mainleaf_ecx_single_range_output")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ecx_cpuid[0x00000014ULL] = (0x1U << 2);
    CHECK(cpuid::intel::trace_enumeration::mainleaf::ecx::single_range_output::get());

    g_ecx_cpuid[0x00000014ULL] = ~(0x1U << 2);
    CHECK_FALSE(cpuid::intel::trace_enumeration::mainleaf::ecx::single_range_output::get());
}

TEST_CASE("intrinsics: cpuid_intel_trace_enumeration_mainleaf_ecx_trace_transport")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ecx_cpuid[0x00000014ULL] = (0x1U << 3);
    CHECK(cpuid::intel::trace_enumeration::mainleaf::ecx::trace_transport::get());

    g_ecx_cpuid[0x00000014ULL] = ~(0x1U << 3);
    CHECK_FALSE(cpuid::intel::trace_enumeration::mainleaf::ecx::trace_transport::get());
}

TEST_CASE("intrinsics: cpuid_intel_trace_enumeration_mainleaf_ecx_lip_values")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ecx_cpuid[0x00000014ULL] = (0x1U << 31);
    CHECK(cpuid::intel::trace_enumeration::mainleaf::ecx::lip_values::get());

    g_ecx_cpuid[0x00000014ULL] = ~(0x1U << 31);
    CHECK_FALSE(cpuid::intel::trace_enumeration::mainleaf::ecx::lip_values::get());
}

TEST_CASE("intrinsics: cpuid_intel_trace_enumeration_subleaf_eax_num_address_ranges")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_eax_cpuid[0x00000014ULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::intel::trace_enumeration::subleaf::eax::num_address_ranges::get() == 0x00000007ULL);
}

TEST_CASE("intrinsics: cpuid_intel_trace_enumeration_subleaf_eax_bitmap_mtc")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_eax_cpuid[0x00000014ULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::intel::trace_enumeration::subleaf::eax::bitmap_mtc::get() == 0x0000FFFFULL);
}

TEST_CASE("intrinsics: cpuid_intel_trace_enumeration_subleaf_ebx_bitmap_cycle_threshold")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ebx_cpuid[0x00000014ULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::intel::trace_enumeration::subleaf::ebx::bitmap_cycle_threshold::get() == 0x0000FFFFULL);
}

TEST_CASE("intrinsics: cpuid_intel_trace_enumeration_subleaf_ebx_bitmap_psb")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ebx_cpuid[0x00000014ULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::intel::trace_enumeration::subleaf::ebx::bitmap_psb::get() == 0x0000FFFFULL);
}

TEST_CASE("intrinsics: cpuid_intel_time_stamp_count_eax_tsc_denom")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_eax_cpuid[0x00000015ULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::intel::time_stamp_count::eax::tsc_denom::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_intel_time_stamp_count_ebx_tsc_numer")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ebx_cpuid[0x00000015ULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::intel::time_stamp_count::ebx::tsc_numer::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_intel_time_stamp_count_ecx_nominal_freq")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ecx_cpuid[0x00000015ULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::intel::time_stamp_count::ecx::nominal_freq::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_intel_processor_freq_eax_base_freq")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_eax_cpuid[0x00000016ULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::intel::processor_freq::eax::base_freq::get() == 0x0000FFFFULL);
}

TEST_CASE("intrinsics: cpuid_intel_processor_freq_ebx_max_freq")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ebx_cpuid[0x00000016ULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::intel::processor_freq::ebx::max_freq::get() == 0x0000FFFFULL);
}

TEST_CASE("intrinsics: cpuid_intel_processor_freq_ecx_bus_freq")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ecx_cpuid[0x00000016ULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::intel::processor_freq::ecx::bus_freq::get() == 0x0000FFFFULL);
}

TEST_CASE("intrinsics: cpuid_intel_vendor_attribute_mainleaf_max_socid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_eax_cpuid[0x00000017ULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::intel::vendor_attribute::mainleaf::max_socid::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_intel_vendor_attribute_mainleaf_ebx_soc_vendor")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ebx_cpuid[0x00000017ULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::intel::vendor_attribute::mainleaf::ebx::soc_vendor::get() == 0x0000FFFFULL);
}

TEST_CASE("intrinsics: cpuid_intel_vendor_attribute_mainleaf_ebx_is_vendor_scheme")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ebx_cpuid[0x00000017ULL] = (0x1U << 16);
    CHECK(cpuid::intel::vendor_attribute::mainleaf::ebx::is_vendor_scheme::get());

    g_ebx_cpuid[0x00000017ULL] = ~(0x1U << 16);
    CHECK_FALSE(cpuid::intel::vendor_attribute::mainleaf::ebx::is_vendor_scheme::get());
}

TEST_CASE("intrinsics: cpuid_intel_vendor_attribute_mainleaf_ecx_project_id")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ecx_cpuid[0x00000017ULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::intel::vendor_attribute::mainleaf::ecx::project_id::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_intel_vendor_attribute_mainleaf_edx_stepping_id")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_edx_cpuid[0x00000017ULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::intel::vendor_attribute::mainleaf::edx::stepping_id::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_intel_vendor_attribute_subleaf1_eax_brand_string")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_eax_cpuid[0x00000017ULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::intel::vendor_attribute::subleaf1::eax::brand_string::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_intel_vendor_attribute_subleaf1_ebx_brand_string")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ebx_cpuid[0x00000017ULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::intel::vendor_attribute::subleaf1::ebx::brand_string::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_intel_vendor_attribute_subleaf1_ecx_brand_string")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ecx_cpuid[0x00000017ULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::intel::vendor_attribute::subleaf1::ecx::brand_string::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_intel_vendor_attribute_subleaf1_edx_brand_string")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_edx_cpuid[0x00000017ULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::intel::vendor_attribute::subleaf1::edx::brand_string::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_intel_ext_feature_info_ecx_lahf_sahf")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ecx_cpuid[0x80000001ULL] = (0x1U << 0);
    CHECK(cpuid::intel::ext_feature_info::ecx::lahf_sahf::get());

    g_ecx_cpuid[0x80000001ULL] = ~(0x1U << 0);
    CHECK_FALSE(cpuid::intel::ext_feature_info::ecx::lahf_sahf::get());
}

TEST_CASE("intrinsics: cpuid_intel_ext_feature_info_ecx_lzcnt")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ecx_cpuid[0x80000001ULL] = (0x1U << 5);
    CHECK(cpuid::intel::ext_feature_info::ecx::lzcnt::get());

    g_ecx_cpuid[0x80000001ULL] = ~(0x1U << 5);
    CHECK_FALSE(cpuid::intel::ext_feature_info::ecx::lzcnt::get());
}

TEST_CASE("intrinsics: cpuid_intel_ext_feature_info_ecx_prefetchw")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ecx_cpuid[0x80000001ULL] = (0x1U << 8);
    CHECK(cpuid::intel::ext_feature_info::ecx::prefetchw::get());

    g_ecx_cpuid[0x80000001ULL] = ~(0x1U << 8);
    CHECK_FALSE(cpuid::intel::ext_feature_info::ecx::prefetchw::get());
}

TEST_CASE("intrinsics: cpuid_intel_ext_feature_info_edx_syscall_sysret")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_edx_cpuid[0x80000001ULL] = (0x1U << 11);
    CHECK(cpuid::intel::ext_feature_info::edx::syscall_sysret::get());

    g_edx_cpuid[0x80000001ULL] = ~(0x1U << 11);
    CHECK_FALSE(cpuid::intel::ext_feature_info::edx::syscall_sysret::get());
}

TEST_CASE("intrinsics: cpuid_intel_ext_feature_info_edx_execute_disable_bit")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_edx_cpuid[0x80000001ULL] = (0x1U << 20);
    CHECK(cpuid::intel::ext_feature_info::edx::execute_disable_bit::get());

    g_edx_cpuid[0x80000001ULL] = ~(0x1U << 20);
    CHECK_FALSE(cpuid::intel::ext_feature_info::edx::execute_disable_bit::get());
}

TEST_CASE("intrinsics: cpuid_intel_ext_feature_info_edx_pages_avail")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_edx_cpuid[0x80000001ULL] = (0x1U << 26);
    CHECK(cpuid::intel::ext_feature_info::edx::pages_avail::get());

    g_edx_cpuid[0x80000001ULL] = ~(0x1U << 26);
    CHECK_FALSE(cpuid::intel::ext_feature_info::edx::pages_avail::get());
}

TEST_CASE("intrinsics: cpuid_intel_ext_feature_info_edx_rdtscp")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_edx_cpuid[0x80000001ULL] = (0x1U << 27);
    CHECK(cpuid::intel::ext_feature_info::edx::rdtscp::get());

    g_edx_cpuid[0x80000001ULL] = ~(0x1U << 27);
    CHECK_FALSE(cpuid::intel::ext_feature_info::edx::rdtscp::get());
}

TEST_CASE("intrinsics: cpuid_intel_ext_feature_info_edx_intel_64")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_edx_cpuid[0x80000001ULL] = (0x1U << 29);
    CHECK(cpuid::intel::ext_feature_info::edx::intel_64::get());

    g_edx_cpuid[0x80000001ULL] = ~(0x1U << 29);
    CHECK_FALSE(cpuid::intel::ext_feature_info::edx::intel_64::get());
}

TEST_CASE("intrinsics: cpuid_intel_l2_info_ecx_line_size")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ecx_cpuid[0x80000006ULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::intel::l2_info::ecx::line_size::get() == 0x000000FFULL);
}

TEST_CASE("intrinsics: cpuid_intel_l2_info_ecx_l2_associativity")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ecx_cpuid[0x80000006ULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::intel::l2_info::ecx::l2_associativity::get() == 0x0000000FULL);
}

TEST_CASE("intrinsics: cpuid_intel_l2_info_ecx_cache_size")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_ecx_cpuid[0x80000006ULL] = 0xFFFFFFFFULL;
    CHECK(cpuid::intel::l2_info::ecx::cache_size::get() == 0x0000FFFFULL);
}

TEST_CASE("intrinsics: cpuid_intel_invariant_tsc_edx_available")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_edx_cpuid[0x80000007ULL] = (0x1U << 8);
    CHECK(cpuid::intel::invariant_tsc::edx::available::get());

    g_edx_cpuid[0x80000007ULL] = ~(0x1U << 8);
    CHECK_FALSE(cpuid::intel::invariant_tsc::edx::available::get());
}

#endif
