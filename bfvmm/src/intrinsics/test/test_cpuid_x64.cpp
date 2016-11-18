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
#include <intrinsics/cpuid_x64.h>

using namespace x64;

std::map<uint32_t, uint32_t> g_eax_cpuid;
std::map<uint32_t, uint32_t> g_ebx_cpuid;
std::map<uint32_t, uint32_t> g_ecx_cpuid;
std::map<uint32_t, uint32_t> g_edx_cpuid;

extern "C" uint32_t __cpuid_eax(uint32_t val) noexcept;
extern "C" uint32_t __cpuid_ebx(uint32_t val) noexcept;
extern "C" uint32_t __cpuid_ecx(uint32_t val) noexcept;
extern "C" uint32_t __cpuid_edx(uint32_t val) noexcept;
extern "C" void __cpuid(void *eax, void *ebx, void *ecx, void *edx) noexcept;

struct cpuid_regs
{
    uint32_t eax;
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;
};

struct cpuid_regs g_regs;

extern "C" uint32_t
__cpuid_eax(uint32_t val) noexcept
{ return g_eax_cpuid[val]; }

extern "C" uint32_t
__cpuid_ebx(uint32_t val) noexcept
{ return g_ebx_cpuid[val]; }

extern "C" uint32_t
__cpuid_ecx(uint32_t val) noexcept
{ return g_ecx_cpuid[val]; }

extern "C" uint32_t
__cpuid_edx(uint32_t val) noexcept
{ return g_edx_cpuid[val]; }

extern "C" void
__cpuid(void *eax, void *ebx, void *ecx, void *edx) noexcept
{
    *static_cast<uint32_t *>(eax) = g_regs.eax;
    *static_cast<uint32_t *>(ebx) = g_regs.ebx;
    *static_cast<uint32_t *>(ecx) = g_regs.ecx;
    *static_cast<uint32_t *>(edx) = g_regs.edx;
}

void
intrinsics_ut::test_cpuid_x64_cpuid()
{
    g_regs.eax = 1U;
    g_regs.ebx = 2U;
    g_regs.ecx = 3U;
    g_regs.edx = 4U;

    auto ret = cpuid::get(g_regs.eax, g_regs.ebx, g_regs.ecx, g_regs.edx);

    this->expect_true(std::get<0>(ret) == 1U);
    this->expect_true(std::get<1>(ret) == 2U);
    this->expect_true(std::get<2>(ret) == 3U);
    this->expect_true(std::get<3>(ret) == 4U);
}

void
intrinsics_ut::test_cpuid_x64_cpuid_eax()
{
    g_eax_cpuid[10U] = 42U;
    this->expect_true(cpuid::eax::get(10U) == 42U);
    this->expect_true(cpuid::eax::get(10UL) == 42U);
}

void
intrinsics_ut::test_cpuid_x64_cpuid_ebx()
{
    g_ebx_cpuid[10U] = 42U;
    this->expect_true(cpuid::ebx::get(10U) == 42U);
    this->expect_true(cpuid::ebx::get(10UL) == 42U);
}

void
intrinsics_ut::test_cpuid_x64_cpuid_ecx()
{
    g_ecx_cpuid[10U] = 42U;
    this->expect_true(cpuid::ecx::get(10U) == 42U);
    this->expect_true(cpuid::ecx::get(10UL) == 42U);
}

void
intrinsics_ut::test_cpuid_x64_cpuid_edx()
{
    g_edx_cpuid[10U] = 42U;
    this->expect_true(cpuid::edx::get(10U) == 42U);
    this->expect_true(cpuid::edx::get(10UL) == 42U);
}

void
intrinsics_ut::test_cpuid_x64_cpuid_addr_size_phys()
{
    g_eax_cpuid[cpuid::addr_size::addr] = 0x12345610;
    this->expect_true(cpuid::addr_size::phys::get() == 0x10);
}

void
intrinsics_ut::test_cpuid_x64_cpuid_addr_size_linear()
{
    g_eax_cpuid[cpuid::addr_size::addr] = 0x12341056;
    this->expect_true(cpuid::addr_size::linear::get() == 0x10);
}

void
intrinsics_ut::test_cpuid_x64_cpuid_feature_information_ecx_sse3()
{
    g_ecx_cpuid[cpuid::feature_information::addr] = 0x1UL << 0;
    this->expect_true(cpuid::feature_information::ecx::sse3::get());

    g_ecx_cpuid[cpuid::feature_information::addr] = ~(0x1U << 0);
    this->expect_false(cpuid::feature_information::ecx::sse3::get());
}

void
intrinsics_ut::test_cpuid_x64_cpuid_feature_information_ecx_pclmulqdq()
{
    g_ecx_cpuid[cpuid::feature_information::addr] = 0x1UL << 1;
    this->expect_true(cpuid::feature_information::ecx::pclmulqdq::get());

    g_ecx_cpuid[cpuid::feature_information::addr] = ~(0x1U << 1);
    this->expect_false(cpuid::feature_information::ecx::pclmulqdq::get());
}

void
intrinsics_ut::test_cpuid_x64_cpuid_feature_information_ecx_dtes64()
{
    g_ecx_cpuid[cpuid::feature_information::addr] = 0x1UL << 2;
    this->expect_true(cpuid::feature_information::ecx::dtes64::get());

    g_ecx_cpuid[cpuid::feature_information::addr] = ~(0x1U << 2);
    this->expect_false(cpuid::feature_information::ecx::dtes64::get());
}

void
intrinsics_ut::test_cpuid_x64_cpuid_feature_information_ecx_monitor()
{
    g_ecx_cpuid[cpuid::feature_information::addr] = 0x1UL << 3;
    this->expect_true(cpuid::feature_information::ecx::monitor::get());

    g_ecx_cpuid[cpuid::feature_information::addr] = ~(0x1U << 3);
    this->expect_false(cpuid::feature_information::ecx::monitor::get());
}

void
intrinsics_ut::test_cpuid_x64_cpuid_feature_information_ecx_ds_cpl()
{
    g_ecx_cpuid[cpuid::feature_information::addr] = 0x1UL << 4;
    this->expect_true(cpuid::feature_information::ecx::ds_cpl::get());

    g_ecx_cpuid[cpuid::feature_information::addr] = ~(0x1U << 4);
    this->expect_false(cpuid::feature_information::ecx::ds_cpl::get());
}

void
intrinsics_ut::test_cpuid_x64_cpuid_feature_information_ecx_vmx()
{
    g_ecx_cpuid[cpuid::feature_information::addr] = 0x1UL << 5;
    this->expect_true(cpuid::feature_information::ecx::vmx::get());

    g_ecx_cpuid[cpuid::feature_information::addr] = ~(0x1U << 5);
    this->expect_false(cpuid::feature_information::ecx::vmx::get());
}

void
intrinsics_ut::test_cpuid_x64_cpuid_feature_information_ecx_smx()
{
    g_ecx_cpuid[cpuid::feature_information::addr] = 0x1UL << 6;
    this->expect_true(cpuid::feature_information::ecx::smx::get());

    g_ecx_cpuid[cpuid::feature_information::addr] = ~(0x1U << 6);
    this->expect_false(cpuid::feature_information::ecx::smx::get());
}

void
intrinsics_ut::test_cpuid_x64_cpuid_feature_information_ecx_eist()
{
    g_ecx_cpuid[cpuid::feature_information::addr] = 0x1UL << 7;
    this->expect_true(cpuid::feature_information::ecx::eist::get());

    g_ecx_cpuid[cpuid::feature_information::addr] = ~(0x1U << 7);
    this->expect_false(cpuid::feature_information::ecx::eist::get());
}

void
intrinsics_ut::test_cpuid_x64_cpuid_feature_information_ecx_tm2()
{
    g_ecx_cpuid[cpuid::feature_information::addr] = 0x1UL << 8;
    this->expect_true(cpuid::feature_information::ecx::tm2::get());

    g_ecx_cpuid[cpuid::feature_information::addr] = ~(0x1U << 8);
    this->expect_false(cpuid::feature_information::ecx::tm2::get());
}

void
intrinsics_ut::test_cpuid_x64_cpuid_feature_information_ecx_ssse3()
{
    g_ecx_cpuid[cpuid::feature_information::addr] = 0x1UL << 9;
    this->expect_true(cpuid::feature_information::ecx::ssse3::get());

    g_ecx_cpuid[cpuid::feature_information::addr] = ~(0x1U << 9);
    this->expect_false(cpuid::feature_information::ecx::ssse3::get());
}

void
intrinsics_ut::test_cpuid_x64_cpuid_feature_information_ecx_cnxt_id()
{
    g_ecx_cpuid[cpuid::feature_information::addr] = 0x1UL << 10;
    this->expect_true(cpuid::feature_information::ecx::cnxt_id::get());

    g_ecx_cpuid[cpuid::feature_information::addr] = ~(0x1U << 10);
    this->expect_false(cpuid::feature_information::ecx::cnxt_id::get());
}

void
intrinsics_ut::test_cpuid_x64_cpuid_feature_information_ecx_sdbg()
{
    g_ecx_cpuid[cpuid::feature_information::addr] = 0x1UL << 11;
    this->expect_true(cpuid::feature_information::ecx::sdbg::get());

    g_ecx_cpuid[cpuid::feature_information::addr] = ~(0x1U << 11);
    this->expect_false(cpuid::feature_information::ecx::sdbg::get());
}

void
intrinsics_ut::test_cpuid_x64_cpuid_feature_information_ecx_fma()
{
    g_ecx_cpuid[cpuid::feature_information::addr] = 0x1UL << 12;
    this->expect_true(cpuid::feature_information::ecx::fma::get());

    g_ecx_cpuid[cpuid::feature_information::addr] = ~(0x1U << 12);
    this->expect_false(cpuid::feature_information::ecx::fma::get());
}

void
intrinsics_ut::test_cpuid_x64_cpuid_feature_information_ecx_cmpxchg16b()
{
    g_ecx_cpuid[cpuid::feature_information::addr] = 0x1UL << 13;
    this->expect_true(cpuid::feature_information::ecx::cmpxchg16b::get());

    g_ecx_cpuid[cpuid::feature_information::addr] = ~(0x1U << 13);
    this->expect_false(cpuid::feature_information::ecx::cmpxchg16b::get());
}

void
intrinsics_ut::test_cpuid_x64_cpuid_feature_information_ecx_xtpr_update_control()
{
    g_ecx_cpuid[cpuid::feature_information::addr] = 0x1UL << 14;
    this->expect_true(cpuid::feature_information::ecx::xtpr_update_control::get());

    g_ecx_cpuid[cpuid::feature_information::addr] = ~(0x1U << 14);
    this->expect_false(cpuid::feature_information::ecx::xtpr_update_control::get());
}

void
intrinsics_ut::test_cpuid_x64_cpuid_feature_information_ecx_pdcm()
{
    g_ecx_cpuid[cpuid::feature_information::addr] = 0x1UL << 15;
    this->expect_true(cpuid::feature_information::ecx::pdcm::get());

    g_ecx_cpuid[cpuid::feature_information::addr] = ~(0x1U << 15);
    this->expect_false(cpuid::feature_information::ecx::pdcm::get());
}

void
intrinsics_ut::test_cpuid_x64_cpuid_feature_information_ecx_pcid()
{
    g_ecx_cpuid[cpuid::feature_information::addr] = 0x1UL << 17;
    this->expect_true(cpuid::feature_information::ecx::pcid::get());

    g_ecx_cpuid[cpuid::feature_information::addr] = ~(0x1U << 17);
    this->expect_false(cpuid::feature_information::ecx::pcid::get());
}

void
intrinsics_ut::test_cpuid_x64_cpuid_feature_information_ecx_dca()
{
    g_ecx_cpuid[cpuid::feature_information::addr] = 0x1UL << 18;
    this->expect_true(cpuid::feature_information::ecx::dca::get());

    g_ecx_cpuid[cpuid::feature_information::addr] = ~(0x1U << 18);
    this->expect_false(cpuid::feature_information::ecx::dca::get());
}

void
intrinsics_ut::test_cpuid_x64_cpuid_feature_information_ecx_sse41()
{
    g_ecx_cpuid[cpuid::feature_information::addr] = 0x1UL << 19;
    this->expect_true(cpuid::feature_information::ecx::sse41::get());

    g_ecx_cpuid[cpuid::feature_information::addr] = ~(0x1U << 19);
    this->expect_false(cpuid::feature_information::ecx::sse41::get());
}

void
intrinsics_ut::test_cpuid_x64_cpuid_feature_information_ecx_sse42()
{
    g_ecx_cpuid[cpuid::feature_information::addr] = 0x1UL << 20;
    this->expect_true(cpuid::feature_information::ecx::sse42::get());

    g_ecx_cpuid[cpuid::feature_information::addr] = ~(0x1U << 20);
    this->expect_false(cpuid::feature_information::ecx::sse42::get());
}

void
intrinsics_ut::test_cpuid_x64_cpuid_feature_information_ecx_x2apic()
{
    g_ecx_cpuid[cpuid::feature_information::addr] = 0x1UL << 21;
    this->expect_true(cpuid::feature_information::ecx::x2apic::get());

    g_ecx_cpuid[cpuid::feature_information::addr] = ~(0x1U << 21);
    this->expect_false(cpuid::feature_information::ecx::x2apic::get());
}

void
intrinsics_ut::test_cpuid_x64_cpuid_feature_information_ecx_movbe()
{
    g_ecx_cpuid[cpuid::feature_information::addr] = 0x1UL << 22;
    this->expect_true(cpuid::feature_information::ecx::movbe::get());

    g_ecx_cpuid[cpuid::feature_information::addr] = ~(0x1U << 22);
    this->expect_false(cpuid::feature_information::ecx::movbe::get());
}

void
intrinsics_ut::test_cpuid_x64_cpuid_feature_information_ecx_popcnt()
{
    g_ecx_cpuid[cpuid::feature_information::addr] = 0x1UL << 23;
    this->expect_true(cpuid::feature_information::ecx::popcnt::get());

    g_ecx_cpuid[cpuid::feature_information::addr] = ~(0x1U << 23);
    this->expect_false(cpuid::feature_information::ecx::popcnt::get());
}

void
intrinsics_ut::test_cpuid_x64_cpuid_feature_information_ecx_tsc_deadline()
{
    g_ecx_cpuid[cpuid::feature_information::addr] = 0x1UL << 24;
    this->expect_true(cpuid::feature_information::ecx::tsc_deadline::get());

    g_ecx_cpuid[cpuid::feature_information::addr] = ~(0x1U << 24);
    this->expect_false(cpuid::feature_information::ecx::tsc_deadline::get());
}

void
intrinsics_ut::test_cpuid_x64_cpuid_feature_information_ecx_aesni()
{
    g_ecx_cpuid[cpuid::feature_information::addr] = 0x1UL << 25;
    this->expect_true(cpuid::feature_information::ecx::aesni::get());

    g_ecx_cpuid[cpuid::feature_information::addr] = ~(0x1U << 25);
    this->expect_false(cpuid::feature_information::ecx::aesni::get());
}

void
intrinsics_ut::test_cpuid_x64_cpuid_feature_information_ecx_xsave()
{
    g_ecx_cpuid[cpuid::feature_information::addr] = 0x1UL << 26;
    this->expect_true(cpuid::feature_information::ecx::xsave::get());

    g_ecx_cpuid[cpuid::feature_information::addr] = ~(0x1U << 26);
    this->expect_false(cpuid::feature_information::ecx::xsave::get());
}

void
intrinsics_ut::test_cpuid_x64_cpuid_feature_information_ecx_osxsave()
{
    g_ecx_cpuid[cpuid::feature_information::addr] = 0x1UL << 27;
    this->expect_true(cpuid::feature_information::ecx::osxsave::get());

    g_ecx_cpuid[cpuid::feature_information::addr] = ~(0x1U << 27);
    this->expect_false(cpuid::feature_information::ecx::osxsave::get());
}

void
intrinsics_ut::test_cpuid_x64_cpuid_feature_information_ecx_avx()
{
    g_ecx_cpuid[cpuid::feature_information::addr] = 0x1UL << 28;
    this->expect_true(cpuid::feature_information::ecx::avx::get());

    g_ecx_cpuid[cpuid::feature_information::addr] = ~(0x1U << 28);
    this->expect_false(cpuid::feature_information::ecx::avx::get());
}

void
intrinsics_ut::test_cpuid_x64_cpuid_feature_information_ecx_f16c()
{
    g_ecx_cpuid[cpuid::feature_information::addr] = 0x1UL << 29;
    this->expect_true(cpuid::feature_information::ecx::f16c::get());

    g_ecx_cpuid[cpuid::feature_information::addr] = ~(0x1U << 29);
    this->expect_false(cpuid::feature_information::ecx::f16c::get());
}

void
intrinsics_ut::test_cpuid_x64_cpuid_feature_information_ecx_rdrand()
{
    g_ecx_cpuid[cpuid::feature_information::addr] = 0x1UL << 30;
    this->expect_true(cpuid::feature_information::ecx::rdrand::get());

    g_ecx_cpuid[cpuid::feature_information::addr] = ~(0x1U << 30);
    this->expect_false(cpuid::feature_information::ecx::rdrand::get());
}

void
intrinsics_ut::test_cpuid_x64_cpuid_feature_information_ecx_dump()
{
    g_ecx_cpuid[cpuid::feature_information::addr] = 0xFFFFFFFFU;
    cpuid::feature_information::ecx::dump();
}

void
intrinsics_ut::test_cpuid_x64_cpuid_extended_feature_flags_subleaf0_ebx_sgx()
{

    g_regs.ebx = 0x1U << 2;
    this->expect_true(cpuid::extended_feature_flags::subleaf0::ebx::sgx::get());

    g_regs.ebx = ~(0x1U << 2);
    this->expect_false(cpuid::extended_feature_flags::subleaf0::ebx::sgx::get());
}

void
intrinsics_ut::test_cpuid_x64_cpuid_extended_feature_flags_subleaf0_ebx_rtm()
{
    g_regs.ebx = 0x1U << 11;
    this->expect_true(cpuid::extended_feature_flags::subleaf0::ebx::rtm::get());

    g_regs.ebx = ~(0x1U << 11);
    this->expect_false(cpuid::extended_feature_flags::subleaf0::ebx::rtm::get());
}

void
intrinsics_ut::test_cpuid_x64_cpuid_extended_feature_flags_subleaf0_ebx_dump()
{
    g_regs.ebx = 0xFFFFFFFFU;
    cpuid::extended_feature_flags::subleaf0::ebx::dump();
}
