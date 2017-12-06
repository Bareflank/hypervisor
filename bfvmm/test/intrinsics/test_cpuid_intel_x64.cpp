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
#include <intrinsics/x86/intel_x64.h>
#include <map>
#include <hippomocks.h>

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

using namespace intel_x64;

std::map<cpuid::field_type, cpuid::value_type> g_eax_cpuid;
std::map<cpuid::field_type, cpuid::value_type> g_ebx_cpuid;
std::map<cpuid::field_type, cpuid::value_type> g_ecx_cpuid;
std::map<cpuid::field_type, cpuid::value_type> g_edx_cpuid;

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

extern "C" uint32_t
test_cpuid_subeax(uint32_t val, uint32_t sub) noexcept
{ bfignored(sub); return g_eax_cpuid[val]; }
extern "C" uint32_t
test_cpuid_subebx(uint32_t val, uint32_t sub) noexcept
{ bfignored(sub); return g_ebx_cpuid[val]; }

extern "C" uint32_t
test_cpuid_subecx(uint32_t val, uint32_t sub) noexcept
{ bfignored(sub); return g_ecx_cpuid[val]; }

extern "C" uint32_t
test_cpuid_subedx(uint32_t val, uint32_t sub) noexcept
{ bfignored(sub); return g_edx_cpuid[val]; }

static void
setup_intrinsics(MockRepository &mocks)
{
    mocks.OnCallFunc(_cpuid_eax).Do(test_cpuid_eax);
    mocks.OnCallFunc(_cpuid_ebx).Do(test_cpuid_ebx);
    mocks.OnCallFunc(_cpuid_ecx).Do(test_cpuid_ecx);
    mocks.OnCallFunc(_cpuid_edx).Do(test_cpuid_edx);
    mocks.OnCallFunc(_cpuid_subeax).Do(test_cpuid_subeax);
    mocks.OnCallFunc(_cpuid_subebx).Do(test_cpuid_subebx);
    mocks.OnCallFunc(_cpuid_subecx).Do(test_cpuid_subecx);
    mocks.OnCallFunc(_cpuid_subedx).Do(test_cpuid_subedx);
}

TEST_CASE("intrinsics: cpuid_feature_information")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::feature_information;

    dump(0);
}

TEST_CASE("intrinsics: cpuid_feature_information_eax")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::feature_information;

    g_eax_cpuid[addr] = 0xFFFFFFFF;
    CHECK(eax::get() == 0xFFFFFFFF);
}

TEST_CASE("intrinsics: cpuid_feature_information_eax_stepping_id")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::feature_information;

    g_eax_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(eax::stepping_id::get() ==
            (eax::stepping_id::mask >> eax::stepping_id::from));
    CHECK(eax::stepping_id::get(eax::stepping_id::mask) ==
            (eax::stepping_id::mask >> eax::stepping_id::from));
}

TEST_CASE("intrinsics: cpuid_feature_information_eax_model")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::feature_information;

    g_eax_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(eax::model::get() ==
            (eax::model::mask >> eax::model::from));
    CHECK(eax::model::get(eax::model::mask) ==
            (eax::model::mask >> eax::model::from));
}

TEST_CASE("intrinsics: cpuid_feature_information_eax_family_id")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::feature_information;

    g_eax_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(eax::family_id::get() ==
            (eax::family_id::mask >> eax::family_id::from));
    CHECK(eax::family_id::get(eax::family_id::mask) ==
            (eax::family_id::mask >> eax::family_id::from));
}

TEST_CASE("intrinsics: cpuid_feature_information_eax_processor_type")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::feature_information;

    g_eax_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(eax::processor_type::get() ==
            (eax::processor_type::mask >> eax::processor_type::from));
    CHECK(eax::processor_type::get(eax::processor_type::mask) ==
            (eax::processor_type::mask >> eax::processor_type::from));
}

TEST_CASE("intrinsics: cpuid_feature_information_eax_extended_model_id")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::feature_information;

    g_eax_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(eax::extended_model_id::get() ==
            (eax::extended_model_id::mask >> eax::extended_model_id::from));
    CHECK(eax::extended_model_id::get(eax::extended_model_id::mask) ==
            (eax::extended_model_id::mask >> eax::extended_model_id::from));
}

TEST_CASE("intrinsics: cpuid_feature_information_eax_extended_family_id")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::feature_information;

    g_eax_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(eax::extended_family_id::get() ==
            (eax::extended_family_id::mask >> eax::extended_family_id::from));
    CHECK(eax::extended_family_id::get(eax::extended_family_id::mask) ==
            (eax::extended_family_id::mask >> eax::extended_family_id::from));
}

TEST_CASE("intrinsics: cpuid_feature_information_ebx")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::feature_information;

    g_ebx_cpuid[addr] = 0xFFFFFFFF;
    CHECK(ebx::get() == 0xFFFFFFFF);
}

TEST_CASE("intrinsics: cpuid_feature_information_ebx_brand_index")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::feature_information;

    g_ebx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(ebx::brand_index::get() ==
            (ebx::brand_index::mask >> ebx::brand_index::from));
    CHECK(ebx::brand_index::get(ebx::brand_index::mask) ==
            (ebx::brand_index::mask >> ebx::brand_index::from));
}

TEST_CASE("intrinsics: cpuid_feature_information_ebx_clflush_line_size")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::feature_information;

    g_ebx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(ebx::clflush_line_size::get() ==
            (ebx::clflush_line_size::mask >> ebx::clflush_line_size::from));
    CHECK(ebx::clflush_line_size::get(ebx::clflush_line_size::mask) ==
            (ebx::clflush_line_size::mask >> ebx::clflush_line_size::from));
}

TEST_CASE("intrinsics: cpuid_feature_information_ebx_max_addressable_ids")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::feature_information;

    g_ebx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(ebx::max_addressable_ids::get() ==
            (ebx::max_addressable_ids::mask >> ebx::max_addressable_ids::from));
    CHECK(ebx::max_addressable_ids::get(ebx::max_addressable_ids::mask) ==
            (ebx::max_addressable_ids::mask >> ebx::max_addressable_ids::from));
}

TEST_CASE("intrinsics: cpuid_feature_information_ebx_initial_apic_id")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::feature_information;

    g_ebx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(ebx::initial_apic_id::get() ==
            (ebx::initial_apic_id::mask >> ebx::initial_apic_id::from));
    CHECK(ebx::initial_apic_id::get(ebx::initial_apic_id::mask) ==
            (ebx::initial_apic_id::mask >> ebx::initial_apic_id::from));
}

TEST_CASE("intrinsics: cpuid_feature_information_ecx")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::feature_information;

    g_ecx_cpuid[addr] = 0xFFFFFFFF;
    CHECK(ecx::get() == 0xFFFFFFFF);
}

TEST_CASE("intrinsics: cpuid_feature_information_ecx_sse3")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::feature_information;

    g_ecx_cpuid[addr] = ecx::sse3::mask;
    CHECK(ecx::sse3::is_enabled());
    g_ecx_cpuid[addr] = 0x0;
    CHECK(ecx::sse3::is_disabled());

    g_ecx_cpuid[addr] = ecx::sse3::mask;
    CHECK(ecx::sse3::is_enabled(ecx::sse3::mask));
    g_ecx_cpuid[addr] = 0x0;
    CHECK(ecx::sse3::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_feature_information_ecx_pclmulqdq")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::feature_information;

    g_ecx_cpuid[addr] = ecx::pclmulqdq::mask;
    CHECK(ecx::pclmulqdq::is_enabled());
    g_ecx_cpuid[addr] = 0x0;
    CHECK(ecx::pclmulqdq::is_disabled());

    g_ecx_cpuid[addr] = ecx::pclmulqdq::mask;
    CHECK(ecx::pclmulqdq::is_enabled(ecx::pclmulqdq::mask));
    g_ecx_cpuid[addr] = 0x0;
    CHECK(ecx::pclmulqdq::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_feature_information_ecx_dtes64")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::feature_information;

    g_ecx_cpuid[addr] = ecx::dtes64::mask;
    CHECK(ecx::dtes64::is_enabled());
    g_ecx_cpuid[addr] = 0x0;
    CHECK(ecx::dtes64::is_disabled());

    g_ecx_cpuid[addr] = ecx::dtes64::mask;
    CHECK(ecx::dtes64::is_enabled(ecx::dtes64::mask));
    g_ecx_cpuid[addr] = 0x0;
    CHECK(ecx::dtes64::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_feature_information_ecx_monitor")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::feature_information;

    g_ecx_cpuid[addr] = ecx::monitor::mask;
    CHECK(ecx::monitor::is_enabled());
    g_ecx_cpuid[addr] = 0x0;
    CHECK(ecx::monitor::is_disabled());

    g_ecx_cpuid[addr] = ecx::monitor::mask;
    CHECK(ecx::monitor::is_enabled(ecx::monitor::mask));
    g_ecx_cpuid[addr] = 0x0;
    CHECK(ecx::monitor::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_feature_information_ecx_ds_cpl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::feature_information;

    g_ecx_cpuid[addr] = ecx::ds_cpl::mask;
    CHECK(ecx::ds_cpl::is_enabled());
    g_ecx_cpuid[addr] = 0x0;
    CHECK(ecx::ds_cpl::is_disabled());

    g_ecx_cpuid[addr] = ecx::ds_cpl::mask;
    CHECK(ecx::ds_cpl::is_enabled(ecx::ds_cpl::mask));
    g_ecx_cpuid[addr] = 0x0;
    CHECK(ecx::ds_cpl::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_feature_information_ecx_vmx")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::feature_information;

    g_ecx_cpuid[addr] = ecx::vmx::mask;
    CHECK(ecx::vmx::is_enabled());
    g_ecx_cpuid[addr] = 0x0;
    CHECK(ecx::vmx::is_disabled());

    g_ecx_cpuid[addr] = ecx::vmx::mask;
    CHECK(ecx::vmx::is_enabled(ecx::vmx::mask));
    g_ecx_cpuid[addr] = 0x0;
    CHECK(ecx::vmx::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_feature_information_ecx_smx")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::feature_information;

    g_ecx_cpuid[addr] = ecx::smx::mask;
    CHECK(ecx::smx::is_enabled());
    g_ecx_cpuid[addr] = 0x0;
    CHECK(ecx::smx::is_disabled());

    g_ecx_cpuid[addr] = ecx::smx::mask;
    CHECK(ecx::smx::is_enabled(ecx::smx::mask));
    g_ecx_cpuid[addr] = 0x0;
    CHECK(ecx::smx::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_feature_information_ecx_eist")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::feature_information;

    g_ecx_cpuid[addr] = ecx::eist::mask;
    CHECK(ecx::eist::is_enabled());
    g_ecx_cpuid[addr] = 0x0;
    CHECK(ecx::eist::is_disabled());

    g_ecx_cpuid[addr] = ecx::eist::mask;
    CHECK(ecx::eist::is_enabled(ecx::eist::mask));
    g_ecx_cpuid[addr] = 0x0;
    CHECK(ecx::eist::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_feature_information_ecx_tm2")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::feature_information;

    g_ecx_cpuid[addr] = ecx::tm2::mask;
    CHECK(ecx::tm2::is_enabled());
    g_ecx_cpuid[addr] = 0x0;
    CHECK(ecx::tm2::is_disabled());

    g_ecx_cpuid[addr] = ecx::tm2::mask;
    CHECK(ecx::tm2::is_enabled(ecx::tm2::mask));
    g_ecx_cpuid[addr] = 0x0;
    CHECK(ecx::tm2::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_feature_information_ecx_ssse3")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::feature_information;

    g_ecx_cpuid[addr] = ecx::ssse3::mask;
    CHECK(ecx::ssse3::is_enabled());
    g_ecx_cpuid[addr] = 0x0;
    CHECK(ecx::ssse3::is_disabled());

    g_ecx_cpuid[addr] = ecx::ssse3::mask;
    CHECK(ecx::ssse3::is_enabled(ecx::ssse3::mask));
    g_ecx_cpuid[addr] = 0x0;
    CHECK(ecx::ssse3::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_feature_information_ecx_cnxt_id")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::feature_information;

    g_ecx_cpuid[addr] = ecx::cnxt_id::mask;
    CHECK(ecx::cnxt_id::is_enabled());
    g_ecx_cpuid[addr] = 0x0;
    CHECK(ecx::cnxt_id::is_disabled());

    g_ecx_cpuid[addr] = ecx::cnxt_id::mask;
    CHECK(ecx::cnxt_id::is_enabled(ecx::cnxt_id::mask));
    g_ecx_cpuid[addr] = 0x0;
    CHECK(ecx::cnxt_id::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_feature_information_ecx_sdbg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::feature_information;

    g_ecx_cpuid[addr] = ecx::sdbg::mask;
    CHECK(ecx::sdbg::is_enabled());
    g_ecx_cpuid[addr] = 0x0;
    CHECK(ecx::sdbg::is_disabled());

    g_ecx_cpuid[addr] = ecx::sdbg::mask;
    CHECK(ecx::sdbg::is_enabled(ecx::sdbg::mask));
    g_ecx_cpuid[addr] = 0x0;
    CHECK(ecx::sdbg::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_feature_information_ecx_fma")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::feature_information;

    g_ecx_cpuid[addr] = ecx::fma::mask;
    CHECK(ecx::fma::is_enabled());
    g_ecx_cpuid[addr] = 0x0;
    CHECK(ecx::fma::is_disabled());

    g_ecx_cpuid[addr] = ecx::fma::mask;
    CHECK(ecx::fma::is_enabled(ecx::fma::mask));
    g_ecx_cpuid[addr] = 0x0;
    CHECK(ecx::fma::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_feature_information_ecx_cmpxchg16b")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::feature_information;

    g_ecx_cpuid[addr] = ecx::cmpxchg16b::mask;
    CHECK(ecx::cmpxchg16b::is_enabled());
    g_ecx_cpuid[addr] = 0x0;
    CHECK(ecx::cmpxchg16b::is_disabled());

    g_ecx_cpuid[addr] = ecx::cmpxchg16b::mask;
    CHECK(ecx::cmpxchg16b::is_enabled(ecx::cmpxchg16b::mask));
    g_ecx_cpuid[addr] = 0x0;
    CHECK(ecx::cmpxchg16b::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_feature_information_ecx_xtpr_update_control")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::feature_information;

    g_ecx_cpuid[addr] = ecx::xtpr_update_control::mask;
    CHECK(ecx::xtpr_update_control::is_enabled());
    g_ecx_cpuid[addr] = 0x0;
    CHECK(ecx::xtpr_update_control::is_disabled());

    g_ecx_cpuid[addr] = ecx::xtpr_update_control::mask;
    CHECK(ecx::xtpr_update_control::is_enabled(ecx::xtpr_update_control::mask));
    g_ecx_cpuid[addr] = 0x0;
    CHECK(ecx::xtpr_update_control::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_feature_information_ecx_pdcm")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::feature_information;

    g_ecx_cpuid[addr] = ecx::pdcm::mask;
    CHECK(ecx::pdcm::is_enabled());
    g_ecx_cpuid[addr] = 0x0;
    CHECK(ecx::pdcm::is_disabled());

    g_ecx_cpuid[addr] = ecx::pdcm::mask;
    CHECK(ecx::pdcm::is_enabled(ecx::pdcm::mask));
    g_ecx_cpuid[addr] = 0x0;
    CHECK(ecx::pdcm::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_feature_information_ecx_pcid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::feature_information;

    g_ecx_cpuid[addr] = ecx::pcid::mask;
    CHECK(ecx::pcid::is_enabled());
    g_ecx_cpuid[addr] = 0x0;
    CHECK(ecx::pcid::is_disabled());

    g_ecx_cpuid[addr] = ecx::pcid::mask;
    CHECK(ecx::pcid::is_enabled(ecx::pcid::mask));
    g_ecx_cpuid[addr] = 0x0;
    CHECK(ecx::pcid::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_feature_information_ecx_dca")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::feature_information;

    g_ecx_cpuid[addr] = ecx::dca::mask;
    CHECK(ecx::dca::is_enabled());
    g_ecx_cpuid[addr] = 0x0;
    CHECK(ecx::dca::is_disabled());

    g_ecx_cpuid[addr] = ecx::dca::mask;
    CHECK(ecx::dca::is_enabled(ecx::dca::mask));
    g_ecx_cpuid[addr] = 0x0;
    CHECK(ecx::dca::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_feature_information_ecx_sse41")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::feature_information;

    g_ecx_cpuid[addr] = ecx::sse41::mask;
    CHECK(ecx::sse41::is_enabled());
    g_ecx_cpuid[addr] = 0x0;
    CHECK(ecx::sse41::is_disabled());

    g_ecx_cpuid[addr] = ecx::sse41::mask;
    CHECK(ecx::sse41::is_enabled(ecx::sse41::mask));
    g_ecx_cpuid[addr] = 0x0;
    CHECK(ecx::sse41::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_feature_information_ecx_sse42")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::feature_information;

    g_ecx_cpuid[addr] = ecx::sse42::mask;
    CHECK(ecx::sse42::is_enabled());
    g_ecx_cpuid[addr] = 0x0;
    CHECK(ecx::sse42::is_disabled());

    g_ecx_cpuid[addr] = ecx::sse42::mask;
    CHECK(ecx::sse42::is_enabled(ecx::sse42::mask));
    g_ecx_cpuid[addr] = 0x0;
    CHECK(ecx::sse42::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_feature_information_ecx_x2apic")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::feature_information;

    g_ecx_cpuid[addr] = ecx::x2apic::mask;
    CHECK(ecx::x2apic::is_enabled());
    g_ecx_cpuid[addr] = 0x0;
    CHECK(ecx::x2apic::is_disabled());

    g_ecx_cpuid[addr] = ecx::x2apic::mask;
    CHECK(ecx::x2apic::is_enabled(ecx::x2apic::mask));
    g_ecx_cpuid[addr] = 0x0;
    CHECK(ecx::x2apic::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_feature_information_ecx_movbe")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::feature_information;

    g_ecx_cpuid[addr] = ecx::movbe::mask;
    CHECK(ecx::movbe::is_enabled());
    g_ecx_cpuid[addr] = 0x0;
    CHECK(ecx::movbe::is_disabled());

    g_ecx_cpuid[addr] = ecx::movbe::mask;
    CHECK(ecx::movbe::is_enabled(ecx::movbe::mask));
    g_ecx_cpuid[addr] = 0x0;
    CHECK(ecx::movbe::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_feature_information_ecx_popcnt")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::feature_information;

    g_ecx_cpuid[addr] = ecx::popcnt::mask;
    CHECK(ecx::popcnt::is_enabled());
    g_ecx_cpuid[addr] = 0x0;
    CHECK(ecx::popcnt::is_disabled());

    g_ecx_cpuid[addr] = ecx::popcnt::mask;
    CHECK(ecx::popcnt::is_enabled(ecx::popcnt::mask));
    g_ecx_cpuid[addr] = 0x0;
    CHECK(ecx::popcnt::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_feature_information_ecx_tsc_deadline")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::feature_information;

    g_ecx_cpuid[addr] = ecx::tsc_deadline::mask;
    CHECK(ecx::tsc_deadline::is_enabled());
    g_ecx_cpuid[addr] = 0x0;
    CHECK(ecx::tsc_deadline::is_disabled());

    g_ecx_cpuid[addr] = ecx::tsc_deadline::mask;
    CHECK(ecx::tsc_deadline::is_enabled(ecx::tsc_deadline::mask));
    g_ecx_cpuid[addr] = 0x0;
    CHECK(ecx::tsc_deadline::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_feature_information_ecx_aesni")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::feature_information;

    g_ecx_cpuid[addr] = ecx::aesni::mask;
    CHECK(ecx::aesni::is_enabled());
    g_ecx_cpuid[addr] = 0x0;
    CHECK(ecx::aesni::is_disabled());

    g_ecx_cpuid[addr] = ecx::aesni::mask;
    CHECK(ecx::aesni::is_enabled(ecx::aesni::mask));
    g_ecx_cpuid[addr] = 0x0;
    CHECK(ecx::aesni::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_feature_information_ecx_xsave")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::feature_information;

    g_ecx_cpuid[addr] = ecx::xsave::mask;
    CHECK(ecx::xsave::is_enabled());
    g_ecx_cpuid[addr] = 0x0;
    CHECK(ecx::xsave::is_disabled());

    g_ecx_cpuid[addr] = ecx::xsave::mask;
    CHECK(ecx::xsave::is_enabled(ecx::xsave::mask));
    g_ecx_cpuid[addr] = 0x0;
    CHECK(ecx::xsave::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_feature_information_ecx_osxsave")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::feature_information;

    g_ecx_cpuid[addr] = ecx::osxsave::mask;
    CHECK(ecx::osxsave::is_enabled());
    g_ecx_cpuid[addr] = 0x0;
    CHECK(ecx::osxsave::is_disabled());

    g_ecx_cpuid[addr] = ecx::osxsave::mask;
    CHECK(ecx::osxsave::is_enabled(ecx::osxsave::mask));
    g_ecx_cpuid[addr] = 0x0;
    CHECK(ecx::osxsave::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_feature_information_ecx_avx")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::feature_information;

    g_ecx_cpuid[addr] = ecx::avx::mask;
    CHECK(ecx::avx::is_enabled());
    g_ecx_cpuid[addr] = 0x0;
    CHECK(ecx::avx::is_disabled());

    g_ecx_cpuid[addr] = ecx::avx::mask;
    CHECK(ecx::avx::is_enabled(ecx::avx::mask));
    g_ecx_cpuid[addr] = 0x0;
    CHECK(ecx::avx::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_feature_information_ecx_f16c")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::feature_information;

    g_ecx_cpuid[addr] = ecx::f16c::mask;
    CHECK(ecx::f16c::is_enabled());
    g_ecx_cpuid[addr] = 0x0;
    CHECK(ecx::f16c::is_disabled());

    g_ecx_cpuid[addr] = ecx::f16c::mask;
    CHECK(ecx::f16c::is_enabled(ecx::f16c::mask));
    g_ecx_cpuid[addr] = 0x0;
    CHECK(ecx::f16c::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_feature_information_ecx_rdrand")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::feature_information;

    g_ecx_cpuid[addr] = ecx::rdrand::mask;
    CHECK(ecx::rdrand::is_enabled());
    g_ecx_cpuid[addr] = 0x0;
    CHECK(ecx::rdrand::is_disabled());

    g_ecx_cpuid[addr] = ecx::rdrand::mask;
    CHECK(ecx::rdrand::is_enabled(ecx::rdrand::mask));
    g_ecx_cpuid[addr] = 0x0;
    CHECK(ecx::rdrand::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_feature_information_edx")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::feature_information;

    g_edx_cpuid[addr] = 0xFFFFFFFF;
    CHECK(edx::get() == 0xFFFFFFFF);
}

TEST_CASE("intrinsics: cpuid_feature_information_edx_fpu")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::feature_information;

    g_edx_cpuid[addr] = edx::fpu::mask;
    CHECK(edx::fpu::is_enabled());
    g_edx_cpuid[addr] = 0x0;
    CHECK(edx::fpu::is_disabled());

    g_edx_cpuid[addr] = edx::fpu::mask;
    CHECK(edx::fpu::is_enabled(edx::fpu::mask));
    g_edx_cpuid[addr] = 0x0;
    CHECK(edx::fpu::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_feature_information_edx_vme")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::feature_information;

    g_edx_cpuid[addr] = edx::vme::mask;
    CHECK(edx::vme::is_enabled());
    g_edx_cpuid[addr] = 0x0;
    CHECK(edx::vme::is_disabled());

    g_edx_cpuid[addr] = edx::vme::mask;
    CHECK(edx::vme::is_enabled(edx::vme::mask));
    g_edx_cpuid[addr] = 0x0;
    CHECK(edx::vme::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_feature_information_edx_de")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::feature_information;

    g_edx_cpuid[addr] = edx::de::mask;
    CHECK(edx::de::is_enabled());
    g_edx_cpuid[addr] = 0x0;
    CHECK(edx::de::is_disabled());

    g_edx_cpuid[addr] = edx::de::mask;
    CHECK(edx::de::is_enabled(edx::de::mask));
    g_edx_cpuid[addr] = 0x0;
    CHECK(edx::de::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_feature_information_edx_pse")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::feature_information;

    g_edx_cpuid[addr] = edx::pse::mask;
    CHECK(edx::pse::is_enabled());
    g_edx_cpuid[addr] = 0x0;
    CHECK(edx::pse::is_disabled());

    g_edx_cpuid[addr] = edx::pse::mask;
    CHECK(edx::pse::is_enabled(edx::pse::mask));
    g_edx_cpuid[addr] = 0x0;
    CHECK(edx::pse::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_feature_information_edx_tsc")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::feature_information;

    g_edx_cpuid[addr] = edx::tsc::mask;
    CHECK(edx::tsc::is_enabled());
    g_edx_cpuid[addr] = 0x0;
    CHECK(edx::tsc::is_disabled());

    g_edx_cpuid[addr] = edx::tsc::mask;
    CHECK(edx::tsc::is_enabled(edx::tsc::mask));
    g_edx_cpuid[addr] = 0x0;
    CHECK(edx::tsc::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_feature_information_edx_msr")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::feature_information;

    g_edx_cpuid[addr] = edx::msr::mask;
    CHECK(edx::msr::is_enabled());
    g_edx_cpuid[addr] = 0x0;
    CHECK(edx::msr::is_disabled());

    g_edx_cpuid[addr] = edx::msr::mask;
    CHECK(edx::msr::is_enabled(edx::msr::mask));
    g_edx_cpuid[addr] = 0x0;
    CHECK(edx::msr::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_feature_information_edx_pae")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::feature_information;

    g_edx_cpuid[addr] = edx::pae::mask;
    CHECK(edx::pae::is_enabled());
    g_edx_cpuid[addr] = 0x0;
    CHECK(edx::pae::is_disabled());

    g_edx_cpuid[addr] = edx::pae::mask;
    CHECK(edx::pae::is_enabled(edx::pae::mask));
    g_edx_cpuid[addr] = 0x0;
    CHECK(edx::pae::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_feature_information_edx_mce")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::feature_information;

    g_edx_cpuid[addr] = edx::mce::mask;
    CHECK(edx::mce::is_enabled());
    g_edx_cpuid[addr] = 0x0;
    CHECK(edx::mce::is_disabled());

    g_edx_cpuid[addr] = edx::mce::mask;
    CHECK(edx::mce::is_enabled(edx::mce::mask));
    g_edx_cpuid[addr] = 0x0;
    CHECK(edx::mce::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_feature_information_edx_cx8")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::feature_information;

    g_edx_cpuid[addr] = edx::cx8::mask;
    CHECK(edx::cx8::is_enabled());
    g_edx_cpuid[addr] = 0x0;
    CHECK(edx::cx8::is_disabled());

    g_edx_cpuid[addr] = edx::cx8::mask;
    CHECK(edx::cx8::is_enabled(edx::cx8::mask));
    g_edx_cpuid[addr] = 0x0;
    CHECK(edx::cx8::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_feature_information_edx_apic")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::feature_information;

    g_edx_cpuid[addr] = edx::apic::mask;
    CHECK(edx::apic::is_enabled());
    g_edx_cpuid[addr] = 0x0;
    CHECK(edx::apic::is_disabled());

    g_edx_cpuid[addr] = edx::apic::mask;
    CHECK(edx::apic::is_enabled(edx::apic::mask));
    g_edx_cpuid[addr] = 0x0;
    CHECK(edx::apic::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_feature_information_edx_sep")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::feature_information;

    g_edx_cpuid[addr] = edx::sep::mask;
    CHECK(edx::sep::is_enabled());
    g_edx_cpuid[addr] = 0x0;
    CHECK(edx::sep::is_disabled());

    g_edx_cpuid[addr] = edx::sep::mask;
    CHECK(edx::sep::is_enabled(edx::sep::mask));
    g_edx_cpuid[addr] = 0x0;
    CHECK(edx::sep::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_feature_information_edx_mtrr")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::feature_information;

    g_edx_cpuid[addr] = edx::mtrr::mask;
    CHECK(edx::mtrr::is_enabled());
    g_edx_cpuid[addr] = 0x0;
    CHECK(edx::mtrr::is_disabled());

    g_edx_cpuid[addr] = edx::mtrr::mask;
    CHECK(edx::mtrr::is_enabled(edx::mtrr::mask));
    g_edx_cpuid[addr] = 0x0;
    CHECK(edx::mtrr::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_feature_information_edx_pge")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::feature_information;

    g_edx_cpuid[addr] = edx::pge::mask;
    CHECK(edx::pge::is_enabled());
    g_edx_cpuid[addr] = 0x0;
    CHECK(edx::pge::is_disabled());

    g_edx_cpuid[addr] = edx::pge::mask;
    CHECK(edx::pge::is_enabled(edx::pge::mask));
    g_edx_cpuid[addr] = 0x0;
    CHECK(edx::pge::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_feature_information_edx_mca")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::feature_information;

    g_edx_cpuid[addr] = edx::mca::mask;
    CHECK(edx::mca::is_enabled());
    g_edx_cpuid[addr] = 0x0;
    CHECK(edx::mca::is_disabled());

    g_edx_cpuid[addr] = edx::mca::mask;
    CHECK(edx::mca::is_enabled(edx::mca::mask));
    g_edx_cpuid[addr] = 0x0;
    CHECK(edx::mca::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_feature_information_edx_cmov")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::feature_information;

    g_edx_cpuid[addr] = edx::cmov::mask;
    CHECK(edx::cmov::is_enabled());
    g_edx_cpuid[addr] = 0x0;
    CHECK(edx::cmov::is_disabled());

    g_edx_cpuid[addr] = edx::cmov::mask;
    CHECK(edx::cmov::is_enabled(edx::cmov::mask));
    g_edx_cpuid[addr] = 0x0;
    CHECK(edx::cmov::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_feature_information_edx_pat")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::feature_information;

    g_edx_cpuid[addr] = edx::pat::mask;
    CHECK(edx::pat::is_enabled());
    g_edx_cpuid[addr] = 0x0;
    CHECK(edx::pat::is_disabled());

    g_edx_cpuid[addr] = edx::pat::mask;
    CHECK(edx::pat::is_enabled(edx::pat::mask));
    g_edx_cpuid[addr] = 0x0;
    CHECK(edx::pat::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_feature_information_edx_pse_36")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::feature_information;

    g_edx_cpuid[addr] = edx::pse_36::mask;
    CHECK(edx::pse_36::is_enabled());
    g_edx_cpuid[addr] = 0x0;
    CHECK(edx::pse_36::is_disabled());

    g_edx_cpuid[addr] = edx::pse_36::mask;
    CHECK(edx::pse_36::is_enabled(edx::pse_36::mask));
    g_edx_cpuid[addr] = 0x0;
    CHECK(edx::pse_36::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_feature_information_edx_psn")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::feature_information;

    g_edx_cpuid[addr] = edx::psn::mask;
    CHECK(edx::psn::is_enabled());
    g_edx_cpuid[addr] = 0x0;
    CHECK(edx::psn::is_disabled());

    g_edx_cpuid[addr] = edx::psn::mask;
    CHECK(edx::psn::is_enabled(edx::psn::mask));
    g_edx_cpuid[addr] = 0x0;
    CHECK(edx::psn::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_feature_information_edx_clfsh")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::feature_information;

    g_edx_cpuid[addr] = edx::clfsh::mask;
    CHECK(edx::clfsh::is_enabled());
    g_edx_cpuid[addr] = 0x0;
    CHECK(edx::clfsh::is_disabled());

    g_edx_cpuid[addr] = edx::clfsh::mask;
    CHECK(edx::clfsh::is_enabled(edx::clfsh::mask));
    g_edx_cpuid[addr] = 0x0;
    CHECK(edx::clfsh::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_feature_information_edx_ds")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::feature_information;

    g_edx_cpuid[addr] = edx::ds::mask;
    CHECK(edx::ds::is_enabled());
    g_edx_cpuid[addr] = 0x0;
    CHECK(edx::ds::is_disabled());

    g_edx_cpuid[addr] = edx::ds::mask;
    CHECK(edx::ds::is_enabled(edx::ds::mask));
    g_edx_cpuid[addr] = 0x0;
    CHECK(edx::ds::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_feature_information_edx_acpi")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::feature_information;

    g_edx_cpuid[addr] = edx::acpi::mask;
    CHECK(edx::acpi::is_enabled());
    g_edx_cpuid[addr] = 0x0;
    CHECK(edx::acpi::is_disabled());

    g_edx_cpuid[addr] = edx::acpi::mask;
    CHECK(edx::acpi::is_enabled(edx::acpi::mask));
    g_edx_cpuid[addr] = 0x0;
    CHECK(edx::acpi::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_feature_information_edx_mmx")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::feature_information;

    g_edx_cpuid[addr] = edx::mmx::mask;
    CHECK(edx::mmx::is_enabled());
    g_edx_cpuid[addr] = 0x0;
    CHECK(edx::mmx::is_disabled());

    g_edx_cpuid[addr] = edx::mmx::mask;
    CHECK(edx::mmx::is_enabled(edx::mmx::mask));
    g_edx_cpuid[addr] = 0x0;
    CHECK(edx::mmx::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_feature_information_edx_fxsr")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::feature_information;

    g_edx_cpuid[addr] = edx::fxsr::mask;
    CHECK(edx::fxsr::is_enabled());
    g_edx_cpuid[addr] = 0x0;
    CHECK(edx::fxsr::is_disabled());

    g_edx_cpuid[addr] = edx::fxsr::mask;
    CHECK(edx::fxsr::is_enabled(edx::fxsr::mask));
    g_edx_cpuid[addr] = 0x0;
    CHECK(edx::fxsr::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_feature_information_edx_sse")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::feature_information;

    g_edx_cpuid[addr] = edx::sse::mask;
    CHECK(edx::sse::is_enabled());
    g_edx_cpuid[addr] = 0x0;
    CHECK(edx::sse::is_disabled());

    g_edx_cpuid[addr] = edx::sse::mask;
    CHECK(edx::sse::is_enabled(edx::sse::mask));
    g_edx_cpuid[addr] = 0x0;
    CHECK(edx::sse::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_feature_information_edx_sse2")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::feature_information;

    g_edx_cpuid[addr] = edx::sse2::mask;
    CHECK(edx::sse2::is_enabled());
    g_edx_cpuid[addr] = 0x0;
    CHECK(edx::sse2::is_disabled());

    g_edx_cpuid[addr] = edx::sse2::mask;
    CHECK(edx::sse2::is_enabled(edx::sse2::mask));
    g_edx_cpuid[addr] = 0x0;
    CHECK(edx::sse2::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_feature_information_edx_ss")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::feature_information;

    g_edx_cpuid[addr] = edx::ss::mask;
    CHECK(edx::ss::is_enabled());
    g_edx_cpuid[addr] = 0x0;
    CHECK(edx::ss::is_disabled());

    g_edx_cpuid[addr] = edx::ss::mask;
    CHECK(edx::ss::is_enabled(edx::ss::mask));
    g_edx_cpuid[addr] = 0x0;
    CHECK(edx::ss::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_feature_information_edx_htt")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::feature_information;

    g_edx_cpuid[addr] = edx::htt::mask;
    CHECK(edx::htt::is_enabled());
    g_edx_cpuid[addr] = 0x0;
    CHECK(edx::htt::is_disabled());

    g_edx_cpuid[addr] = edx::htt::mask;
    CHECK(edx::htt::is_enabled(edx::htt::mask));
    g_edx_cpuid[addr] = 0x0;
    CHECK(edx::htt::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_feature_information_edx_tm")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::feature_information;

    g_edx_cpuid[addr] = edx::tm::mask;
    CHECK(edx::tm::is_enabled());
    g_edx_cpuid[addr] = 0x0;
    CHECK(edx::tm::is_disabled());

    g_edx_cpuid[addr] = edx::tm::mask;
    CHECK(edx::tm::is_enabled(edx::tm::mask));
    g_edx_cpuid[addr] = 0x0;
    CHECK(edx::tm::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_feature_information_edx_pbe")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::feature_information;

    g_edx_cpuid[addr] = edx::pbe::mask;
    CHECK(edx::pbe::is_enabled());
    g_edx_cpuid[addr] = 0x0;
    CHECK(edx::pbe::is_disabled());

    g_edx_cpuid[addr] = edx::pbe::mask;
    CHECK(edx::pbe::is_enabled(edx::pbe::mask));
    g_edx_cpuid[addr] = 0x0;
    CHECK(edx::pbe::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_extended_feature_flags")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::extended_feature_flags;

    dump(0);
}

TEST_CASE("intrinsics: cpuid_extended_feature_flags_subleaf0_eax")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::extended_feature_flags;

    g_eax_cpuid[addr] = 0xFFFFFFFF;
    CHECK(subleaf0::eax::get() == 0xFFFFFFFF);
}

TEST_CASE("intrinsics: cpuid_extended_feature_flags_subleaf0_eax_max_input")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::extended_feature_flags;

    g_eax_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(subleaf0::eax::max_input::get() ==
          (subleaf0::eax::max_input::mask >> subleaf0::eax::max_input::from));
    CHECK(subleaf0::eax::max_input::get(subleaf0::eax::max_input::mask) ==
          (subleaf0::eax::max_input::mask >> subleaf0::eax::max_input::from));
}

TEST_CASE("intrinsics: cpuid_extended_feature_flags_subleaf0_ebx")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::extended_feature_flags;

    g_ebx_cpuid[addr] = 0xFFFFFFFF;
    CHECK(subleaf0::ebx::get() == 0xFFFFFFFF);
}

TEST_CASE("intrinsics: cpuid_extended_feature_flags_subleaf0_ebx_fsgsbase")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::extended_feature_flags;

    g_ebx_cpuid[addr] = subleaf0::ebx::fsgsbase::mask;
    CHECK(subleaf0::ebx::fsgsbase::is_enabled());
    g_ebx_cpuid[addr] = 0x0;
    CHECK(subleaf0::ebx::fsgsbase::is_disabled());

    g_ebx_cpuid[addr] = subleaf0::ebx::fsgsbase::mask;
    CHECK(subleaf0::ebx::fsgsbase::is_enabled(subleaf0::ebx::fsgsbase::mask));
    g_ebx_cpuid[addr] = 0x0;
    CHECK(subleaf0::ebx::fsgsbase::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_extended_feature_flags_subleaf0_ebx_ia32_tsc_adjust")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::extended_feature_flags;

    g_ebx_cpuid[addr] = subleaf0::ebx::ia32_tsc_adjust::mask;
    CHECK(subleaf0::ebx::ia32_tsc_adjust::is_enabled());
    g_ebx_cpuid[addr] = 0x0;
    CHECK(subleaf0::ebx::ia32_tsc_adjust::is_disabled());

    g_ebx_cpuid[addr] = subleaf0::ebx::ia32_tsc_adjust::mask;
    CHECK(subleaf0::ebx::ia32_tsc_adjust::is_enabled(subleaf0::ebx::ia32_tsc_adjust::mask));
    g_ebx_cpuid[addr] = 0x0;
    CHECK(subleaf0::ebx::ia32_tsc_adjust::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_extended_feature_flags_subleaf0_ebx_sgx")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::extended_feature_flags;

    g_ebx_cpuid[addr] = subleaf0::ebx::sgx::mask;
    CHECK(subleaf0::ebx::sgx::is_enabled());
    g_ebx_cpuid[addr] = 0x0;
    CHECK(subleaf0::ebx::sgx::is_disabled());

    g_ebx_cpuid[addr] = subleaf0::ebx::sgx::mask;
    CHECK(subleaf0::ebx::sgx::is_enabled(subleaf0::ebx::sgx::mask));
    g_ebx_cpuid[addr] = 0x0;
    CHECK(subleaf0::ebx::sgx::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_extended_feature_flags_subleaf0_ebx_bmi1")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::extended_feature_flags;

    g_ebx_cpuid[addr] = subleaf0::ebx::bmi1::mask;
    CHECK(subleaf0::ebx::bmi1::is_enabled());
    g_ebx_cpuid[addr] = 0x0;
    CHECK(subleaf0::ebx::bmi1::is_disabled());

    g_ebx_cpuid[addr] = subleaf0::ebx::bmi1::mask;
    CHECK(subleaf0::ebx::bmi1::is_enabled(subleaf0::ebx::bmi1::mask));
    g_ebx_cpuid[addr] = 0x0;
    CHECK(subleaf0::ebx::bmi1::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_extended_feature_flags_subleaf0_ebx_hle")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::extended_feature_flags;

    g_ebx_cpuid[addr] = subleaf0::ebx::hle::mask;
    CHECK(subleaf0::ebx::hle::is_enabled());
    g_ebx_cpuid[addr] = 0x0;
    CHECK(subleaf0::ebx::hle::is_disabled());

    g_ebx_cpuid[addr] = subleaf0::ebx::hle::mask;
    CHECK(subleaf0::ebx::hle::is_enabled(subleaf0::ebx::hle::mask));
    g_ebx_cpuid[addr] = 0x0;
    CHECK(subleaf0::ebx::hle::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_extended_feature_flags_subleaf0_ebx_avx2")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::extended_feature_flags;

    g_ebx_cpuid[addr] = subleaf0::ebx::avx2::mask;
    CHECK(subleaf0::ebx::avx2::is_enabled());
    g_ebx_cpuid[addr] = 0x0;
    CHECK(subleaf0::ebx::avx2::is_disabled());

    g_ebx_cpuid[addr] = subleaf0::ebx::avx2::mask;
    CHECK(subleaf0::ebx::avx2::is_enabled(subleaf0::ebx::avx2::mask));
    g_ebx_cpuid[addr] = 0x0;
    CHECK(subleaf0::ebx::avx2::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_extended_feature_flags_subleaf0_ebx_fdp_excptn_only")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::extended_feature_flags;

    g_ebx_cpuid[addr] = subleaf0::ebx::fdp_excptn_only::mask;
    CHECK(subleaf0::ebx::fdp_excptn_only::is_enabled());
    g_ebx_cpuid[addr] = 0x0;
    CHECK(subleaf0::ebx::fdp_excptn_only::is_disabled());

    g_ebx_cpuid[addr] = subleaf0::ebx::fdp_excptn_only::mask;
    CHECK(subleaf0::ebx::fdp_excptn_only::is_enabled(subleaf0::ebx::fdp_excptn_only::mask));
    g_ebx_cpuid[addr] = 0x0;
    CHECK(subleaf0::ebx::fdp_excptn_only::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_extended_feature_flags_subleaf0_ebx_smep")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::extended_feature_flags;

    g_ebx_cpuid[addr] = subleaf0::ebx::smep::mask;
    CHECK(subleaf0::ebx::smep::is_enabled());
    g_ebx_cpuid[addr] = 0x0;
    CHECK(subleaf0::ebx::smep::is_disabled());

    g_ebx_cpuid[addr] = subleaf0::ebx::smep::mask;
    CHECK(subleaf0::ebx::smep::is_enabled(subleaf0::ebx::smep::mask));
    g_ebx_cpuid[addr] = 0x0;
    CHECK(subleaf0::ebx::smep::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_extended_feature_flags_subleaf0_ebx_bmi2")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::extended_feature_flags;

    g_ebx_cpuid[addr] = subleaf0::ebx::bmi2::mask;
    CHECK(subleaf0::ebx::bmi2::is_enabled());
    g_ebx_cpuid[addr] = 0x0;
    CHECK(subleaf0::ebx::bmi2::is_disabled());

    g_ebx_cpuid[addr] = subleaf0::ebx::bmi2::mask;
    CHECK(subleaf0::ebx::bmi2::is_enabled(subleaf0::ebx::bmi2::mask));
    g_ebx_cpuid[addr] = 0x0;
    CHECK(subleaf0::ebx::bmi2::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_extended_feature_flags_subleaf0_ebx_movsb")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::extended_feature_flags;

    g_ebx_cpuid[addr] = subleaf0::ebx::movsb::mask;
    CHECK(subleaf0::ebx::movsb::is_enabled());
    g_ebx_cpuid[addr] = 0x0;
    CHECK(subleaf0::ebx::movsb::is_disabled());

    g_ebx_cpuid[addr] = subleaf0::ebx::movsb::mask;
    CHECK(subleaf0::ebx::movsb::is_enabled(subleaf0::ebx::movsb::mask));
    g_ebx_cpuid[addr] = 0x0;
    CHECK(subleaf0::ebx::movsb::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_extended_feature_flags_subleaf0_ebx_invpcid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::extended_feature_flags;

    g_ebx_cpuid[addr] = subleaf0::ebx::invpcid::mask;
    CHECK(subleaf0::ebx::invpcid::is_enabled());
    g_ebx_cpuid[addr] = 0x0;
    CHECK(subleaf0::ebx::invpcid::is_disabled());

    g_ebx_cpuid[addr] = subleaf0::ebx::invpcid::mask;
    CHECK(subleaf0::ebx::invpcid::is_enabled(subleaf0::ebx::invpcid::mask));
    g_ebx_cpuid[addr] = 0x0;
    CHECK(subleaf0::ebx::invpcid::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_extended_feature_flags_subleaf0_ebx_rtm")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::extended_feature_flags;

    g_ebx_cpuid[addr] = subleaf0::ebx::rtm::mask;
    CHECK(subleaf0::ebx::rtm::is_enabled());
    g_ebx_cpuid[addr] = 0x0;
    CHECK(subleaf0::ebx::rtm::is_disabled());

    g_ebx_cpuid[addr] = subleaf0::ebx::rtm::mask;
    CHECK(subleaf0::ebx::rtm::is_enabled(subleaf0::ebx::rtm::mask));
    g_ebx_cpuid[addr] = 0x0;
    CHECK(subleaf0::ebx::rtm::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_extended_feature_flags_subleaf0_ebx_rtm_m")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::extended_feature_flags;

    g_ebx_cpuid[addr] = subleaf0::ebx::rtm_m::mask;
    CHECK(subleaf0::ebx::rtm_m::is_enabled());
    g_ebx_cpuid[addr] = 0x0;
    CHECK(subleaf0::ebx::rtm_m::is_disabled());

    g_ebx_cpuid[addr] = subleaf0::ebx::rtm_m::mask;
    CHECK(subleaf0::ebx::rtm_m::is_enabled(subleaf0::ebx::rtm_m::mask));
    g_ebx_cpuid[addr] = 0x0;
    CHECK(subleaf0::ebx::rtm_m::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_extended_feature_flags_subleaf0_ebx_fpucs_fpuds")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::extended_feature_flags;

    g_ebx_cpuid[addr] = subleaf0::ebx::fpucs_fpuds::mask;
    CHECK(subleaf0::ebx::fpucs_fpuds::is_enabled());
    g_ebx_cpuid[addr] = 0x0;
    CHECK(subleaf0::ebx::fpucs_fpuds::is_disabled());

    g_ebx_cpuid[addr] = subleaf0::ebx::fpucs_fpuds::mask;
    CHECK(subleaf0::ebx::fpucs_fpuds::is_enabled(subleaf0::ebx::fpucs_fpuds::mask));
    g_ebx_cpuid[addr] = 0x0;
    CHECK(subleaf0::ebx::fpucs_fpuds::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_extended_feature_flags_subleaf0_ebx_mpx")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::extended_feature_flags;

    g_ebx_cpuid[addr] = subleaf0::ebx::mpx::mask;
    CHECK(subleaf0::ebx::mpx::is_enabled());
    g_ebx_cpuid[addr] = 0x0;
    CHECK(subleaf0::ebx::mpx::is_disabled());

    g_ebx_cpuid[addr] = subleaf0::ebx::mpx::mask;
    CHECK(subleaf0::ebx::mpx::is_enabled(subleaf0::ebx::mpx::mask));
    g_ebx_cpuid[addr] = 0x0;
    CHECK(subleaf0::ebx::mpx::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_extended_feature_flags_subleaf0_ebx_rdt_a")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::extended_feature_flags;

    g_ebx_cpuid[addr] = subleaf0::ebx::rdt_a::mask;
    CHECK(subleaf0::ebx::rdt_a::is_enabled());
    g_ebx_cpuid[addr] = 0x0;
    CHECK(subleaf0::ebx::rdt_a::is_disabled());

    g_ebx_cpuid[addr] = subleaf0::ebx::rdt_a::mask;
    CHECK(subleaf0::ebx::rdt_a::is_enabled(subleaf0::ebx::rdt_a::mask));
    g_ebx_cpuid[addr] = 0x0;
    CHECK(subleaf0::ebx::rdt_a::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_extended_feature_flags_subleaf0_ebx_rdseed")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::extended_feature_flags;

    g_ebx_cpuid[addr] = subleaf0::ebx::rdseed::mask;
    CHECK(subleaf0::ebx::rdseed::is_enabled());
    g_ebx_cpuid[addr] = 0x0;
    CHECK(subleaf0::ebx::rdseed::is_disabled());

    g_ebx_cpuid[addr] = subleaf0::ebx::rdseed::mask;
    CHECK(subleaf0::ebx::rdseed::is_enabled(subleaf0::ebx::rdseed::mask));
    g_ebx_cpuid[addr] = 0x0;
    CHECK(subleaf0::ebx::rdseed::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_extended_feature_flags_subleaf0_ebx_adx")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::extended_feature_flags;

    g_ebx_cpuid[addr] = subleaf0::ebx::adx::mask;
    CHECK(subleaf0::ebx::adx::is_enabled());
    g_ebx_cpuid[addr] = 0x0;
    CHECK(subleaf0::ebx::adx::is_disabled());

    g_ebx_cpuid[addr] = subleaf0::ebx::adx::mask;
    CHECK(subleaf0::ebx::adx::is_enabled(subleaf0::ebx::adx::mask));
    g_ebx_cpuid[addr] = 0x0;
    CHECK(subleaf0::ebx::adx::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_extended_feature_flags_subleaf0_ebx_smap")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::extended_feature_flags;

    g_ebx_cpuid[addr] = subleaf0::ebx::smap::mask;
    CHECK(subleaf0::ebx::smap::is_enabled());
    g_ebx_cpuid[addr] = 0x0;
    CHECK(subleaf0::ebx::smap::is_disabled());

    g_ebx_cpuid[addr] = subleaf0::ebx::smap::mask;
    CHECK(subleaf0::ebx::smap::is_enabled(subleaf0::ebx::smap::mask));
    g_ebx_cpuid[addr] = 0x0;
    CHECK(subleaf0::ebx::smap::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_extended_feature_flags_subleaf0_ebx_clflushopt")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::extended_feature_flags;

    g_ebx_cpuid[addr] = subleaf0::ebx::clflushopt::mask;
    CHECK(subleaf0::ebx::clflushopt::is_enabled());
    g_ebx_cpuid[addr] = 0x0;
    CHECK(subleaf0::ebx::clflushopt::is_disabled());

    g_ebx_cpuid[addr] = subleaf0::ebx::clflushopt::mask;
    CHECK(subleaf0::ebx::clflushopt::is_enabled(subleaf0::ebx::clflushopt::mask));
    g_ebx_cpuid[addr] = 0x0;
    CHECK(subleaf0::ebx::clflushopt::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_extended_feature_flags_subleaf0_ebx_clwb")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::extended_feature_flags;

    g_ebx_cpuid[addr] = subleaf0::ebx::clwb::mask;
    CHECK(subleaf0::ebx::clwb::is_enabled());
    g_ebx_cpuid[addr] = 0x0;
    CHECK(subleaf0::ebx::clwb::is_disabled());

    g_ebx_cpuid[addr] = subleaf0::ebx::clwb::mask;
    CHECK(subleaf0::ebx::clwb::is_enabled(subleaf0::ebx::clwb::mask));
    g_ebx_cpuid[addr] = 0x0;
    CHECK(subleaf0::ebx::clwb::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_extended_feature_flags_subleaf0_ebx_trace")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::extended_feature_flags;

    g_ebx_cpuid[addr] = subleaf0::ebx::trace::mask;
    CHECK(subleaf0::ebx::trace::is_enabled());
    g_ebx_cpuid[addr] = 0x0;
    CHECK(subleaf0::ebx::trace::is_disabled());

    g_ebx_cpuid[addr] = subleaf0::ebx::trace::mask;
    CHECK(subleaf0::ebx::trace::is_enabled(subleaf0::ebx::trace::mask));
    g_ebx_cpuid[addr] = 0x0;
    CHECK(subleaf0::ebx::trace::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_extended_feature_flags_subleaf0_ebx_sha")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::extended_feature_flags;

    g_ebx_cpuid[addr] = subleaf0::ebx::sha::mask;
    CHECK(subleaf0::ebx::sha::is_enabled());
    g_ebx_cpuid[addr] = 0x0;
    CHECK(subleaf0::ebx::sha::is_disabled());

    g_ebx_cpuid[addr] = subleaf0::ebx::sha::mask;
    CHECK(subleaf0::ebx::sha::is_enabled(subleaf0::ebx::sha::mask));
    g_ebx_cpuid[addr] = 0x0;
    CHECK(subleaf0::ebx::sha::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_extended_feature_flags_subleaf0_ecx")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::extended_feature_flags;

    g_ecx_cpuid[addr] = 0xFFFFFFFF;
    CHECK(subleaf0::ecx::get() == 0xFFFFFFFF);
}

TEST_CASE("intrinsics: cpuid_extended_feature_flags_subleaf0_ecx_prefetchwt1")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::extended_feature_flags;

    g_ecx_cpuid[addr] = subleaf0::ecx::prefetchwt1::mask;
    CHECK(subleaf0::ecx::prefetchwt1::is_enabled());
    g_ecx_cpuid[addr] = 0x0;
    CHECK(subleaf0::ecx::prefetchwt1::is_disabled());

    g_ecx_cpuid[addr] = subleaf0::ecx::prefetchwt1::mask;
    CHECK(subleaf0::ecx::prefetchwt1::is_enabled(subleaf0::ecx::prefetchwt1::mask));
    g_ecx_cpuid[addr] = 0x0;
    CHECK(subleaf0::ecx::prefetchwt1::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_extended_feature_flags_subleaf0_ecx_umip")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::extended_feature_flags;

    g_ecx_cpuid[addr] = subleaf0::ecx::umip::mask;
    CHECK(subleaf0::ecx::umip::is_enabled());
    g_ecx_cpuid[addr] = 0x0;
    CHECK(subleaf0::ecx::umip::is_disabled());

    g_ecx_cpuid[addr] = subleaf0::ecx::umip::mask;
    CHECK(subleaf0::ecx::umip::is_enabled(subleaf0::ecx::umip::mask));
    g_ecx_cpuid[addr] = 0x0;
    CHECK(subleaf0::ecx::umip::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_extended_feature_flags_subleaf0_ecx_pku")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::extended_feature_flags;

    g_ecx_cpuid[addr] = subleaf0::ecx::pku::mask;
    CHECK(subleaf0::ecx::pku::is_enabled());
    g_ecx_cpuid[addr] = 0x0;
    CHECK(subleaf0::ecx::pku::is_disabled());

    g_ecx_cpuid[addr] = subleaf0::ecx::pku::mask;
    CHECK(subleaf0::ecx::pku::is_enabled(subleaf0::ecx::pku::mask));
    g_ecx_cpuid[addr] = 0x0;
    CHECK(subleaf0::ecx::pku::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_extended_feature_flags_subleaf0_ecx_ospke")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::extended_feature_flags;

    g_ecx_cpuid[addr] = subleaf0::ecx::ospke::mask;
    CHECK(subleaf0::ecx::ospke::is_enabled());
    g_ecx_cpuid[addr] = 0x0;
    CHECK(subleaf0::ecx::ospke::is_disabled());

    g_ecx_cpuid[addr] = subleaf0::ecx::ospke::mask;
    CHECK(subleaf0::ecx::ospke::is_enabled(subleaf0::ecx::ospke::mask));
    g_ecx_cpuid[addr] = 0x0;
    CHECK(subleaf0::ecx::ospke::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_extended_feature_flags_subleaf0_ecx_mawau")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::extended_feature_flags;

    g_ecx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(subleaf0::ecx::mawau::get() ==
          (subleaf0::ecx::mawau::mask >> subleaf0::ecx::mawau::from));
    CHECK(subleaf0::ecx::mawau::get(subleaf0::ecx::mawau::mask) ==
          (subleaf0::ecx::mawau::mask >> subleaf0::ecx::mawau::from));
}

TEST_CASE("intrinsics: cpuid_extended_feature_flags_subleaf0_ecx_rdpid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::extended_feature_flags;

    g_ecx_cpuid[addr] = subleaf0::ecx::rdpid::mask;
    CHECK(subleaf0::ecx::rdpid::is_enabled());
    g_ecx_cpuid[addr] = 0x0;
    CHECK(subleaf0::ecx::rdpid::is_disabled());

    g_ecx_cpuid[addr] = subleaf0::ecx::rdpid::mask;
    CHECK(subleaf0::ecx::rdpid::is_enabled(subleaf0::ecx::rdpid::mask));
    g_ecx_cpuid[addr] = 0x0;
    CHECK(subleaf0::ecx::rdpid::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_extended_feature_flags_subleaf0_ecx_sgx_lc")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::extended_feature_flags;

    g_ecx_cpuid[addr] = subleaf0::ecx::sgx_lc::mask;
    CHECK(subleaf0::ecx::sgx_lc::is_enabled());
    g_ecx_cpuid[addr] = 0x0;
    CHECK(subleaf0::ecx::sgx_lc::is_disabled());

    g_ecx_cpuid[addr] = subleaf0::ecx::sgx_lc::mask;
    CHECK(subleaf0::ecx::sgx_lc::is_enabled(subleaf0::ecx::sgx_lc::mask));
    g_ecx_cpuid[addr] = 0x0;
    CHECK(subleaf0::ecx::sgx_lc::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_arch_perf_monitoring")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::arch_perf_monitoring;

    dump(0);
}

TEST_CASE("intrinsics: cpuid_arch_perf_monitoring_eax")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::arch_perf_monitoring;

    g_eax_cpuid[addr] = 0xFFFFFFFF;
    CHECK(eax::get() == 0xFFFFFFFF);
}

TEST_CASE("intrinsics: cpuid_arch_perf_monitoring_eax_version_id")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::arch_perf_monitoring;

    g_eax_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(eax::version_id::get() ==
          (eax::version_id::mask >> eax::version_id::from));
    CHECK(eax::version_id::get(eax::version_id::mask) ==
          (eax::version_id::mask >> eax::version_id::from));
}

TEST_CASE("intrinsics: cpuid_arch_perf_monitoring_eax_gppmc_count")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::arch_perf_monitoring;

    g_eax_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(eax::gppmc_count::get() ==
          (eax::gppmc_count::mask >> eax::gppmc_count::from));
    CHECK(eax::gppmc_count::get(eax::gppmc_count::mask) ==
          (eax::gppmc_count::mask >> eax::gppmc_count::from));
}

TEST_CASE("intrinsics: cpuid_arch_perf_monitoring_eax_gppmc_bit_width")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::arch_perf_monitoring;

    g_eax_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(eax::gppmc_bit_width::get() ==
          (eax::gppmc_bit_width::mask >> eax::gppmc_bit_width::from));
    CHECK(eax::gppmc_bit_width::get(eax::gppmc_bit_width::mask) ==
          (eax::gppmc_bit_width::mask >> eax::gppmc_bit_width::from));
}

TEST_CASE("intrinsics: cpuid_arch_perf_monitoring_eax_ebx_enumeration_length")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::arch_perf_monitoring;

    g_eax_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(eax::ebx_enumeration_length::get() ==
          (eax::ebx_enumeration_length::mask >> eax::ebx_enumeration_length::from));
    CHECK(eax::ebx_enumeration_length::get(eax::ebx_enumeration_length::mask) ==
          (eax::ebx_enumeration_length::mask >> eax::ebx_enumeration_length::from));
}

TEST_CASE("intrinsics: cpuid_arch_perf_monitoring_ebx")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::arch_perf_monitoring;

    g_ebx_cpuid[addr] = 0xFFFFFFFF;
    CHECK(ebx::get() == 0xFFFFFFFF);
}

TEST_CASE("intrinsics: cpuid_arch_perf_monitoring_ebx_core_cycle_event")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::arch_perf_monitoring;

    g_ebx_cpuid[addr] = ebx::core_cycle_event::mask;
    CHECK(ebx::core_cycle_event::is_enabled());
    g_ebx_cpuid[addr] = 0x0;
    CHECK(ebx::core_cycle_event::is_disabled());

    g_ebx_cpuid[addr] = ebx::core_cycle_event::mask;
    CHECK(ebx::core_cycle_event::is_enabled(ebx::core_cycle_event::mask));
    g_ebx_cpuid[addr] = 0x0;
    CHECK(ebx::core_cycle_event::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_arch_perf_monitoring_ebx_instr_retired_event")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::arch_perf_monitoring;

    g_ebx_cpuid[addr] = ebx::instr_retired_event::mask;
    CHECK(ebx::instr_retired_event::is_enabled());
    g_ebx_cpuid[addr] = 0x0;
    CHECK(ebx::instr_retired_event::is_disabled());

    g_ebx_cpuid[addr] = ebx::instr_retired_event::mask;
    CHECK(ebx::instr_retired_event::is_enabled(ebx::instr_retired_event::mask));
    g_ebx_cpuid[addr] = 0x0;
    CHECK(ebx::instr_retired_event::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_arch_perf_monitoring_ebx_reference_cycles_event")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::arch_perf_monitoring;

    g_ebx_cpuid[addr] = ebx::reference_cycles_event::mask;
    CHECK(ebx::reference_cycles_event::is_enabled());
    g_ebx_cpuid[addr] = 0x0;
    CHECK(ebx::reference_cycles_event::is_disabled());

    g_ebx_cpuid[addr] = ebx::reference_cycles_event::mask;
    CHECK(ebx::reference_cycles_event::is_enabled(ebx::reference_cycles_event::mask));
    g_ebx_cpuid[addr] = 0x0;
    CHECK(ebx::reference_cycles_event::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_arch_perf_monitoring_ebx_llc_reference_event")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::arch_perf_monitoring;

    g_ebx_cpuid[addr] = ebx::llc_reference_event::mask;
    CHECK(ebx::llc_reference_event::is_enabled());
    g_ebx_cpuid[addr] = 0x0;
    CHECK(ebx::llc_reference_event::is_disabled());

    g_ebx_cpuid[addr] = ebx::llc_reference_event::mask;
    CHECK(ebx::llc_reference_event::is_enabled(ebx::llc_reference_event::mask));
    g_ebx_cpuid[addr] = 0x0;
    CHECK(ebx::llc_reference_event::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_arch_perf_monitoring_ebx_llc_misses_event")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::arch_perf_monitoring;

    g_ebx_cpuid[addr] = ebx::llc_misses_event::mask;
    CHECK(ebx::llc_misses_event::is_enabled());
    g_ebx_cpuid[addr] = 0x0;
    CHECK(ebx::llc_misses_event::is_disabled());

    g_ebx_cpuid[addr] = ebx::llc_misses_event::mask;
    CHECK(ebx::llc_misses_event::is_enabled(ebx::llc_misses_event::mask));
    g_ebx_cpuid[addr] = 0x0;
    CHECK(ebx::llc_misses_event::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_arch_perf_monitoring_ebx_branch_instr_retired_event")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::arch_perf_monitoring;

    g_ebx_cpuid[addr] = ebx::branch_instr_retired_event::mask;
    CHECK(ebx::branch_instr_retired_event::is_enabled());
    g_ebx_cpuid[addr] = 0x0;
    CHECK(ebx::branch_instr_retired_event::is_disabled());

    g_ebx_cpuid[addr] = ebx::branch_instr_retired_event::mask;
    CHECK(ebx::branch_instr_retired_event::is_enabled(ebx::branch_instr_retired_event::mask));
    g_ebx_cpuid[addr] = 0x0;
    CHECK(ebx::branch_instr_retired_event::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_arch_perf_monitoring_ebx_branch_mispredict_retired_event")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::arch_perf_monitoring;

    g_ebx_cpuid[addr] = ebx::branch_mispredict_retired_event::mask;
    CHECK(ebx::branch_mispredict_retired_event::is_enabled());
    g_ebx_cpuid[addr] = 0x0;
    CHECK(ebx::branch_mispredict_retired_event::is_disabled());

    g_ebx_cpuid[addr] = ebx::branch_mispredict_retired_event::mask;
    CHECK(ebx::branch_mispredict_retired_event::is_enabled(ebx::branch_mispredict_retired_event::mask));
    g_ebx_cpuid[addr] = 0x0;
    CHECK(ebx::branch_mispredict_retired_event::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_arch_perf_monitoring_edx")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::arch_perf_monitoring;

    g_edx_cpuid[addr] = 0xFFFFFFFF;
    CHECK(edx::get() == 0xFFFFFFFF);
}

TEST_CASE("intrinsics: cpuid_arch_perf_monitoring_edx_ffpmc_count")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::arch_perf_monitoring;

    g_edx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(edx::ffpmc_count::get() ==
          (edx::ffpmc_count::mask >> edx::ffpmc_count::from));
    CHECK(edx::ffpmc_count::get(edx::ffpmc_count::mask) ==
          (edx::ffpmc_count::mask >> edx::ffpmc_count::from));
}

TEST_CASE("intrinsics: cpuid_arch_perf_monitoring_edx_ffpmc_bit_width")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::arch_perf_monitoring;

    g_edx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(edx::ffpmc_bit_width::get() ==
          (edx::ffpmc_bit_width::mask >> edx::ffpmc_bit_width::from));
    CHECK(edx::ffpmc_bit_width::get(edx::ffpmc_bit_width::mask) ==
          (edx::ffpmc_bit_width::mask >> edx::ffpmc_bit_width::from));
}

TEST_CASE("intrinsics: cpuid_cache_tlb_info")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::cache_tlb_info;

    dump(0);
}

TEST_CASE("intrinsics: cpuid_cache_tlb_info_eax")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::cache_tlb_info;

    g_eax_cpuid[addr] = 0xFFFFFFFF;
    CHECK(eax::get() == 0xFFFFFFFF);
}

TEST_CASE("intrinsics: cpuid_cache_tlb_info_ebx")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::cache_tlb_info;

    g_ebx_cpuid[addr] = 0xFFFFFFFF;
    CHECK(ebx::get() == 0xFFFFFFFF);
}

TEST_CASE("intrinsics: cpuid_cache_tlb_info_ecx")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::cache_tlb_info;

    g_ecx_cpuid[addr] = 0xFFFFFFFF;
    CHECK(ecx::get() == 0xFFFFFFFF);
}

TEST_CASE("intrinsics: cpuid_cache_tlb_info_edx")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::cache_tlb_info;

    g_edx_cpuid[addr] = 0xFFFFFFFF;
    CHECK(edx::get() == 0xFFFFFFFF);
}

TEST_CASE("intrinsics: cpuid_serial_num")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::serial_num;

    dump(0);
}

TEST_CASE("intrinsics: cpuid_serial_num_ecx")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::serial_num;

    g_ecx_cpuid[addr] = 0xFFFFFFFF;
    CHECK(ecx::get() == 0xFFFFFFFF);
}

TEST_CASE("intrinsics: cpuid_serial_num_edx")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::serial_num;

    g_edx_cpuid[addr] = 0xFFFFFFFF;
    CHECK(edx::get() == 0xFFFFFFFF);
}

TEST_CASE("intrinsics: cpuid_cache_parameters")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::cache_parameters;

    dump(0);
}

TEST_CASE("intrinsics: cpuid_cache_parameters_eax")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::cache_parameters;

    g_eax_cpuid[addr] = 0xFFFFFFFF;
    CHECK(eax::get() == 0xFFFFFFFF);
}

TEST_CASE("intrinsics: cpuid_cache_parameters_eax_cache_type")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::cache_parameters;

    g_eax_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(eax::cache_type::get() ==
          (eax::cache_type::mask >> eax::cache_type::from));
    CHECK(eax::cache_type::get(eax::cache_type::mask) ==
          (eax::cache_type::mask >> eax::cache_type::from));
}

TEST_CASE("intrinsics: cpuid_cache_parameters_eax_cache_level")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::cache_parameters;

    g_eax_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(eax::cache_level::get() ==
          (eax::cache_level::mask >> eax::cache_level::from));
    CHECK(eax::cache_level::get(eax::cache_level::mask) ==
          (eax::cache_level::mask >> eax::cache_level::from));
}

TEST_CASE("intrinsics: cpuid_cache_parameters_eax_self_init_level")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::cache_parameters;

    g_eax_cpuid[addr] = eax::self_init_level::mask;
    CHECK(eax::self_init_level::is_enabled());
    g_eax_cpuid[addr] = 0x0;
    CHECK(eax::self_init_level::is_disabled());

    g_eax_cpuid[addr] = eax::self_init_level::mask;
    CHECK(eax::self_init_level::is_enabled(eax::self_init_level::mask));
    g_eax_cpuid[addr] = 0x0;
    CHECK(eax::self_init_level::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_cache_parameters_eax_fully_associative")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::cache_parameters;

    g_eax_cpuid[addr] = eax::fully_associative::mask;
    CHECK(eax::fully_associative::is_enabled());
    g_eax_cpuid[addr] = 0x0;
    CHECK(eax::fully_associative::is_disabled());

    g_eax_cpuid[addr] = eax::fully_associative::mask;
    CHECK(eax::fully_associative::is_enabled(eax::fully_associative::mask));
    g_eax_cpuid[addr] = 0x0;
    CHECK(eax::fully_associative::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_cache_parameters_eax_max_ids_logical")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::cache_parameters;

    g_eax_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(eax::max_ids_logical::get() ==
          (eax::max_ids_logical::mask >> eax::max_ids_logical::from));
    CHECK(eax::max_ids_logical::get(eax::max_ids_logical::mask) ==
          (eax::max_ids_logical::mask >> eax::max_ids_logical::from));
}

TEST_CASE("intrinsics: cpuid_cache_parameters_eax_max_ids_physical")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::cache_parameters;

    g_eax_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(eax::max_ids_physical::get() ==
          (eax::max_ids_physical::mask >> eax::max_ids_physical::from));
    CHECK(eax::max_ids_physical::get(eax::max_ids_physical::mask) ==
          (eax::max_ids_physical::mask >> eax::max_ids_physical::from));
}

TEST_CASE("intrinsics: cpuid_cache_parameters_ebx")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::cache_parameters;

    g_ebx_cpuid[addr] = 0xFFFFFFFF;
    CHECK(ebx::get() == 0xFFFFFFFF);
}

TEST_CASE("intrinsics: cpuid_cache_parameters_ebx_l")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::cache_parameters;

    g_ebx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(ebx::l::get() ==
          (ebx::l::mask >> ebx::l::from));
    CHECK(ebx::l::get(ebx::l::mask) ==
          (ebx::l::mask >> ebx::l::from));
}

TEST_CASE("intrinsics: cpuid_cache_parameters_ebx_p")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::cache_parameters;

    g_ebx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(ebx::p::get() ==
          (ebx::p::mask >> ebx::p::from));
    CHECK(ebx::p::get(ebx::p::mask) ==
          (ebx::p::mask >> ebx::p::from));
}

TEST_CASE("intrinsics: cpuid_cache_parameters_ebx_w")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::cache_parameters;

    g_ebx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(ebx::w::get() ==
          (ebx::w::mask >> ebx::w::from));
    CHECK(ebx::w::get(ebx::w::mask) ==
          (ebx::w::mask >> ebx::w::from));
}

TEST_CASE("intrinsics: cpuid_cache_parameters_ecx")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::cache_parameters;

    g_ecx_cpuid[addr] = 0xFFFFFFFF;
    CHECK(ecx::get() == 0xFFFFFFFF);
}

TEST_CASE("intrinsics: cpuid_cache_parameters_ecx_num_sets")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::cache_parameters;

    g_ecx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(ecx::num_sets::get() ==
          (ecx::num_sets::mask >> ecx::num_sets::from));
    CHECK(ecx::num_sets::get(ecx::num_sets::mask) ==
          (ecx::num_sets::mask >> ecx::num_sets::from));
}

TEST_CASE("intrinsics: cpuid_cache_parameters_edx")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::cache_parameters;

    g_edx_cpuid[addr] = 0xFFFFFFFF;
    CHECK(edx::get() == 0xFFFFFFFF);
}

TEST_CASE("intrinsics: cpuid_cache_parameters_edx_wbinvd_invd")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::cache_parameters;

    g_edx_cpuid[addr] = edx::wbinvd_invd::mask;
    CHECK(edx::wbinvd_invd::is_enabled());
    g_edx_cpuid[addr] = 0x0;
    CHECK(edx::wbinvd_invd::is_disabled());

    g_edx_cpuid[addr] = edx::wbinvd_invd::mask;
    CHECK(edx::wbinvd_invd::is_enabled(edx::wbinvd_invd::mask));
    g_edx_cpuid[addr] = 0x0;
    CHECK(edx::wbinvd_invd::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_cache_parameters_edx_cache_inclusiveness")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::cache_parameters;

    g_edx_cpuid[addr] = edx::cache_inclusiveness::mask;
    CHECK(edx::cache_inclusiveness::is_enabled());
    g_edx_cpuid[addr] = 0x0;
    CHECK(edx::cache_inclusiveness::is_disabled());

    g_edx_cpuid[addr] = edx::cache_inclusiveness::mask;
    CHECK(edx::cache_inclusiveness::is_enabled(edx::cache_inclusiveness::mask));
    g_edx_cpuid[addr] = 0x0;
    CHECK(edx::cache_inclusiveness::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_cache_parameters_edx_complex_cache_indexing")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::cache_parameters;

    g_edx_cpuid[addr] = edx::complex_cache_indexing::mask;
    CHECK(edx::complex_cache_indexing::is_enabled());
    g_edx_cpuid[addr] = 0x0;
    CHECK(edx::complex_cache_indexing::is_disabled());

    g_edx_cpuid[addr] = edx::complex_cache_indexing::mask;
    CHECK(edx::complex_cache_indexing::is_enabled(edx::complex_cache_indexing::mask));
    g_edx_cpuid[addr] = 0x0;
    CHECK(edx::complex_cache_indexing::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_monitor_mwait")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::monitor_mwait;

    dump(0);
}

TEST_CASE("intrinsics: cpuid_monitor_mwait_eax")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::monitor_mwait;

    g_eax_cpuid[addr] = 0xFFFFFFFF;
    CHECK(eax::get() == 0xFFFFFFFF);
}

TEST_CASE("intrinsics: cpuid_monitor_mwait_eax_min_line_size")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::monitor_mwait;

    g_eax_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(eax::min_line_size::get() ==
          (eax::min_line_size::mask >> eax::min_line_size::from));
    CHECK(eax::min_line_size::get(eax::min_line_size::mask) ==
          (eax::min_line_size::mask >> eax::min_line_size::from));
}

TEST_CASE("intrinsics: cpuid_monitor_mwait_ebx")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::monitor_mwait;

    g_ebx_cpuid[addr] = 0xFFFFFFFF;
    CHECK(ebx::get() == 0xFFFFFFFF);
}

TEST_CASE("intrinsics: cpuid_monitor_mwait_ebx_max_line_size")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::monitor_mwait;

    g_ebx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(ebx::max_line_size::get() ==
          (ebx::max_line_size::mask >> ebx::max_line_size::from));
    CHECK(ebx::max_line_size::get(ebx::max_line_size::mask) ==
          (ebx::max_line_size::mask >> ebx::max_line_size::from));
}

TEST_CASE("intrinsics: cpuid_monitor_mwait_ecx")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::monitor_mwait;

    g_ecx_cpuid[addr] = 0xFFFFFFFF;
    CHECK(ecx::get() == 0xFFFFFFFF);
}

TEST_CASE("intrinsics: cpuid_monitor_mwait_ecx_enum_mwait_extensions")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::monitor_mwait;

    g_ecx_cpuid[addr] = ecx::enum_mwait_extensions::mask;
    CHECK(ecx::enum_mwait_extensions::is_enabled());
    g_ecx_cpuid[addr] = 0x0;
    CHECK(ecx::enum_mwait_extensions::is_disabled());

    g_ecx_cpuid[addr] = ecx::enum_mwait_extensions::mask;
    CHECK(ecx::enum_mwait_extensions::is_enabled(ecx::enum_mwait_extensions::mask));
    g_ecx_cpuid[addr] = 0x0;
    CHECK(ecx::enum_mwait_extensions::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_monitor_mwait_ecx_interrupt_break_event")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::monitor_mwait;

    g_ecx_cpuid[addr] = ecx::interrupt_break_event::mask;
    CHECK(ecx::interrupt_break_event::is_enabled());
    g_ecx_cpuid[addr] = 0x0;
    CHECK(ecx::interrupt_break_event::is_disabled());

    g_ecx_cpuid[addr] = ecx::interrupt_break_event::mask;
    CHECK(ecx::interrupt_break_event::is_enabled(ecx::interrupt_break_event::mask));
    g_ecx_cpuid[addr] = 0x0;
    CHECK(ecx::interrupt_break_event::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_monitor_mwait_edx")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::monitor_mwait;

    g_edx_cpuid[addr] = 0xFFFFFFFF;
    CHECK(edx::get() == 0xFFFFFFFF);
}

TEST_CASE("intrinsics: cpuid_monitor_mwait_edx_num_c0")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::monitor_mwait;

    g_edx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(edx::num_c0::get() ==
          (edx::num_c0::mask >> edx::num_c0::from));
    CHECK(edx::num_c0::get(edx::num_c0::mask) ==
          (edx::num_c0::mask >> edx::num_c0::from));
}

TEST_CASE("intrinsics: cpuid_monitor_mwait_edx_num_c1")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::monitor_mwait;

    g_edx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(edx::num_c1::get() ==
          (edx::num_c1::mask >> edx::num_c1::from));
    CHECK(edx::num_c1::get(edx::num_c1::mask) ==
          (edx::num_c1::mask >> edx::num_c1::from));
}

TEST_CASE("intrinsics: cpuid_monitor_mwait_edx_num_c2")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::monitor_mwait;

    g_edx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(edx::num_c2::get() ==
          (edx::num_c2::mask >> edx::num_c2::from));
    CHECK(edx::num_c2::get(edx::num_c2::mask) ==
          (edx::num_c2::mask >> edx::num_c2::from));
}

TEST_CASE("intrinsics: cpuid_monitor_mwait_edx_num_c3")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::monitor_mwait;

    g_edx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(edx::num_c3::get() ==
          (edx::num_c3::mask >> edx::num_c3::from));
    CHECK(edx::num_c3::get(edx::num_c3::mask) ==
          (edx::num_c3::mask >> edx::num_c3::from));
}

TEST_CASE("intrinsics: cpuid_monitor_mwait_edx_num_c4")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::monitor_mwait;

    g_edx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(edx::num_c4::get() ==
          (edx::num_c4::mask >> edx::num_c4::from));
    CHECK(edx::num_c4::get(edx::num_c4::mask) ==
          (edx::num_c4::mask >> edx::num_c4::from));
}

TEST_CASE("intrinsics: cpuid_monitor_mwait_edx_num_c5")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::monitor_mwait;

    g_edx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(edx::num_c5::get() ==
          (edx::num_c5::mask >> edx::num_c5::from));
    CHECK(edx::num_c5::get(edx::num_c5::mask) ==
          (edx::num_c5::mask >> edx::num_c5::from));
}

TEST_CASE("intrinsics: cpuid_monitor_mwait_edx_num_c6")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::monitor_mwait;

    g_edx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(edx::num_c6::get() ==
          (edx::num_c6::mask >> edx::num_c6::from));
    CHECK(edx::num_c6::get(edx::num_c6::mask) ==
          (edx::num_c6::mask >> edx::num_c6::from));
}

TEST_CASE("intrinsics: cpuid_monitor_mwait_edx_num_c7")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::monitor_mwait;

    g_edx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(edx::num_c7::get() ==
          (edx::num_c7::mask >> edx::num_c7::from));
    CHECK(edx::num_c7::get(edx::num_c7::mask) ==
          (edx::num_c7::mask >> edx::num_c7::from));
}

TEST_CASE("intrinsics: cpuid_therm_power_management")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::therm_power_management;

    dump(0);
}

TEST_CASE("intrinsics: cpuid_therm_power_management_eax")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::therm_power_management;

    g_eax_cpuid[addr] = 0xFFFFFFFF;
    CHECK(eax::get() == 0xFFFFFFFF);
}

TEST_CASE("intrinsics: cpuid_therm_power_management_eax_temp_sensor")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::therm_power_management;

    g_eax_cpuid[addr] = eax::temp_sensor::mask;
    CHECK(eax::temp_sensor::is_enabled());
    g_eax_cpuid[addr] = 0x0;
    CHECK(eax::temp_sensor::is_disabled());

    g_eax_cpuid[addr] = eax::temp_sensor::mask;
    CHECK(eax::temp_sensor::is_enabled(eax::temp_sensor::mask));
    g_eax_cpuid[addr] = 0x0;
    CHECK(eax::temp_sensor::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_therm_power_management_eax_intel_turbo")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::therm_power_management;

    g_eax_cpuid[addr] = eax::intel_turbo::mask;
    CHECK(eax::intel_turbo::is_enabled());
    g_eax_cpuid[addr] = 0x0;
    CHECK(eax::intel_turbo::is_disabled());

    g_eax_cpuid[addr] = eax::intel_turbo::mask;
    CHECK(eax::intel_turbo::is_enabled(eax::intel_turbo::mask));
    g_eax_cpuid[addr] = 0x0;
    CHECK(eax::intel_turbo::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_therm_power_management_eax_arat")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::therm_power_management;

    g_eax_cpuid[addr] = eax::arat::mask;
    CHECK(eax::arat::is_enabled());
    g_eax_cpuid[addr] = 0x0;
    CHECK(eax::arat::is_disabled());

    g_eax_cpuid[addr] = eax::arat::mask;
    CHECK(eax::arat::is_enabled(eax::arat::mask));
    g_eax_cpuid[addr] = 0x0;
    CHECK(eax::arat::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_therm_power_management_eax_pln")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::therm_power_management;

    g_eax_cpuid[addr] = eax::pln::mask;
    CHECK(eax::pln::is_enabled());
    g_eax_cpuid[addr] = 0x0;
    CHECK(eax::pln::is_disabled());

    g_eax_cpuid[addr] = eax::pln::mask;
    CHECK(eax::pln::is_enabled(eax::pln::mask));
    g_eax_cpuid[addr] = 0x0;
    CHECK(eax::pln::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_therm_power_management_eax_ecmd")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::therm_power_management;

    g_eax_cpuid[addr] = eax::ecmd::mask;
    CHECK(eax::ecmd::is_enabled());
    g_eax_cpuid[addr] = 0x0;
    CHECK(eax::ecmd::is_disabled());

    g_eax_cpuid[addr] = eax::ecmd::mask;
    CHECK(eax::ecmd::is_enabled(eax::ecmd::mask));
    g_eax_cpuid[addr] = 0x0;
    CHECK(eax::ecmd::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_therm_power_management_eax_ptm")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::therm_power_management;

    g_eax_cpuid[addr] = eax::ptm::mask;
    CHECK(eax::ptm::is_enabled());
    g_eax_cpuid[addr] = 0x0;
    CHECK(eax::ptm::is_disabled());

    g_eax_cpuid[addr] = eax::ptm::mask;
    CHECK(eax::ptm::is_enabled(eax::ptm::mask));
    g_eax_cpuid[addr] = 0x0;
    CHECK(eax::ptm::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_therm_power_management_eax_hwp")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::therm_power_management;

    g_eax_cpuid[addr] = eax::hwp::mask;
    CHECK(eax::hwp::is_enabled());
    g_eax_cpuid[addr] = 0x0;
    CHECK(eax::hwp::is_disabled());

    g_eax_cpuid[addr] = eax::hwp::mask;
    CHECK(eax::hwp::is_enabled(eax::hwp::mask));
    g_eax_cpuid[addr] = 0x0;
    CHECK(eax::hwp::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_therm_power_management_eax_hwp_notification")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::therm_power_management;

    g_eax_cpuid[addr] = eax::hwp_notification::mask;
    CHECK(eax::hwp_notification::is_enabled());
    g_eax_cpuid[addr] = 0x0;
    CHECK(eax::hwp_notification::is_disabled());

    g_eax_cpuid[addr] = eax::hwp_notification::mask;
    CHECK(eax::hwp_notification::is_enabled(eax::hwp_notification::mask));
    g_eax_cpuid[addr] = 0x0;
    CHECK(eax::hwp_notification::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_therm_power_management_eax_hwp_energy_perf")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::therm_power_management;

    g_eax_cpuid[addr] = eax::hwp_energy_perf::mask;
    CHECK(eax::hwp_energy_perf::is_enabled());
    g_eax_cpuid[addr] = 0x0;
    CHECK(eax::hwp_energy_perf::is_disabled());

    g_eax_cpuid[addr] = eax::hwp_energy_perf::mask;
    CHECK(eax::hwp_energy_perf::is_enabled(eax::hwp_energy_perf::mask));
    g_eax_cpuid[addr] = 0x0;
    CHECK(eax::hwp_energy_perf::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_therm_power_management_eax_hwp_package_request")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::therm_power_management;

    g_eax_cpuid[addr] = eax::hwp_package_request::mask;
    CHECK(eax::hwp_package_request::is_enabled());
    g_eax_cpuid[addr] = 0x0;
    CHECK(eax::hwp_package_request::is_disabled());

    g_eax_cpuid[addr] = eax::hwp_package_request::mask;
    CHECK(eax::hwp_package_request::is_enabled(eax::hwp_package_request::mask));
    g_eax_cpuid[addr] = 0x0;
    CHECK(eax::hwp_package_request::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_therm_power_management_eax_hdc")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::therm_power_management;

    g_eax_cpuid[addr] = eax::hdc::mask;
    CHECK(eax::hdc::is_enabled());
    g_eax_cpuid[addr] = 0x0;
    CHECK(eax::hdc::is_disabled());

    g_eax_cpuid[addr] = eax::hdc::mask;
    CHECK(eax::hdc::is_enabled(eax::hdc::mask));
    g_eax_cpuid[addr] = 0x0;
    CHECK(eax::hdc::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_therm_power_management_ebx")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::therm_power_management;

    g_ebx_cpuid[addr] = 0xFFFFFFFF;
    CHECK(ebx::get() == 0xFFFFFFFF);
}

TEST_CASE("intrinsics: cpuid_therm_power_management_ebx_num_interrupts")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::therm_power_management;

    g_ebx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(ebx::num_interrupts::get() ==
          (ebx::num_interrupts::mask >> ebx::num_interrupts::from));
    CHECK(ebx::num_interrupts::get(ebx::num_interrupts::mask) ==
          (ebx::num_interrupts::mask >> ebx::num_interrupts::from));
}

TEST_CASE("intrinsics: cpuid_therm_power_management_ecx")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::therm_power_management;

    g_ecx_cpuid[addr] = 0xFFFFFFFF;
    CHECK(ecx::get() == 0xFFFFFFFF);
}

TEST_CASE("intrinsics: cpuid_therm_power_management_ecx_hardware_feedback")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::therm_power_management;

    g_ecx_cpuid[addr] = ecx::hardware_feedback::mask;
    CHECK(ecx::hardware_feedback::is_enabled());
    g_ecx_cpuid[addr] = 0x0;
    CHECK(ecx::hardware_feedback::is_disabled());

    g_ecx_cpuid[addr] = ecx::hardware_feedback::mask;
    CHECK(ecx::hardware_feedback::is_enabled(ecx::hardware_feedback::mask));
    g_ecx_cpuid[addr] = 0x0;
    CHECK(ecx::hardware_feedback::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_therm_power_management_ecx_energy_perf_bias")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::therm_power_management;

    g_ecx_cpuid[addr] = ecx::energy_perf_bias::mask;
    CHECK(ecx::energy_perf_bias::is_enabled());
    g_ecx_cpuid[addr] = 0x0;
    CHECK(ecx::energy_perf_bias::is_disabled());

    g_ecx_cpuid[addr] = ecx::energy_perf_bias::mask;
    CHECK(ecx::energy_perf_bias::is_enabled(ecx::energy_perf_bias::mask));
    g_ecx_cpuid[addr] = 0x0;
    CHECK(ecx::energy_perf_bias::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_access_cache")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::access_cache;

    dump(0);
}

TEST_CASE("intrinsics: cpuid_access_cache_eax")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::access_cache;

    g_eax_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(eax::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_topology_enumeration")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::topology_enumeration;

    dump(0);
}

TEST_CASE("intrinsics: cpuid_topology_enumeration_eax")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::topology_enumeration;

    g_eax_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(eax::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_topology_enumeration_eax_x2apic_shift")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::topology_enumeration;

    g_eax_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(eax::x2apic_shift::get() ==
          (eax::x2apic_shift::mask >> eax::x2apic_shift::from));
    CHECK(eax::x2apic_shift::get(eax::x2apic_shift::mask) ==
          (eax::x2apic_shift::mask >> eax::x2apic_shift::from));
}

TEST_CASE("intrinsics: cpuid_topology_enumeration_ebx")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::topology_enumeration;

    g_ebx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(ebx::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_topology_enumeration_ebx_num_processors")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::topology_enumeration;

    g_ebx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(ebx::num_processors::get() ==
          (ebx::num_processors::mask >> ebx::num_processors::from));
    CHECK(ebx::num_processors::get(ebx::num_processors::mask) ==
          (ebx::num_processors::mask >> ebx::num_processors::from));
}

TEST_CASE("intrinsics: cpuid_topology_enumeration_ecx")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::topology_enumeration;

    g_ecx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(ecx::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_topology_enumeration_ecx_level_number")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::topology_enumeration;

    g_ecx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(ecx::level_number::get() ==
          (ecx::level_number::mask >> ecx::level_number::from));
    CHECK(ecx::level_number::get(ecx::level_number::mask) ==
          (ecx::level_number::mask >> ecx::level_number::from));
}

TEST_CASE("intrinsics: cpuid_topology_enumeration_ecx_level_type")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::topology_enumeration;

    g_ecx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(ecx::level_type::get() ==
          (ecx::level_type::mask >> ecx::level_type::from));
    CHECK(ecx::level_type::get(ecx::level_type::mask) ==
          (ecx::level_type::mask >> ecx::level_type::from));
}

TEST_CASE("intrinsics: cpuid_topology_enumeration_edx")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::topology_enumeration;

    g_edx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(edx::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_topology_enumeration_edx_x2apic_id")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::topology_enumeration;

    g_edx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(edx::x2apic_id::get() ==
          (edx::x2apic_id::mask >> edx::x2apic_id::from));
    CHECK(edx::x2apic_id::get(edx::x2apic_id::mask) ==
          (edx::x2apic_id::mask >> edx::x2apic_id::from));
}

TEST_CASE("intrinsics: cpuid_extended_state_enum")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::extended_state_enum;

    dump(0);
}

TEST_CASE("intrinsics: cpuid_extended_state_enum_mainleaf_eax")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::extended_state_enum;

    g_eax_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(mainleaf::eax::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_extended_state_enum_mainleaf_ebx")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::extended_state_enum;

    g_ebx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(mainleaf::ebx::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_extended_state_enum_mainleaf_ecx")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::extended_state_enum;

    g_ecx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(mainleaf::ecx::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_extended_state_enum_mainleaf_edx")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::extended_state_enum;

    g_edx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(mainleaf::edx::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_extended_state_enum_subleaf1_eax")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::extended_state_enum;

    g_eax_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(subleaf1::eax::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_extended_state_enum_subleaf1_eax_xsaveopt")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::extended_state_enum;

    g_eax_cpuid[addr] = subleaf1::eax::xsaveopt::mask;
    CHECK(subleaf1::eax::xsaveopt::is_enabled());
    g_eax_cpuid[addr] = 0x0;
    CHECK(subleaf1::eax::xsaveopt::is_disabled());

    g_eax_cpuid[addr] = subleaf1::eax::xsaveopt::mask;
    CHECK(subleaf1::eax::xsaveopt::is_enabled(subleaf1::eax::xsaveopt::mask));
    g_eax_cpuid[addr] = 0x0;
    CHECK(subleaf1::eax::xsaveopt::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_extended_state_enum_subleaf1_eax_xsavec")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::extended_state_enum;

    g_eax_cpuid[addr] = subleaf1::eax::xsavec::mask;
    CHECK(subleaf1::eax::xsavec::is_enabled());
    g_eax_cpuid[addr] = 0x0;
    CHECK(subleaf1::eax::xsavec::is_disabled());

    g_eax_cpuid[addr] = subleaf1::eax::xsavec::mask;
    CHECK(subleaf1::eax::xsavec::is_enabled(subleaf1::eax::xsavec::mask));
    g_eax_cpuid[addr] = 0x0;
    CHECK(subleaf1::eax::xsavec::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_extended_state_enum_subleaf1_eax_xgetbv")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::extended_state_enum;

    g_eax_cpuid[addr] = subleaf1::eax::xgetbv::mask;
    CHECK(subleaf1::eax::xgetbv::is_enabled());
    g_eax_cpuid[addr] = 0x0;
    CHECK(subleaf1::eax::xgetbv::is_disabled());

    g_eax_cpuid[addr] = subleaf1::eax::xgetbv::mask;
    CHECK(subleaf1::eax::xgetbv::is_enabled(subleaf1::eax::xgetbv::mask));
    g_eax_cpuid[addr] = 0x0;
    CHECK(subleaf1::eax::xgetbv::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_extended_state_enum_subleaf1_eax_xsaves_xrstors")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::extended_state_enum;

    g_eax_cpuid[addr] = subleaf1::eax::xsaves_xrstors::mask;
    CHECK(subleaf1::eax::xsaves_xrstors::is_enabled());
    g_eax_cpuid[addr] = 0x0;
    CHECK(subleaf1::eax::xsaves_xrstors::is_disabled());

    g_eax_cpuid[addr] = subleaf1::eax::xsaves_xrstors::mask;
    CHECK(subleaf1::eax::xsaves_xrstors::is_enabled(subleaf1::eax::xsaves_xrstors::mask));
    g_eax_cpuid[addr] = 0x0;
    CHECK(subleaf1::eax::xsaves_xrstors::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_extended_state_enum_subleaf1_ebx")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::extended_state_enum;

    g_ebx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(subleaf1::ebx::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_extended_state_enum_subleaf1_ebx_xsave_size")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::extended_state_enum;

    g_ebx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(subleaf1::ebx::xsave_size::get() ==
          (subleaf1::ebx::xsave_size::mask >> subleaf1::ebx::xsave_size::from));
    CHECK(subleaf1::ebx::xsave_size::get(subleaf1::ebx::xsave_size::mask) ==
          (subleaf1::ebx::xsave_size::mask >> subleaf1::ebx::xsave_size::from));
}

TEST_CASE("intrinsics: cpuid_extended_state_enum_subleaf1_ecx")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::extended_state_enum;

    g_ecx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(subleaf1::ecx::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_extended_state_enum_subleaf1_ecx_supported_bits")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::extended_state_enum;

    g_ecx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(subleaf1::ecx::supported_bits::get() ==
          (subleaf1::ecx::supported_bits::mask >> subleaf1::ecx::supported_bits::from));
    CHECK(subleaf1::ecx::supported_bits::get(subleaf1::ecx::supported_bits::mask) ==
          (subleaf1::ecx::supported_bits::mask >> subleaf1::ecx::supported_bits::from));
}

TEST_CASE("intrinsics: cpuid_extended_state_enum_subleaf1_edx")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::extended_state_enum;

    g_edx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(subleaf1::edx::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_extended_state_enum_subleaf1_edx_supported_bits")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::extended_state_enum;

    g_edx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(subleaf1::edx::supported_bits::get() ==
          (subleaf1::edx::supported_bits::mask >> subleaf1::edx::supported_bits::from));
    CHECK(subleaf1::edx::supported_bits::get(subleaf1::edx::supported_bits::mask) ==
          (subleaf1::edx::supported_bits::mask >> subleaf1::edx::supported_bits::from));
}

TEST_CASE("intrinsics: cpuid_intel_rdt")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::intel_rdt;

    dump(0);
}

TEST_CASE("intrinsics: cpuid_intel_rdt_subleaf0_ebx")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::intel_rdt;

    g_ebx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(subleaf0::ebx::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_intel_rdt_subleaf0_ebx_rmid_max_range")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::intel_rdt;

    g_ebx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(subleaf0::ebx::rmid_max_range::get() ==
          (subleaf0::ebx::rmid_max_range::mask >> subleaf0::ebx::rmid_max_range::from));
    CHECK(subleaf0::ebx::rmid_max_range::get(subleaf0::ebx::rmid_max_range::mask) ==
          (subleaf0::ebx::rmid_max_range::mask >> subleaf0::ebx::rmid_max_range::from));
}

TEST_CASE("intrinsics: cpuid_intel_rdt_subleaf0_edx")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::intel_rdt;

    g_edx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(subleaf0::edx::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_intel_rdt_subleaf0_edx_l3_rdt")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::intel_rdt;

    g_edx_cpuid[addr] = subleaf0::edx::l3_rdt::mask;
    CHECK(subleaf0::edx::l3_rdt::is_enabled());
    g_edx_cpuid[addr] = 0x0;
    CHECK(subleaf0::edx::l3_rdt::is_disabled());

    g_edx_cpuid[addr] = subleaf0::edx::l3_rdt::mask;
    CHECK(subleaf0::edx::l3_rdt::is_enabled(subleaf0::edx::l3_rdt::mask));
    g_edx_cpuid[addr] = 0x0;
    CHECK(subleaf0::edx::l3_rdt::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_intel_rdt_subleaf1_ebx")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::intel_rdt;

    g_ebx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(subleaf1::ebx::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_intel_rdt_subleaf1_ebx_conversion_factor")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::intel_rdt;

    g_ebx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(subleaf1::ebx::conversion_factor::get() ==
          (subleaf1::ebx::conversion_factor::mask >> subleaf1::ebx::conversion_factor::from));
    CHECK(subleaf1::ebx::conversion_factor::get(subleaf1::ebx::conversion_factor::mask) ==
          (subleaf1::ebx::conversion_factor::mask >> subleaf1::ebx::conversion_factor::from));
}

TEST_CASE("intrinsics: cpuid_intel_rdt_subleaf1_ecx")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::intel_rdt;

    g_ecx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(subleaf1::ecx::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_intel_rdt_subleaf1_ecx_rmid_max_range")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::intel_rdt;

    g_ecx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(subleaf1::ecx::rmid_max_range::get() ==
          (subleaf1::ecx::rmid_max_range::mask >> subleaf1::ecx::rmid_max_range::from));
    CHECK(subleaf1::ecx::rmid_max_range::get(subleaf1::ecx::rmid_max_range::mask) ==
          (subleaf1::ecx::rmid_max_range::mask >> subleaf1::ecx::rmid_max_range::from));
}

TEST_CASE("intrinsics: cpuid_intel_rdt_subleaf1_edx")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::intel_rdt;

    g_edx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(subleaf1::edx::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_intel_rdt_subleaf1_edx_l3_occupancy")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::intel_rdt;

    g_edx_cpuid[addr] = subleaf1::edx::l3_occupancy::mask;
    CHECK(subleaf1::edx::l3_occupancy::is_enabled());
    g_edx_cpuid[addr] = 0x0;
    CHECK(subleaf1::edx::l3_occupancy::is_disabled());

    g_edx_cpuid[addr] = subleaf1::edx::l3_occupancy::mask;
    CHECK(subleaf1::edx::l3_occupancy::is_enabled(subleaf1::edx::l3_occupancy::mask));
    g_edx_cpuid[addr] = 0x0;
    CHECK(subleaf1::edx::l3_occupancy::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_intel_rdt_subleaf1_edx_l3_total_bandwith")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::intel_rdt;

    g_edx_cpuid[addr] = subleaf1::edx::l3_total_bandwith::mask;
    CHECK(subleaf1::edx::l3_total_bandwith::is_enabled());
    g_edx_cpuid[addr] = 0x0;
    CHECK(subleaf1::edx::l3_total_bandwith::is_disabled());

    g_edx_cpuid[addr] = subleaf1::edx::l3_total_bandwith::mask;
    CHECK(subleaf1::edx::l3_total_bandwith::is_enabled(subleaf1::edx::l3_total_bandwith::mask));
    g_edx_cpuid[addr] = 0x0;
    CHECK(subleaf1::edx::l3_total_bandwith::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_intel_rdt_subleaf1_edx_l3_local_bandwith")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::intel_rdt;

    g_edx_cpuid[addr] = subleaf1::edx::l3_local_bandwith::mask;
    CHECK(subleaf1::edx::l3_local_bandwith::is_enabled());
    g_edx_cpuid[addr] = 0x0;
    CHECK(subleaf1::edx::l3_local_bandwith::is_disabled());

    g_edx_cpuid[addr] = subleaf1::edx::l3_local_bandwith::mask;
    CHECK(subleaf1::edx::l3_local_bandwith::is_enabled(subleaf1::edx::l3_local_bandwith::mask));
    g_edx_cpuid[addr] = 0x0;
    CHECK(subleaf1::edx::l3_local_bandwith::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_allocation_enumeration")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::allocation_enumeration;

    dump(0);
}

TEST_CASE("intrinsics: cpuid_allocation_enumeration_subleaf0_ebx")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::allocation_enumeration;

    g_ebx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(subleaf0::ebx::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_allocation_enumeration_subleaf0_ebx_l3_cache")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::allocation_enumeration;

    g_ebx_cpuid[addr] = subleaf0::ebx::l3_cache::mask;
    CHECK(subleaf0::ebx::l3_cache::is_enabled());
    g_ebx_cpuid[addr] = 0x0;
    CHECK(subleaf0::ebx::l3_cache::is_disabled());

    g_ebx_cpuid[addr] = subleaf0::ebx::l3_cache::mask;
    CHECK(subleaf0::ebx::l3_cache::is_enabled(subleaf0::ebx::l3_cache::mask));
    g_ebx_cpuid[addr] = 0x0;
    CHECK(subleaf0::ebx::l3_cache::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_allocation_enumeration_subleaf0_ebx_l2_cache")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::allocation_enumeration;

    g_ebx_cpuid[addr] = subleaf0::ebx::l2_cache::mask;
    CHECK(subleaf0::ebx::l2_cache::is_enabled());
    g_ebx_cpuid[addr] = 0x0;
    CHECK(subleaf0::ebx::l2_cache::is_disabled());

    g_ebx_cpuid[addr] = subleaf0::ebx::l2_cache::mask;
    CHECK(subleaf0::ebx::l2_cache::is_enabled(subleaf0::ebx::l2_cache::mask));
    g_ebx_cpuid[addr] = 0x0;
    CHECK(subleaf0::ebx::l2_cache::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_allocation_enumeration_subleaf0_ebx_mem_bandwidth")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::allocation_enumeration;

    g_ebx_cpuid[addr] = subleaf0::ebx::mem_bandwidth::mask;
    CHECK(subleaf0::ebx::mem_bandwidth::is_enabled());
    g_ebx_cpuid[addr] = 0x0;
    CHECK(subleaf0::ebx::mem_bandwidth::is_disabled());

    g_ebx_cpuid[addr] = subleaf0::ebx::mem_bandwidth::mask;
    CHECK(subleaf0::ebx::mem_bandwidth::is_enabled(subleaf0::ebx::mem_bandwidth::mask));
    g_ebx_cpuid[addr] = 0x0;
    CHECK(subleaf0::ebx::mem_bandwidth::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_allocation_enumeration_subleaf1_eax")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::allocation_enumeration;

    g_eax_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(subleaf1::eax::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_allocation_enumeration_subleaf1_eax_mask_length")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::allocation_enumeration;

    g_eax_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(subleaf1::eax::mask_length::get() ==
          (subleaf1::eax::mask_length::mask >> subleaf1::eax::mask_length::from));
    CHECK(subleaf1::eax::mask_length::get(subleaf1::eax::mask_length::mask) ==
          (subleaf1::eax::mask_length::mask >> subleaf1::eax::mask_length::from));
}

TEST_CASE("intrinsics: cpuid_allocation_enumeration_subleaf1_ebx")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::allocation_enumeration;

    g_ebx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(subleaf1::ebx::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_allocation_enumeration_subleaf1_ebx_map")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::allocation_enumeration;

    g_ebx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(subleaf1::ebx::map::get() ==
          (subleaf1::ebx::map::mask >> subleaf1::ebx::map::from));
    CHECK(subleaf1::ebx::map::get(subleaf1::ebx::map::mask) ==
          (subleaf1::ebx::map::mask >> subleaf1::ebx::map::from));
}

TEST_CASE("intrinsics: cpuid_allocation_enumeration_subleaf1_ecx")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::allocation_enumeration;

    g_ecx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(subleaf1::ecx::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_allocation_enumeration_subleaf1_ecx_data_prio")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::allocation_enumeration;

    g_ecx_cpuid[addr] = subleaf1::ecx::data_prio::mask;
    CHECK(subleaf1::ecx::data_prio::is_enabled());
    g_ecx_cpuid[addr] = 0x0;
    CHECK(subleaf1::ecx::data_prio::is_disabled());

    g_ecx_cpuid[addr] = subleaf1::ecx::data_prio::mask;
    CHECK(subleaf1::ecx::data_prio::is_enabled(subleaf1::ecx::data_prio::mask));
    g_ecx_cpuid[addr] = 0x0;
    CHECK(subleaf1::ecx::data_prio::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_allocation_enumeration_subleaf1_edx")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::allocation_enumeration;

    g_edx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(subleaf1::edx::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_allocation_enumeration_subleaf1_edx_max_cos")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::allocation_enumeration;

    g_edx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(subleaf1::edx::max_cos::get() ==
          (subleaf1::edx::max_cos::mask >> subleaf1::edx::max_cos::from));
    CHECK(subleaf1::edx::max_cos::get(subleaf1::edx::max_cos::mask) ==
          (subleaf1::edx::max_cos::mask >> subleaf1::edx::max_cos::from));
}

TEST_CASE("intrinsics: cpuid_allocation_enumeration_subleaf2_eax")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::allocation_enumeration;

    g_eax_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(subleaf2::eax::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_allocation_enumeration_subleaf2_eax_mask_length")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::allocation_enumeration;

    g_eax_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(subleaf2::eax::mask_length::get() ==
          (subleaf2::eax::mask_length::mask >> subleaf2::eax::mask_length::from));
    CHECK(subleaf2::eax::mask_length::get(subleaf2::eax::mask_length::mask) ==
          (subleaf2::eax::mask_length::mask >> subleaf2::eax::mask_length::from));
}

TEST_CASE("intrinsics: cpuid_allocation_enumeration_subleaf2_ebx")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::allocation_enumeration;

    g_ebx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(subleaf2::ebx::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_allocation_enumeration_subleaf2_ebx_map")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::allocation_enumeration;

    g_ebx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(subleaf2::ebx::map::get() ==
          (subleaf2::ebx::map::mask >> subleaf2::ebx::map::from));
    CHECK(subleaf2::ebx::map::get(subleaf2::ebx::map::mask) ==
          (subleaf2::ebx::map::mask >> subleaf2::ebx::map::from));
}

TEST_CASE("intrinsics: cpuid_allocation_enumeration_subleaf2_edx")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::allocation_enumeration;

    g_edx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(subleaf2::edx::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_allocation_enumeration_subleaf2_edx_max_cos")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::allocation_enumeration;

    g_edx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(subleaf2::edx::max_cos::get() ==
          (subleaf2::edx::max_cos::mask >> subleaf2::edx::max_cos::from));
    CHECK(subleaf2::edx::max_cos::get(subleaf2::edx::max_cos::mask) ==
          (subleaf2::edx::max_cos::mask >> subleaf2::edx::max_cos::from));
}

TEST_CASE("intrinsics: cpuid_allocation_enumeration_subleaf3_eax")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::allocation_enumeration;

    g_eax_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(subleaf3::eax::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_allocation_enumeration_subleaf3_eax_max_throttle")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::allocation_enumeration;

    g_eax_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(subleaf3::eax::max_throttle::get() ==
          (subleaf3::eax::max_throttle::mask >> subleaf3::eax::max_throttle::from));
    CHECK(subleaf3::eax::max_throttle::get(subleaf3::eax::max_throttle::mask) ==
          (subleaf3::eax::max_throttle::mask >> subleaf3::eax::max_throttle::from));
}

TEST_CASE("intrinsics: cpuid_allocation_enumeration_subleaf3_ecx")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::allocation_enumeration;

    g_ecx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(subleaf3::ecx::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_allocation_enumeration_subleaf3_ecx_linear")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::allocation_enumeration;

    g_ecx_cpuid[addr] = subleaf3::ecx::linear::mask;
    CHECK(subleaf3::ecx::linear::is_enabled());
    g_ecx_cpuid[addr] = 0x0;
    CHECK(subleaf3::ecx::linear::is_disabled());

    g_ecx_cpuid[addr] = subleaf3::ecx::linear::mask;
    CHECK(subleaf3::ecx::linear::is_enabled(subleaf3::ecx::linear::mask));
    g_ecx_cpuid[addr] = 0x0;
    CHECK(subleaf3::ecx::linear::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_allocation_enumeration_subleaf3_edx")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::allocation_enumeration;

    g_edx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(subleaf3::edx::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_allocation_enumeration_subleaf3_edx_max_cos")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::allocation_enumeration;

    g_edx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(subleaf3::edx::max_cos::get() ==
          (subleaf3::edx::max_cos::mask >> subleaf3::edx::max_cos::from));
    CHECK(subleaf3::edx::max_cos::get(subleaf3::edx::max_cos::mask) ==
          (subleaf3::edx::max_cos::mask >> subleaf3::edx::max_cos::from));
}

TEST_CASE("intrinsics: cpuid_intel_sgx")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::intel_sgx;

    dump(0);
}

TEST_CASE("intrinsics: cpuid_intel_sgx_subleaf0_eax")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::intel_sgx;

    g_eax_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(subleaf0::eax::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_intel_sgx_subleaf0_eax_sgx1")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::intel_sgx;

    g_eax_cpuid[addr] = subleaf0::eax::sgx1::mask;
    CHECK(subleaf0::eax::sgx1::is_enabled());
    g_eax_cpuid[addr] = 0x0;
    CHECK(subleaf0::eax::sgx1::is_disabled());

    g_eax_cpuid[addr] = subleaf0::eax::sgx1::mask;
    CHECK(subleaf0::eax::sgx1::is_enabled(subleaf0::eax::sgx1::mask));
    g_eax_cpuid[addr] = 0x0;
    CHECK(subleaf0::eax::sgx1::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_intel_sgx_subleaf0_eax_sgx2")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::intel_sgx;

    g_eax_cpuid[addr] = subleaf0::eax::sgx2::mask;
    CHECK(subleaf0::eax::sgx2::is_enabled());
    g_eax_cpuid[addr] = 0x0;
    CHECK(subleaf0::eax::sgx2::is_disabled());

    g_eax_cpuid[addr] = subleaf0::eax::sgx2::mask;
    CHECK(subleaf0::eax::sgx2::is_enabled(subleaf0::eax::sgx2::mask));
    g_eax_cpuid[addr] = 0x0;
    CHECK(subleaf0::eax::sgx2::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_intel_sgx_subleaf0_ebx")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::intel_sgx;

    g_ebx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(subleaf0::ebx::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_intel_sgx_subleaf0_ebx_miscselect")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::intel_sgx;

    g_ebx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(subleaf0::ebx::miscselect::get() ==
          (subleaf0::ebx::miscselect::mask >> subleaf0::ebx::miscselect::from));
    CHECK(subleaf0::ebx::miscselect::get(subleaf0::ebx::miscselect::mask) ==
          (subleaf0::ebx::miscselect::mask >> subleaf0::ebx::miscselect::from));
}

TEST_CASE("intrinsics: cpuid_intel_sgx_subleaf0_edx")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::intel_sgx;

    g_edx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(subleaf0::edx::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_intel_sgx_subleaf0_edx_mes_not64")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::intel_sgx;

    g_edx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(subleaf0::edx::mes_not64::get() ==
          (subleaf0::edx::mes_not64::mask >> subleaf0::edx::mes_not64::from));
    CHECK(subleaf0::edx::mes_not64::get(subleaf0::edx::mes_not64::mask) ==
          (subleaf0::edx::mes_not64::mask >> subleaf0::edx::mes_not64::from));
}

TEST_CASE("intrinsics: cpuid_intel_sgx_subleaf0_edx_mes_64")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::intel_sgx;

    g_edx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(subleaf0::edx::mes_64::get() ==
          (subleaf0::edx::mes_64::mask >> subleaf0::edx::mes_64::from));
    CHECK(subleaf0::edx::mes_64::get(subleaf0::edx::mes_64::mask) ==
          (subleaf0::edx::mes_64::mask >> subleaf0::edx::mes_64::from));
}

TEST_CASE("intrinsics: cpuid_intel_sgx_subleaf1_eax")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::intel_sgx;

    g_eax_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(subleaf1::eax::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_intel_sgx_subleaf1_ebx")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::intel_sgx;

    g_ebx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(subleaf1::ebx::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_intel_sgx_subleaf1_ecx")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::intel_sgx;

    g_ecx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(subleaf1::ecx::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_intel_sgx_subleaf1_edx")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::intel_sgx;

    g_edx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(subleaf1::edx::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_intel_sgx_subleaf2_eax")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::intel_sgx;

    g_eax_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(subleaf2::eax::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_intel_sgx_subleaf2_eax_subleaf_type")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::intel_sgx;

    g_eax_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(subleaf2::eax::subleaf_type::get() ==
          (subleaf2::eax::subleaf_type::mask >> subleaf2::eax::subleaf_type::from));
    CHECK(subleaf2::eax::subleaf_type::get(subleaf2::eax::subleaf_type::mask) ==
          (subleaf2::eax::subleaf_type::mask >> subleaf2::eax::subleaf_type::from));
}

TEST_CASE("intrinsics: cpuid_intel_sgx_subleaf2_eax_address")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::intel_sgx;

    g_eax_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(subleaf2::eax::address::get() ==
          (subleaf2::eax::address::mask >> subleaf2::eax::address::from));
    CHECK(subleaf2::eax::address::get(subleaf2::eax::address::mask) ==
          (subleaf2::eax::address::mask >> subleaf2::eax::address::from));
}

TEST_CASE("intrinsics: cpuid_intel_sgx_subleaf2_ebx")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::intel_sgx;

    g_ebx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(subleaf2::ebx::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_intel_sgx_subleaf2_ebx_address")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::intel_sgx;

    g_ebx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(subleaf2::ebx::address::get() ==
          (subleaf2::ebx::address::mask >> subleaf2::ebx::address::from));
    CHECK(subleaf2::ebx::address::get(subleaf2::ebx::address::mask) ==
          (subleaf2::ebx::address::mask >> subleaf2::ebx::address::from));
}

TEST_CASE("intrinsics: cpuid_intel_sgx_subleaf2_ecx")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::intel_sgx;

    g_ecx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(subleaf2::ecx::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_intel_sgx_subleaf2_ecx_epc_property")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::intel_sgx;

    g_ecx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(subleaf2::ecx::epc_property::get() ==
          (subleaf2::ecx::epc_property::mask >> subleaf2::ecx::epc_property::from));
    CHECK(subleaf2::ecx::epc_property::get(subleaf2::ecx::epc_property::mask) ==
          (subleaf2::ecx::epc_property::mask >> subleaf2::ecx::epc_property::from));
}

TEST_CASE("intrinsics: cpuid_intel_sgx_subleaf2_ecx_epc_size")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::intel_sgx;

    g_ecx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(subleaf2::ecx::epc_size::get() ==
          (subleaf2::ecx::epc_size::mask >> subleaf2::ecx::epc_size::from));
    CHECK(subleaf2::ecx::epc_size::get(subleaf2::ecx::epc_size::mask) ==
          (subleaf2::ecx::epc_size::mask >> subleaf2::ecx::epc_size::from));
}

TEST_CASE("intrinsics: cpuid_intel_sgx_subleaf2_edx")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::intel_sgx;

    g_edx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(subleaf2::edx::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_intel_sgx_subleaf2_edx_epc_size")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::intel_sgx;

    g_edx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(subleaf2::edx::epc_size::get() ==
          (subleaf2::edx::epc_size::mask >> subleaf2::edx::epc_size::from));
    CHECK(subleaf2::edx::epc_size::get(subleaf2::edx::epc_size::mask) ==
          (subleaf2::edx::epc_size::mask >> subleaf2::edx::epc_size::from));
}

TEST_CASE("intrinsics: cpuid_trace_enumeration")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::trace_enumeration;

    dump(0);
}

TEST_CASE("intrinsics: cpuid_trace_enumeration_mainleaf_eax")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::trace_enumeration;

    g_eax_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(mainleaf::eax::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_trace_enumeration_mainleaf_eax_max_subleaf")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::trace_enumeration;

    g_eax_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(mainleaf::eax::max_subleaf::get() ==
          (mainleaf::eax::max_subleaf::mask >> mainleaf::eax::max_subleaf::from));
    CHECK(mainleaf::eax::max_subleaf::get(mainleaf::eax::max_subleaf::mask) ==
          (mainleaf::eax::max_subleaf::mask >> mainleaf::eax::max_subleaf::from));
}

TEST_CASE("intrinsics: cpuid_trace_enumeration_mainleaf_ebx")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::trace_enumeration;

    g_ebx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(mainleaf::ebx::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_trace_enumeration_mainleaf_ebx_ia32_rtit_ctlcr3filter")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::trace_enumeration;

    g_ebx_cpuid[addr] = mainleaf::ebx::ia32_rtit_ctlcr3filter::mask;
    CHECK(mainleaf::ebx::ia32_rtit_ctlcr3filter::is_enabled());
    g_ebx_cpuid[addr] = 0x0;
    CHECK(mainleaf::ebx::ia32_rtit_ctlcr3filter::is_disabled());

    g_ebx_cpuid[addr] = mainleaf::ebx::ia32_rtit_ctlcr3filter::mask;
    CHECK(mainleaf::ebx::ia32_rtit_ctlcr3filter::is_enabled(mainleaf::ebx::ia32_rtit_ctlcr3filter::mask));
    g_ebx_cpuid[addr] = 0x0;
    CHECK(mainleaf::ebx::ia32_rtit_ctlcr3filter::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_trace_enumeration_mainleaf_ebx_configurable_psb")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::trace_enumeration;

    g_ebx_cpuid[addr] = mainleaf::ebx::configurable_psb::mask;
    CHECK(mainleaf::ebx::configurable_psb::is_enabled());
    g_ebx_cpuid[addr] = 0x0;
    CHECK(mainleaf::ebx::configurable_psb::is_disabled());

    g_ebx_cpuid[addr] = mainleaf::ebx::configurable_psb::mask;
    CHECK(mainleaf::ebx::configurable_psb::is_enabled(mainleaf::ebx::configurable_psb::mask));
    g_ebx_cpuid[addr] = 0x0;
    CHECK(mainleaf::ebx::configurable_psb::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_trace_enumeration_mainleaf_ebx_ip_filtering")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::trace_enumeration;

    g_ebx_cpuid[addr] = mainleaf::ebx::ip_filtering::mask;
    CHECK(mainleaf::ebx::ip_filtering::is_enabled());
    g_ebx_cpuid[addr] = 0x0;
    CHECK(mainleaf::ebx::ip_filtering::is_disabled());

    g_ebx_cpuid[addr] = mainleaf::ebx::ip_filtering::mask;
    CHECK(mainleaf::ebx::ip_filtering::is_enabled(mainleaf::ebx::ip_filtering::mask));
    g_ebx_cpuid[addr] = 0x0;
    CHECK(mainleaf::ebx::ip_filtering::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_trace_enumeration_mainleaf_ebx_mtc_timing_packet")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::trace_enumeration;

    g_ebx_cpuid[addr] = mainleaf::ebx::mtc_timing_packet::mask;
    CHECK(mainleaf::ebx::mtc_timing_packet::is_enabled());
    g_ebx_cpuid[addr] = 0x0;
    CHECK(mainleaf::ebx::mtc_timing_packet::is_disabled());

    g_ebx_cpuid[addr] = mainleaf::ebx::mtc_timing_packet::mask;
    CHECK(mainleaf::ebx::mtc_timing_packet::is_enabled(mainleaf::ebx::mtc_timing_packet::mask));
    g_ebx_cpuid[addr] = 0x0;
    CHECK(mainleaf::ebx::mtc_timing_packet::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_trace_enumeration_mainleaf_ebx_ptwrite")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::trace_enumeration;

    g_ebx_cpuid[addr] = mainleaf::ebx::ptwrite::mask;
    CHECK(mainleaf::ebx::ptwrite::is_enabled());
    g_ebx_cpuid[addr] = 0x0;
    CHECK(mainleaf::ebx::ptwrite::is_disabled());

    g_ebx_cpuid[addr] = mainleaf::ebx::ptwrite::mask;
    CHECK(mainleaf::ebx::ptwrite::is_enabled(mainleaf::ebx::ptwrite::mask));
    g_ebx_cpuid[addr] = 0x0;
    CHECK(mainleaf::ebx::ptwrite::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_trace_enumeration_mainleaf_ebx_power_event_trace")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::trace_enumeration;

    g_ebx_cpuid[addr] = mainleaf::ebx::power_event_trace::mask;
    CHECK(mainleaf::ebx::power_event_trace::is_enabled());
    g_ebx_cpuid[addr] = 0x0;
    CHECK(mainleaf::ebx::power_event_trace::is_disabled());

    g_ebx_cpuid[addr] = mainleaf::ebx::power_event_trace::mask;
    CHECK(mainleaf::ebx::power_event_trace::is_enabled(mainleaf::ebx::power_event_trace::mask));
    g_ebx_cpuid[addr] = 0x0;
    CHECK(mainleaf::ebx::power_event_trace::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_trace_enumeration_mainleaf_ecx")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::trace_enumeration;

    g_ecx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(mainleaf::ecx::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_trace_enumeration_mainleaf_ecx_trading_enabled")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::trace_enumeration;

    g_ecx_cpuid[addr] = mainleaf::ecx::trading_enabled::mask;
    CHECK(mainleaf::ecx::trading_enabled::is_enabled());
    g_ecx_cpuid[addr] = 0x0;
    CHECK(mainleaf::ecx::trading_enabled::is_disabled());

    g_ecx_cpuid[addr] = mainleaf::ecx::trading_enabled::mask;
    CHECK(mainleaf::ecx::trading_enabled::is_enabled(mainleaf::ecx::trading_enabled::mask));
    g_ecx_cpuid[addr] = 0x0;
    CHECK(mainleaf::ecx::trading_enabled::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_trace_enumeration_mainleaf_ecx_topa_entry")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::trace_enumeration;

    g_ecx_cpuid[addr] = mainleaf::ecx::topa_entry::mask;
    CHECK(mainleaf::ecx::topa_entry::is_enabled());
    g_ecx_cpuid[addr] = 0x0;
    CHECK(mainleaf::ecx::topa_entry::is_disabled());

    g_ecx_cpuid[addr] = mainleaf::ecx::topa_entry::mask;
    CHECK(mainleaf::ecx::topa_entry::is_enabled(mainleaf::ecx::topa_entry::mask));
    g_ecx_cpuid[addr] = 0x0;
    CHECK(mainleaf::ecx::topa_entry::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_trace_enumeration_mainleaf_ecx_single_range_output")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::trace_enumeration;

    g_ecx_cpuid[addr] = mainleaf::ecx::single_range_output::mask;
    CHECK(mainleaf::ecx::single_range_output::is_enabled());
    g_ecx_cpuid[addr] = 0x0;
    CHECK(mainleaf::ecx::single_range_output::is_disabled());

    g_ecx_cpuid[addr] = mainleaf::ecx::single_range_output::mask;
    CHECK(mainleaf::ecx::single_range_output::is_enabled(mainleaf::ecx::single_range_output::mask));
    g_ecx_cpuid[addr] = 0x0;
    CHECK(mainleaf::ecx::single_range_output::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_trace_enumeration_mainleaf_ecx_trace_transport")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::trace_enumeration;

    g_ecx_cpuid[addr] = mainleaf::ecx::trace_transport::mask;
    CHECK(mainleaf::ecx::trace_transport::is_enabled());
    g_ecx_cpuid[addr] = 0x0;
    CHECK(mainleaf::ecx::trace_transport::is_disabled());

    g_ecx_cpuid[addr] = mainleaf::ecx::trace_transport::mask;
    CHECK(mainleaf::ecx::trace_transport::is_enabled(mainleaf::ecx::trace_transport::mask));
    g_ecx_cpuid[addr] = 0x0;
    CHECK(mainleaf::ecx::trace_transport::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_trace_enumeration_mainleaf_ecx_lip_values")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::trace_enumeration;

    g_ecx_cpuid[addr] = mainleaf::ecx::lip_values::mask;
    CHECK(mainleaf::ecx::lip_values::is_enabled());
    g_ecx_cpuid[addr] = 0x0;
    CHECK(mainleaf::ecx::lip_values::is_disabled());

    g_ecx_cpuid[addr] = mainleaf::ecx::lip_values::mask;
    CHECK(mainleaf::ecx::lip_values::is_enabled(mainleaf::ecx::lip_values::mask));
    g_ecx_cpuid[addr] = 0x0;
    CHECK(mainleaf::ecx::lip_values::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_trace_enumeration_subleaf1_eax")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::trace_enumeration;

    g_eax_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(subleaf1::eax::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_trace_enumeration_subleaf1_eax_num_address_ranges")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::trace_enumeration;

    g_eax_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(subleaf1::eax::num_address_ranges::get() ==
          (subleaf1::eax::num_address_ranges::mask >> subleaf1::eax::num_address_ranges::from));
    CHECK(subleaf1::eax::num_address_ranges::get(subleaf1::eax::num_address_ranges::mask) ==
          (subleaf1::eax::num_address_ranges::mask >> subleaf1::eax::num_address_ranges::from));
}

TEST_CASE("intrinsics: cpuid_trace_enumeration_subleaf1_eax_bitmap_mtc")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::trace_enumeration;

    g_eax_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(subleaf1::eax::bitmap_mtc::get() ==
          (subleaf1::eax::bitmap_mtc::mask >> subleaf1::eax::bitmap_mtc::from));
    CHECK(subleaf1::eax::bitmap_mtc::get(subleaf1::eax::bitmap_mtc::mask) ==
          (subleaf1::eax::bitmap_mtc::mask >> subleaf1::eax::bitmap_mtc::from));
}

TEST_CASE("intrinsics: cpuid_trace_enumeration_subleaf1_ebx")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::trace_enumeration;

    g_ebx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(subleaf1::ebx::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_trace_enumeration_subleaf1_ebx_bitmap_cycle_threshold")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::trace_enumeration;

    g_ebx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(subleaf1::ebx::bitmap_cycle_threshold::get() ==
          (subleaf1::ebx::bitmap_cycle_threshold::mask >> subleaf1::ebx::bitmap_cycle_threshold::from));
    CHECK(subleaf1::ebx::bitmap_cycle_threshold::get(subleaf1::ebx::bitmap_cycle_threshold::mask) ==
          (subleaf1::ebx::bitmap_cycle_threshold::mask >> subleaf1::ebx::bitmap_cycle_threshold::from));
}

TEST_CASE("intrinsics: cpuid_trace_enumeration_subleaf1_eax_bitmap_psb")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::trace_enumeration;

    g_ebx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(subleaf1::ebx::bitmap_psb::get() ==
          (subleaf1::ebx::bitmap_psb::mask >> subleaf1::ebx::bitmap_psb::from));
    CHECK(subleaf1::ebx::bitmap_psb::get(subleaf1::ebx::bitmap_psb::mask) ==
          (subleaf1::ebx::bitmap_psb::mask >> subleaf1::ebx::bitmap_psb::from));
}

TEST_CASE("intrinsics: cpuid_time_stamp_count")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::time_stamp_count;

    dump(0);
}

TEST_CASE("intrinsics: cpuid_time_stamp_count_eax")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::time_stamp_count;

    g_eax_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(eax::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_time_stamp_count_ebx")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::time_stamp_count;

    g_ebx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(ebx::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_time_stamp_count_ecx")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::time_stamp_count;

    g_ecx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(ecx::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_processor_freq")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::processor_freq;

    dump(0);
}

TEST_CASE("intrinsics: cpuid_processor_freq_eax")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::processor_freq;

    g_eax_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(eax::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_processor_freq_ebx")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::processor_freq;

    g_ebx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(ebx::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_processor_freq_ecx")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::processor_freq;

    g_ecx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(ecx::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_vendor_attribute")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::vendor_attribute;

    dump(0);
}

TEST_CASE("intrinsics: cpuid_vendor_attribute_mainleaf_eax")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::vendor_attribute;

    g_eax_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(mainleaf::eax::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_vendor_attribute_mainleaf_eax_max_socid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::vendor_attribute;

    g_eax_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(mainleaf::eax::max_socid::get() ==
          (mainleaf::eax::max_socid::mask >> mainleaf::eax::max_socid::from));
    CHECK(mainleaf::eax::max_socid::get(mainleaf::eax::max_socid::mask) ==
          (mainleaf::eax::max_socid::mask >> mainleaf::eax::max_socid::from));
}

TEST_CASE("intrinsics: cpuid_vendor_attribute_mainleaf_ebx")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::vendor_attribute;

    g_ebx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(mainleaf::ebx::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_vendor_attribute_mainleaf_ebx_soc_vendor")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::vendor_attribute;

    g_ebx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(mainleaf::ebx::soc_vendor::get() ==
          (mainleaf::ebx::soc_vendor::mask >> mainleaf::ebx::soc_vendor::from));
    CHECK(mainleaf::ebx::soc_vendor::get(mainleaf::ebx::soc_vendor::mask) ==
          (mainleaf::ebx::soc_vendor::mask >> mainleaf::ebx::soc_vendor::from));
}

TEST_CASE("intrinsics: cpuid_vendor_attribute_mainleaf_ebx_is_vendor_scheme")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::vendor_attribute;

    g_ebx_cpuid[addr] = mainleaf::ebx::is_vendor_scheme::mask;
    CHECK(mainleaf::ebx::is_vendor_scheme::is_enabled());
    g_ebx_cpuid[addr] = 0x0;
    CHECK(mainleaf::ebx::is_vendor_scheme::is_disabled());

    g_ebx_cpuid[addr] = mainleaf::ebx::is_vendor_scheme::mask;
    CHECK(mainleaf::ebx::is_vendor_scheme::is_enabled(mainleaf::ebx::is_vendor_scheme::mask));
    g_ebx_cpuid[addr] = 0x0;
    CHECK(mainleaf::ebx::is_vendor_scheme::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_vendor_attribute_mainleaf_ecx")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::vendor_attribute;

    g_ecx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(mainleaf::ecx::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_vendor_attribute_mainleaf_ecx_project_id")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::vendor_attribute;

    g_ecx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(mainleaf::ecx::project_id::get() ==
          (mainleaf::ecx::project_id::mask >> mainleaf::ecx::project_id::from));
    CHECK(mainleaf::ecx::project_id::get(mainleaf::ecx::project_id::mask) ==
          (mainleaf::ecx::project_id::mask >> mainleaf::ecx::project_id::from));
}

TEST_CASE("intrinsics: cpuid_vendor_attribute_mainleaf_edx")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::vendor_attribute;

    g_edx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(mainleaf::edx::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_vendor_attribute_mainleaf_edx_stepping_id")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::vendor_attribute;

    g_edx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(mainleaf::edx::stepping_id::get() ==
          (mainleaf::edx::stepping_id::mask >> mainleaf::edx::stepping_id::from));
    CHECK(mainleaf::edx::stepping_id::get(mainleaf::edx::stepping_id::mask) ==
          (mainleaf::edx::stepping_id::mask >> mainleaf::edx::stepping_id::from));
}

TEST_CASE("intrinsics: cpuid_vendor_attribute_subleaf1_eax")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::vendor_attribute;

    g_eax_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(subleaf1::eax::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_vendor_attribute_subleaf1_ebx")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::vendor_attribute;

    g_ebx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(subleaf1::ebx::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_vendor_attribute_subleaf1_ecx")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::vendor_attribute;

    g_ecx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(subleaf1::ecx::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_vendor_attribute_subleaf1_edx")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::vendor_attribute;

    g_edx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(subleaf1::edx::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_ext_feature_info")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::ext_feature_info;

    dump(0);
}

TEST_CASE("intrinsics: cpuid_ext_feature_info_ecx")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::ext_feature_info;

    g_ecx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(ecx::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_ext_feature_info_ecx_lahf_sahf")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::ext_feature_info;

    g_ecx_cpuid[addr] = ecx::lahf_sahf::mask;
    CHECK(ecx::lahf_sahf::is_enabled());
    g_ecx_cpuid[addr] = 0x0;
    CHECK(ecx::lahf_sahf::is_disabled());

    g_ecx_cpuid[addr] = ecx::lahf_sahf::mask;
    CHECK(ecx::lahf_sahf::is_enabled(ecx::lahf_sahf::mask));
    g_ecx_cpuid[addr] = 0x0;
    CHECK(ecx::lahf_sahf::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_ext_feature_info_ecx_lzcnt")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::ext_feature_info;

    g_ecx_cpuid[addr] = ecx::lzcnt::mask;
    CHECK(ecx::lzcnt::is_enabled());
    g_ecx_cpuid[addr] = 0x0;
    CHECK(ecx::lzcnt::is_disabled());

    g_ecx_cpuid[addr] = ecx::lzcnt::mask;
    CHECK(ecx::lzcnt::is_enabled(ecx::lzcnt::mask));
    g_ecx_cpuid[addr] = 0x0;
    CHECK(ecx::lzcnt::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_ext_feature_info_ecx_prefetchw")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::ext_feature_info;

    g_ecx_cpuid[addr] = ecx::prefetchw::mask;
    CHECK(ecx::prefetchw::is_enabled());
    g_ecx_cpuid[addr] = 0x0;
    CHECK(ecx::prefetchw::is_disabled());

    g_ecx_cpuid[addr] = ecx::prefetchw::mask;
    CHECK(ecx::prefetchw::is_enabled(ecx::prefetchw::mask));
    g_ecx_cpuid[addr] = 0x0;
    CHECK(ecx::prefetchw::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_ext_feature_info_edx")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::ext_feature_info;

    g_edx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(edx::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_ext_feature_info_edx_syscall_sysret")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::ext_feature_info;

    g_edx_cpuid[addr] = edx::syscall_sysret::mask;
    CHECK(edx::syscall_sysret::is_enabled());
    g_edx_cpuid[addr] = 0x0;
    CHECK(edx::syscall_sysret::is_disabled());

    g_edx_cpuid[addr] = edx::syscall_sysret::mask;
    CHECK(edx::syscall_sysret::is_enabled(edx::syscall_sysret::mask));
    g_edx_cpuid[addr] = 0x0;
    CHECK(edx::syscall_sysret::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_ext_feature_info_edx_execute_disable_bit")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::ext_feature_info;

    g_edx_cpuid[addr] = edx::execute_disable_bit::mask;
    CHECK(edx::execute_disable_bit::is_enabled());
    g_edx_cpuid[addr] = 0x0;
    CHECK(edx::execute_disable_bit::is_disabled());

    g_edx_cpuid[addr] = edx::execute_disable_bit::mask;
    CHECK(edx::execute_disable_bit::is_enabled(edx::execute_disable_bit::mask));
    g_edx_cpuid[addr] = 0x0;
    CHECK(edx::execute_disable_bit::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_ext_feature_info_edx_pages_avail")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::ext_feature_info;

    g_edx_cpuid[addr] = edx::pages_avail::mask;
    CHECK(edx::pages_avail::is_enabled());
    g_edx_cpuid[addr] = 0x0;
    CHECK(edx::pages_avail::is_disabled());

    g_edx_cpuid[addr] = edx::pages_avail::mask;
    CHECK(edx::pages_avail::is_enabled(edx::pages_avail::mask));
    g_edx_cpuid[addr] = 0x0;
    CHECK(edx::pages_avail::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_ext_feature_info_edx_rdtscp")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::ext_feature_info;

    g_edx_cpuid[addr] = edx::rdtscp::mask;
    CHECK(edx::rdtscp::is_enabled());
    g_edx_cpuid[addr] = 0x0;
    CHECK(edx::rdtscp::is_disabled());

    g_edx_cpuid[addr] = edx::rdtscp::mask;
    CHECK(edx::rdtscp::is_enabled(edx::rdtscp::mask));
    g_edx_cpuid[addr] = 0x0;
    CHECK(edx::rdtscp::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_ext_feature_info_edx_intel_64")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::ext_feature_info;

    g_edx_cpuid[addr] = edx::intel_64::mask;
    CHECK(edx::intel_64::is_enabled());
    g_edx_cpuid[addr] = 0x0;
    CHECK(edx::intel_64::is_disabled());

    g_edx_cpuid[addr] = edx::intel_64::mask;
    CHECK(edx::intel_64::is_enabled(edx::intel_64::mask));
    g_edx_cpuid[addr] = 0x0;
    CHECK(edx::intel_64::is_disabled(0x0));
}

TEST_CASE("intrinsics: cpuid_l2_info")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::l2_info;

    dump(0);
}

TEST_CASE("intrinsics: cpuid_l2_info_ecx")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::l2_info;

    g_ecx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(ecx::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_l2_info_ecx_line_size")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::l2_info;

    g_ecx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(ecx::line_size::get() ==
          (ecx::line_size::mask >> ecx::line_size::from));
    CHECK(ecx::line_size::get(ecx::line_size::mask) ==
          (ecx::line_size::mask >> ecx::line_size::from));
}

TEST_CASE("intrinsics: cpuid_l2_info_ecx_l2_associativity")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::l2_info;

    g_ecx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(ecx::l2_associativity::get() ==
          (ecx::l2_associativity::mask >> ecx::l2_associativity::from));
    CHECK(ecx::l2_associativity::get(ecx::l2_associativity::mask) ==
          (ecx::l2_associativity::mask >> ecx::l2_associativity::from));
}

TEST_CASE("intrinsics: cpuid_l2_info_ecx_cache_size")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::l2_info;

    g_ecx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(ecx::cache_size::get() ==
          (ecx::cache_size::mask >> ecx::cache_size::from));
    CHECK(ecx::cache_size::get(ecx::cache_size::mask) ==
          (ecx::cache_size::mask >> ecx::cache_size::from));
}

TEST_CASE("intrinsics: cpuid_invariant_tsc")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::invariant_tsc;

    dump(0);
}

TEST_CASE("intrinsics: cpuid_invariant_tsc_edx")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::invariant_tsc;

    g_edx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(edx::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_invariant_tsc_edx_available")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::invariant_tsc;

    g_edx_cpuid[addr] = edx::available::mask;
    CHECK(edx::available::is_enabled());
    g_edx_cpuid[addr] = 0x0;
    CHECK(edx::available::is_disabled());

    g_edx_cpuid[addr] = edx::available::mask;
    CHECK(edx::available::is_enabled(edx::available::mask));
    g_edx_cpuid[addr] = 0x0;
    CHECK(edx::available::is_disabled(0x0));
}

#endif
