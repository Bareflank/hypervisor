//
// Bareflank Hypervisor
// Copyright (C) 2018 Assured Information Security, Inc.
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

#include <map>
#include <arch/intel_x64/mtrr.h>

using namespace x64;
using namespace intel_x64;
using namespace mtrr;

std::map<::intel_x64::msrs::field_type, ::intel_x64::msrs::value_type> g_msrs;
std::map<::intel_x64::cpuid::field_type, ::intel_x64::cpuid::value_type> g_cpuid_edx;

extern "C" uint64_t
_read_msr(uint32_t addr) noexcept
{ return g_msrs[addr]; }

extern "C" void
_write_msr(uint32_t addr, uint64_t val) noexcept
{ g_msrs[addr] = val; }

extern "C" uint32_t
_cpuid_edx(uint32_t val) noexcept
{ return g_cpuid_edx[val]; }

TEST_CASE("mtrr::is_supported")
{
    g_cpuid_edx[::intel_x64::cpuid::feature_information::addr] = 0xFFFFFFFFULL;
    CHECK(mtrr::is_supported());

    g_cpuid_edx[intel_x64::cpuid::feature_information::addr] = 0x00ULL;
    CHECK(!mtrr::is_supported());
}

TEST_CASE("mtrr::ia32_mtrrcap")
{
    g_msrs[ia32_mtrrcap::addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(ia32_mtrrcap::get() == 0xFFFFFFFFFFFFFFFFULL);
    ia32_mtrrcap::dump(0);
}

TEST_CASE("mtrr::ia32_mtrrcap::vcnt")
{
    using namespace ::intel_x64::mtrr::ia32_mtrrcap;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFCCULL;
    CHECK(vcnt::get() == 0xCCULL);
    CHECK(vcnt::get(0xCC00ULL) == 0x0ULL);
}

TEST_CASE("mtrr::ia32_mtrrcap::fixed_support")
{
    using namespace ::intel_x64::mtrr::ia32_mtrrcap;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(fixed_support::is_enabled());
    CHECK(fixed_support::is_enabled(0xF00ULL));

    g_msrs[addr] = 0x0ULL;
    CHECK(fixed_support::is_disabled());
    CHECK(fixed_support::is_disabled(0xEFFULL));
}

TEST_CASE("mtrr::ia32_mtrrcap::wc_support")
{
    using namespace ::intel_x64::mtrr::ia32_mtrrcap;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(wc_support::is_enabled());
    CHECK(wc_support::is_enabled(0xF00ULL));

    g_msrs[addr] = 0x0ULL;
    CHECK(wc_support::is_disabled());
    CHECK(wc_support::is_disabled(0xB00ULL));
}

TEST_CASE("mtrr::ia32_mtrrcap::smrr_support")
{
    using namespace ::intel_x64::mtrr::ia32_mtrrcap;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(smrr_support::is_enabled());
    CHECK(smrr_support::is_enabled(0xF00ULL));

    g_msrs[addr] = 0x0ULL;
    CHECK(smrr_support::is_disabled());
    CHECK(smrr_support::is_disabled(0x7FFULL));
}

TEST_CASE("mtrr::ia32_mtrr_def_type")
{
    using namespace intel_x64::mtrr::ia32_mtrr_def_type;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("mtrr::ia32_mtrr_def_type::type")
{
    using namespace ::intel_x64::mtrr::ia32_mtrr_def_type;

    type::set(0xCCULL);
    CHECK(type::get() == 0xCCULL);

    auto val = 0ULL;
    val = type::set(val, 0x3ULL);
    CHECK(type::get(val) == 0x3ULL);
}

TEST_CASE("mtrr::ia32_mtrr_def_type::fe")
{
    using namespace ::intel_x64::mtrr::ia32_mtrr_def_type;

    fe::enable();
    CHECK(fe::is_enabled());

    fe::disable();
    CHECK(fe::is_disabled());

    auto val = 0ULL;
    val = fe::enable(val);
    CHECK(fe::is_enabled(val));

    val = fe::disable(val);
    CHECK(fe::is_disabled(val));
}

TEST_CASE("mtrr::ia32_mtrr_def_type::e")
{
    using namespace ::intel_x64::mtrr::ia32_mtrr_def_type;

    e::enable();
    CHECK(e::is_enabled());

    e::disable();
    CHECK(e::is_disabled());

    auto val = 0ULL;
    val = e::enable(val);
    CHECK(e::is_enabled(val));

    val = e::disable(val);
    CHECK(e::is_disabled(val));
}

TEST_CASE("mtrr::physbase0")
{
    using namespace intel_x64::mtrr::physbase0;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("mtrr::physbase0::type")
{
    using namespace ::intel_x64::mtrr::physbase0;

    type::set(::intel_x64::mtrr::uncacheable);
    CHECK(type::get() == ::intel_x64::mtrr::uncacheable);

    type::set(::intel_x64::mtrr::write_combining);
    CHECK(type::get() == ::intel_x64::mtrr::write_combining);

    type::set(::intel_x64::mtrr::write_through);
    CHECK(type::get() == ::intel_x64::mtrr::write_through);

    auto reg = 0xFFFFULL;
    reg = type::set(reg, ::intel_x64::mtrr::write_protected);
    CHECK(type::get(reg) == ::intel_x64::mtrr::write_protected);

    reg = type::set(reg, ::intel_x64::mtrr::write_back);
    CHECK(type::get(reg) == ::intel_x64::mtrr::write_back);
}

TEST_CASE("mtrr::physbase0::physbase")
{
    using namespace ::intel_x64::mtrr::physbase0;

    auto addr = 0xBEEF000ULL;
    auto base = addr >> 12ULL;

    physbase::set(base);
    CHECK(physbase::get() == base);
    CHECK(addr == (physbase::get() << 12ULL));

    auto reg = 0xFFULL;
    reg = physbase::set(reg, base);
    CHECK(physbase::get(reg) == addr >> 12ULL);
}

TEST_CASE("mtrr::physbase1")
{
    using namespace intel_x64::mtrr::physbase1;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("mtrr::physbase1::type")
{
    using namespace ::intel_x64::mtrr::physbase1;

    type::set(::intel_x64::mtrr::uncacheable);
    CHECK(type::get() == ::intel_x64::mtrr::uncacheable);

    type::set(::intel_x64::mtrr::write_combining);
    CHECK(type::get() == ::intel_x64::mtrr::write_combining);

    type::set(::intel_x64::mtrr::write_through);
    CHECK(type::get() == ::intel_x64::mtrr::write_through);

    auto reg = 0xFFFFULL;
    reg = type::set(reg, ::intel_x64::mtrr::write_protected);
    CHECK(type::get(reg) == ::intel_x64::mtrr::write_protected);

    reg = type::set(reg, ::intel_x64::mtrr::write_back);
    CHECK(type::get(reg) == ::intel_x64::mtrr::write_back);
}

TEST_CASE("mtrr::physbase1::physbase")
{
    using namespace ::intel_x64::mtrr::physbase1;

    auto addr = 0xBEEF000ULL;
    auto base = addr >> 12ULL;

    physbase::set(base);
    CHECK(physbase::get() == base);
    CHECK(addr == (physbase::get() << 12ULL));

    auto reg = 0xFFULL;
    reg = physbase::set(reg, base);
    CHECK(physbase::get(reg) == addr >> 12ULL);
}

TEST_CASE("mtrr::physbase2")
{
    using namespace intel_x64::mtrr::physbase2;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("mtrr::physbase2::type")
{
    using namespace ::intel_x64::mtrr::physbase2;

    type::set(::intel_x64::mtrr::uncacheable);
    CHECK(type::get() == ::intel_x64::mtrr::uncacheable);

    type::set(::intel_x64::mtrr::write_combining);
    CHECK(type::get() == ::intel_x64::mtrr::write_combining);

    type::set(::intel_x64::mtrr::write_through);
    CHECK(type::get() == ::intel_x64::mtrr::write_through);

    auto reg = 0xFFFFULL;
    reg = type::set(reg, ::intel_x64::mtrr::write_protected);
    CHECK(type::get(reg) == ::intel_x64::mtrr::write_protected);

    reg = type::set(reg, ::intel_x64::mtrr::write_back);
    CHECK(type::get(reg) == ::intel_x64::mtrr::write_back);
}

TEST_CASE("mtrr::physbase2::physbase")
{
    using namespace ::intel_x64::mtrr::physbase2;

    auto addr = 0xBEEF000ULL;
    auto base = addr >> 12ULL;

    physbase::set(base);
    CHECK(physbase::get() == base);
    CHECK(addr == (physbase::get() << 12ULL));

    auto reg = 0xFFULL;
    reg = physbase::set(reg, base);
    CHECK(physbase::get(reg) == addr >> 12ULL);
}

TEST_CASE("mtrr::physbase3")
{
    using namespace intel_x64::mtrr::physbase3;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("mtrr::physbase3::type")
{
    using namespace ::intel_x64::mtrr::physbase3;

    type::set(::intel_x64::mtrr::uncacheable);
    CHECK(type::get() == ::intel_x64::mtrr::uncacheable);

    type::set(::intel_x64::mtrr::write_combining);
    CHECK(type::get() == ::intel_x64::mtrr::write_combining);

    type::set(::intel_x64::mtrr::write_through);
    CHECK(type::get() == ::intel_x64::mtrr::write_through);

    auto reg = 0xFFFFULL;
    reg = type::set(reg, ::intel_x64::mtrr::write_protected);
    CHECK(type::get(reg) == ::intel_x64::mtrr::write_protected);

    reg = type::set(reg, ::intel_x64::mtrr::write_back);
    CHECK(type::get(reg) == ::intel_x64::mtrr::write_back);
}

TEST_CASE("mtrr::physbase3::physbase")
{
    using namespace ::intel_x64::mtrr::physbase3;

    auto addr = 0xBEEF000ULL;
    auto base = addr >> 12ULL;

    physbase::set(base);
    CHECK(physbase::get() == base);
    CHECK(addr == (physbase::get() << 12ULL));

    auto reg = 0xFFULL;
    reg = physbase::set(reg, base);
    CHECK(physbase::get(reg) == addr >> 12ULL);
}

TEST_CASE("mtrr::physbase4")
{
    using namespace intel_x64::mtrr::physbase4;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("mtrr::physbase4::type")
{
    using namespace ::intel_x64::mtrr::physbase4;

    type::set(::intel_x64::mtrr::uncacheable);
    CHECK(type::get() == ::intel_x64::mtrr::uncacheable);

    type::set(::intel_x64::mtrr::write_combining);
    CHECK(type::get() == ::intel_x64::mtrr::write_combining);

    type::set(::intel_x64::mtrr::write_through);
    CHECK(type::get() == ::intel_x64::mtrr::write_through);

    auto reg = 0xFFFFULL;
    reg = type::set(reg, ::intel_x64::mtrr::write_protected);
    CHECK(type::get(reg) == ::intel_x64::mtrr::write_protected);

    reg = type::set(reg, ::intel_x64::mtrr::write_back);
    CHECK(type::get(reg) == ::intel_x64::mtrr::write_back);
}

TEST_CASE("mtrr::physbase4::physbase")
{
    using namespace ::intel_x64::mtrr::physbase4;

    auto addr = 0xBEEF000ULL;
    auto base = addr >> 12ULL;

    physbase::set(base);
    CHECK(physbase::get() == base);
    CHECK(addr == (physbase::get() << 12ULL));

    auto reg = 0xFFULL;
    reg = physbase::set(reg, base);
    CHECK(physbase::get(reg) == addr >> 12ULL);
}

TEST_CASE("mtrr::physbase5")
{
    using namespace intel_x64::mtrr::physbase5;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("mtrr::physbase5::type")
{
    using namespace ::intel_x64::mtrr::physbase5;

    type::set(::intel_x64::mtrr::uncacheable);
    CHECK(type::get() == ::intel_x64::mtrr::uncacheable);

    type::set(::intel_x64::mtrr::write_combining);
    CHECK(type::get() == ::intel_x64::mtrr::write_combining);

    type::set(::intel_x64::mtrr::write_through);
    CHECK(type::get() == ::intel_x64::mtrr::write_through);

    auto reg = 0xFFFFULL;
    reg = type::set(reg, ::intel_x64::mtrr::write_protected);
    CHECK(type::get(reg) == ::intel_x64::mtrr::write_protected);

    reg = type::set(reg, ::intel_x64::mtrr::write_back);
    CHECK(type::get(reg) == ::intel_x64::mtrr::write_back);
}

TEST_CASE("mtrr::physbase5::physbase")
{
    using namespace ::intel_x64::mtrr::physbase5;

    auto addr = 0xBEEF000ULL;
    auto base = addr >> 12ULL;

    physbase::set(base);
    CHECK(physbase::get() == base);
    CHECK(addr == (physbase::get() << 12ULL));

    auto reg = 0xFFULL;
    reg = physbase::set(reg, base);
    CHECK(physbase::get(reg) == addr >> 12ULL);
}

TEST_CASE("mtrr::physbase6")
{
    using namespace intel_x64::mtrr::physbase6;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("mtrr::physbase6::type")
{
    using namespace ::intel_x64::mtrr::physbase6;

    type::set(::intel_x64::mtrr::uncacheable);
    CHECK(type::get() == ::intel_x64::mtrr::uncacheable);

    type::set(::intel_x64::mtrr::write_combining);
    CHECK(type::get() == ::intel_x64::mtrr::write_combining);

    type::set(::intel_x64::mtrr::write_through);
    CHECK(type::get() == ::intel_x64::mtrr::write_through);

    auto reg = 0xFFFFULL;
    reg = type::set(reg, ::intel_x64::mtrr::write_protected);
    CHECK(type::get(reg) == ::intel_x64::mtrr::write_protected);

    reg = type::set(reg, ::intel_x64::mtrr::write_back);
    CHECK(type::get(reg) == ::intel_x64::mtrr::write_back);
}

TEST_CASE("mtrr::physbase6::physbase")
{
    using namespace ::intel_x64::mtrr::physbase6;

    auto addr = 0xBEEF000ULL;
    auto base = addr >> 12ULL;

    physbase::set(base);
    CHECK(physbase::get() == base);
    CHECK(addr == (physbase::get() << 12ULL));

    auto reg = 0xFFULL;
    reg = physbase::set(reg, base);
    CHECK(physbase::get(reg) == addr >> 12ULL);
}

TEST_CASE("mtrr::physbase7")
{
    using namespace intel_x64::mtrr::physbase7;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("mtrr::physbase7::type")
{
    using namespace ::intel_x64::mtrr::physbase7;

    type::set(::intel_x64::mtrr::uncacheable);
    CHECK(type::get() == ::intel_x64::mtrr::uncacheable);

    type::set(::intel_x64::mtrr::write_combining);
    CHECK(type::get() == ::intel_x64::mtrr::write_combining);

    type::set(::intel_x64::mtrr::write_through);
    CHECK(type::get() == ::intel_x64::mtrr::write_through);

    auto reg = 0xFFFFULL;
    reg = type::set(reg, ::intel_x64::mtrr::write_protected);
    CHECK(type::get(reg) == ::intel_x64::mtrr::write_protected);

    reg = type::set(reg, ::intel_x64::mtrr::write_back);
    CHECK(type::get(reg) == ::intel_x64::mtrr::write_back);
}

TEST_CASE("mtrr::physbase7::physbase")
{
    using namespace ::intel_x64::mtrr::physbase7;

    auto addr = 0xBEEF000ULL;
    auto base = addr >> 12ULL;

    physbase::set(base);
    CHECK(physbase::get() == base);
    CHECK(addr == (physbase::get() << 12ULL));

    auto reg = 0xFFULL;
    reg = physbase::set(reg, base);
    CHECK(physbase::get(reg) == addr >> 12ULL);
}

TEST_CASE("mtrr::physbase8")
{
    using namespace intel_x64::mtrr::physbase8;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("mtrr::physbase8::type")
{
    using namespace ::intel_x64::mtrr::physbase8;

    type::set(::intel_x64::mtrr::uncacheable);
    CHECK(type::get() == ::intel_x64::mtrr::uncacheable);

    type::set(::intel_x64::mtrr::write_combining);
    CHECK(type::get() == ::intel_x64::mtrr::write_combining);

    type::set(::intel_x64::mtrr::write_through);
    CHECK(type::get() == ::intel_x64::mtrr::write_through);

    auto reg = 0xFFFFULL;
    reg = type::set(reg, ::intel_x64::mtrr::write_protected);
    CHECK(type::get(reg) == ::intel_x64::mtrr::write_protected);

    reg = type::set(reg, ::intel_x64::mtrr::write_back);
    CHECK(type::get(reg) == ::intel_x64::mtrr::write_back);
}

TEST_CASE("mtrr::physbase8::physbase")
{
    using namespace ::intel_x64::mtrr::physbase8;

    auto addr = 0xBEEF000ULL;
    auto base = addr >> 12ULL;

    physbase::set(base);
    CHECK(physbase::get() == base);
    CHECK(addr == (physbase::get() << 12ULL));

    auto reg = 0xFFULL;
    reg = physbase::set(reg, base);
    CHECK(physbase::get(reg) == addr >> 12ULL);
}

TEST_CASE("mtrr::physbase9")
{
    using namespace intel_x64::mtrr::physbase9;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("mtrr::physbase9::type")
{
    using namespace ::intel_x64::mtrr::physbase9;

    type::set(::intel_x64::mtrr::uncacheable);
    CHECK(type::get() == ::intel_x64::mtrr::uncacheable);

    type::set(::intel_x64::mtrr::write_combining);
    CHECK(type::get() == ::intel_x64::mtrr::write_combining);

    type::set(::intel_x64::mtrr::write_through);
    CHECK(type::get() == ::intel_x64::mtrr::write_through);

    auto reg = 0xFFFFULL;
    reg = type::set(reg, ::intel_x64::mtrr::write_protected);
    CHECK(type::get(reg) == ::intel_x64::mtrr::write_protected);

    reg = type::set(reg, ::intel_x64::mtrr::write_back);
    CHECK(type::get(reg) == ::intel_x64::mtrr::write_back);
}

TEST_CASE("mtrr::physbase9::physbase")
{
    using namespace ::intel_x64::mtrr::physbase9;

    auto addr = 0xBEEF000ULL;
    auto base = addr >> 12ULL;

    physbase::set(base);
    CHECK(physbase::get() == base);
    CHECK(addr == (physbase::get() << 12ULL));

    auto reg = 0xFFULL;
    reg = physbase::set(reg, base);
    CHECK(physbase::get(reg) == addr >> 12ULL);
}

TEST_CASE("mtrr::physmask0")
{
    using namespace intel_x64::mtrr::physmask0;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("mtrr::physmask0::valid")
{
    using namespace intel_x64::mtrr::physmask0;

    valid::enable();
    CHECK(valid::is_enabled());

    valid::disable();
    CHECK(valid::is_disabled());

    auto reg = 0ULL;
    reg = valid::enable(reg);
    CHECK(valid::is_enabled(reg));

    reg = valid::disable(reg);
    CHECK(valid::is_disabled(reg));
}

TEST_CASE("mtrr::physmask0::physmask")
{
    using namespace intel_x64::mtrr::physmask0;

    auto mask = 0xAFEBEEF000ULL;

    physmask::set(mask >> 12ULL);
    CHECK(physmask::get() == mask >> 12ULL);

    auto reg = 0xE8ULL;
    reg = physmask::set(reg, mask >> 12ULL);
    CHECK(physmask::get(reg) == mask >> 12ULL);
}

TEST_CASE("mtrr::physmask1")
{
    using namespace intel_x64::mtrr::physmask1;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("mtrr::physmask1::valid")
{
    using namespace intel_x64::mtrr::physmask1;

    valid::enable();
    CHECK(valid::is_enabled());

    valid::disable();
    CHECK(valid::is_disabled());

    auto reg = 0ULL;
    reg = valid::enable(reg);
    CHECK(valid::is_enabled(reg));

    reg = valid::disable(reg);
    CHECK(valid::is_disabled(reg));
}

TEST_CASE("mtrr::physmask1::physmask")
{
    using namespace intel_x64::mtrr::physmask1;

    auto mask = 0xAFEBEEF000ULL;

    physmask::set(mask >> 12ULL);
    CHECK(physmask::get() == mask >> 12ULL);

    auto reg = 0xE8ULL;
    reg = physmask::set(reg, mask >> 12ULL);
    CHECK(physmask::get(reg) == mask >> 12ULL);
}

TEST_CASE("mtrr::physmask2")
{
    using namespace intel_x64::mtrr::physmask2;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("mtrr::physmask2::valid")
{
    using namespace intel_x64::mtrr::physmask2;

    valid::enable();
    CHECK(valid::is_enabled());

    valid::disable();
    CHECK(valid::is_disabled());

    auto reg = 0ULL;
    reg = valid::enable(reg);
    CHECK(valid::is_enabled(reg));

    reg = valid::disable(reg);
    CHECK(valid::is_disabled(reg));
}

TEST_CASE("mtrr::physmask2::physmask")
{
    using namespace intel_x64::mtrr::physmask2;

    auto mask = 0xAFEBEEF000ULL;

    physmask::set(mask >> 12ULL);
    CHECK(physmask::get() == mask >> 12ULL);

    auto reg = 0xE8ULL;
    reg = physmask::set(reg, mask >> 12ULL);
    CHECK(physmask::get(reg) == mask >> 12ULL);
}

TEST_CASE("mtrr::physmask3")
{
    using namespace intel_x64::mtrr::physmask3;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("mtrr::physmask3::valid")
{
    using namespace intel_x64::mtrr::physmask3;

    valid::enable();
    CHECK(valid::is_enabled());

    valid::disable();
    CHECK(valid::is_disabled());

    auto reg = 0ULL;
    reg = valid::enable(reg);
    CHECK(valid::is_enabled(reg));

    reg = valid::disable(reg);
    CHECK(valid::is_disabled(reg));
}

TEST_CASE("mtrr::physmask3::physmask")
{
    using namespace intel_x64::mtrr::physmask3;

    auto mask = 0xAFEBEEF000ULL;

    physmask::set(mask >> 12ULL);
    CHECK(physmask::get() == mask >> 12ULL);

    auto reg = 0xE8ULL;
    reg = physmask::set(reg, mask >> 12ULL);
    CHECK(physmask::get(reg) == mask >> 12ULL);
}

TEST_CASE("mtrr::physmask4")
{
    using namespace intel_x64::mtrr::physmask4;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("mtrr::physmask4::valid")
{
    using namespace intel_x64::mtrr::physmask4;

    valid::enable();
    CHECK(valid::is_enabled());

    valid::disable();
    CHECK(valid::is_disabled());

    auto reg = 0ULL;
    reg = valid::enable(reg);
    CHECK(valid::is_enabled(reg));

    reg = valid::disable(reg);
    CHECK(valid::is_disabled(reg));
}

TEST_CASE("mtrr::physmask4::physmask")
{
    using namespace intel_x64::mtrr::physmask4;

    auto mask = 0xAFEBEEF000ULL;

    physmask::set(mask >> 12ULL);
    CHECK(physmask::get() == mask >> 12ULL);

    auto reg = 0xE8ULL;
    reg = physmask::set(reg, mask >> 12ULL);
    CHECK(physmask::get(reg) == mask >> 12ULL);
}

TEST_CASE("mtrr::physmask5")
{
    using namespace intel_x64::mtrr::physmask5;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("mtrr::physmask5::valid")
{
    using namespace intel_x64::mtrr::physmask5;

    valid::enable();
    CHECK(valid::is_enabled());

    valid::disable();
    CHECK(valid::is_disabled());

    auto reg = 0ULL;
    reg = valid::enable(reg);
    CHECK(valid::is_enabled(reg));

    reg = valid::disable(reg);
    CHECK(valid::is_disabled(reg));
}

TEST_CASE("mtrr::physmask5::physmask")
{
    using namespace intel_x64::mtrr::physmask5;

    auto mask = 0xAFEBEEF000ULL;

    physmask::set(mask >> 12ULL);
    CHECK(physmask::get() == mask >> 12ULL);

    auto reg = 0xE8ULL;
    reg = physmask::set(reg, mask >> 12ULL);
    CHECK(physmask::get(reg) == mask >> 12ULL);
}

TEST_CASE("mtrr::physmask6")
{
    using namespace intel_x64::mtrr::physmask6;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("mtrr::physmask6::valid")
{
    using namespace intel_x64::mtrr::physmask6;

    valid::enable();
    CHECK(valid::is_enabled());

    valid::disable();
    CHECK(valid::is_disabled());

    auto reg = 0ULL;
    reg = valid::enable(reg);
    CHECK(valid::is_enabled(reg));

    reg = valid::disable(reg);
    CHECK(valid::is_disabled(reg));
}

TEST_CASE("mtrr::physmask6::physmask")
{
    using namespace intel_x64::mtrr::physmask6;

    auto mask = 0xAFEBEEF000ULL;

    physmask::set(mask >> 12ULL);
    CHECK(physmask::get() == mask >> 12ULL);

    auto reg = 0xE8ULL;
    reg = physmask::set(reg, mask >> 12ULL);
    CHECK(physmask::get(reg) == mask >> 12ULL);
}

TEST_CASE("mtrr::physmask7")
{
    using namespace intel_x64::mtrr::physmask7;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("mtrr::physmask7::valid")
{
    using namespace intel_x64::mtrr::physmask7;

    valid::enable();
    CHECK(valid::is_enabled());

    valid::disable();
    CHECK(valid::is_disabled());

    auto reg = 0ULL;
    reg = valid::enable(reg);
    CHECK(valid::is_enabled(reg));

    reg = valid::disable(reg);
    CHECK(valid::is_disabled(reg));
}

TEST_CASE("mtrr::physmask7::physmask")
{
    using namespace intel_x64::mtrr::physmask7;

    auto mask = 0xAFEBEEF000ULL;

    physmask::set(mask >> 12ULL);
    CHECK(physmask::get() == mask >> 12ULL);

    auto reg = 0xE8ULL;
    reg = physmask::set(reg, mask >> 12ULL);
    CHECK(physmask::get(reg) == mask >> 12ULL);
}

TEST_CASE("mtrr::physmask8")
{
    using namespace intel_x64::mtrr::physmask8;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("mtrr::physmask8::valid")
{
    using namespace intel_x64::mtrr::physmask8;

    valid::enable();
    CHECK(valid::is_enabled());

    valid::disable();
    CHECK(valid::is_disabled());

    auto reg = 0ULL;
    reg = valid::enable(reg);
    CHECK(valid::is_enabled(reg));

    reg = valid::disable(reg);
    CHECK(valid::is_disabled(reg));
}

TEST_CASE("mtrr::physmask8::physmask")
{
    using namespace intel_x64::mtrr::physmask8;

    auto mask = 0xAFEBEEF000ULL;

    physmask::set(mask >> 12ULL);
    CHECK(physmask::get() == mask >> 12ULL);

    auto reg = 0xE8ULL;
    reg = physmask::set(reg, mask >> 12ULL);
    CHECK(physmask::get(reg) == mask >> 12ULL);
}

TEST_CASE("mtrr::physmask9")
{
    using namespace intel_x64::mtrr::physmask9;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("mtrr::physmask9::valid")
{
    using namespace intel_x64::mtrr::physmask9;

    valid::enable();
    CHECK(valid::is_enabled());

    valid::disable();
    CHECK(valid::is_disabled());

    auto reg = 0ULL;
    reg = valid::enable(reg);
    CHECK(valid::is_enabled(reg));

    reg = valid::disable(reg);
    CHECK(valid::is_disabled(reg));
}

TEST_CASE("mtrr::physmask9::physmask")
{
    using namespace intel_x64::mtrr::physmask9;

    auto mask = 0xAFEBEEF000ULL;

    physmask::set(mask >> 12ULL);
    CHECK(physmask::get() == mask >> 12ULL);

    auto reg = 0xE8ULL;
    reg = physmask::set(reg, mask >> 12ULL);
    CHECK(physmask::get(reg) == mask >> 12ULL);
}

TEST_CASE("mtrr::fix64k_00000")
{
    using namespace intel_x64::mtrr::fix64k_00000;

    set(0xFFFFFFFF11111111ULL);
    CHECK(get() == 0xFFFFFFFF11111111ULL);
    dump(0);

    range0::set(mtrr::uncacheable);
    range1::set(mtrr::write_combining);
    range2::set(mtrr::write_through);
    range3::set(mtrr::write_protected);
    range4::set(mtrr::write_back);
    range5::set(0xFFULL);
    range6::set(0xEEULL);
    range7::set(0xDDULL);

    CHECK(range0::get() == mtrr::uncacheable);
    CHECK(range1::get() == mtrr::write_combining);
    CHECK(range2::get() == mtrr::write_through);
    CHECK(range3::get() == mtrr::write_protected);
    CHECK(range4::get() == mtrr::write_back);
    CHECK(range5::get() == 0xFFULL);
    CHECK(range6::get() == 0xEEULL);
    CHECK(range7::get() == 0xDDULL);

    auto reg = 0x0ULL;
    reg = range0::set(reg, mtrr::uncacheable);
    reg = range1::set(reg, mtrr::write_combining);
    reg = range2::set(reg, mtrr::write_through);
    reg = range3::set(reg, mtrr::write_protected);
    reg = range4::set(reg, mtrr::write_back);
    reg = range5::set(reg, 0xFFULL);
    reg = range6::set(reg, 0xEEULL);
    reg = range7::set(reg, 0xDDULL);

    CHECK(range0::get(reg) == mtrr::uncacheable);
    CHECK(range1::get(reg) == mtrr::write_combining);
    CHECK(range2::get(reg) == mtrr::write_through);
    CHECK(range3::get(reg) == mtrr::write_protected);
    CHECK(range4::get(reg) == mtrr::write_back);
    CHECK(range5::get(reg) == 0xFFULL);
    CHECK(range6::get(reg) == 0xEEULL);
    CHECK(range7::get(reg) == 0xDDULL);
}

TEST_CASE("mtrr::fix16k_80000")
{
    using namespace intel_x64::mtrr::fix16k_80000;

    set(0xFFFFFFFF11111111ULL);
    CHECK(get() == 0xFFFFFFFF11111111ULL);
    dump(0);

    range0::set(mtrr::uncacheable);
    range1::set(mtrr::write_combining);
    range2::set(mtrr::write_through);
    range3::set(mtrr::write_protected);
    range4::set(mtrr::write_back);
    range5::set(0xFFULL);
    range6::set(0xEEULL);
    range7::set(0xDDULL);

    CHECK(range0::get() == mtrr::uncacheable);
    CHECK(range1::get() == mtrr::write_combining);
    CHECK(range2::get() == mtrr::write_through);
    CHECK(range3::get() == mtrr::write_protected);
    CHECK(range4::get() == mtrr::write_back);
    CHECK(range5::get() == 0xFFULL);
    CHECK(range6::get() == 0xEEULL);
    CHECK(range7::get() == 0xDDULL);

    auto reg = 0x0ULL;
    reg = range0::set(reg, mtrr::uncacheable);
    reg = range1::set(reg, mtrr::write_combining);
    reg = range2::set(reg, mtrr::write_through);
    reg = range3::set(reg, mtrr::write_protected);
    reg = range4::set(reg, mtrr::write_back);
    reg = range5::set(reg, 0xFFULL);
    reg = range6::set(reg, 0xEEULL);
    reg = range7::set(reg, 0xDDULL);

    CHECK(range0::get(reg) == mtrr::uncacheable);
    CHECK(range1::get(reg) == mtrr::write_combining);
    CHECK(range2::get(reg) == mtrr::write_through);
    CHECK(range3::get(reg) == mtrr::write_protected);
    CHECK(range4::get(reg) == mtrr::write_back);
    CHECK(range5::get(reg) == 0xFFULL);
    CHECK(range6::get(reg) == 0xEEULL);
    CHECK(range7::get(reg) == 0xDDULL);
}

TEST_CASE("mtrr::fix16k_A0000")
{
    using namespace intel_x64::mtrr::fix16k_A0000;

    set(0xFFFFFFFF11111111ULL);
    CHECK(get() == 0xFFFFFFFF11111111ULL);
    dump(0);

    range0::set(mtrr::uncacheable);
    range1::set(mtrr::write_combining);
    range2::set(mtrr::write_through);
    range3::set(mtrr::write_protected);
    range4::set(mtrr::write_back);
    range5::set(0xFFULL);
    range6::set(0xEEULL);
    range7::set(0xDDULL);

    CHECK(range0::get() == mtrr::uncacheable);
    CHECK(range1::get() == mtrr::write_combining);
    CHECK(range2::get() == mtrr::write_through);
    CHECK(range3::get() == mtrr::write_protected);
    CHECK(range4::get() == mtrr::write_back);
    CHECK(range5::get() == 0xFFULL);
    CHECK(range6::get() == 0xEEULL);
    CHECK(range7::get() == 0xDDULL);

    auto reg = 0x0ULL;
    reg = range0::set(reg, mtrr::uncacheable);
    reg = range1::set(reg, mtrr::write_combining);
    reg = range2::set(reg, mtrr::write_through);
    reg = range3::set(reg, mtrr::write_protected);
    reg = range4::set(reg, mtrr::write_back);
    reg = range5::set(reg, 0xFFULL);
    reg = range6::set(reg, 0xEEULL);
    reg = range7::set(reg, 0xDDULL);

    CHECK(range0::get(reg) == mtrr::uncacheable);
    CHECK(range1::get(reg) == mtrr::write_combining);
    CHECK(range2::get(reg) == mtrr::write_through);
    CHECK(range3::get(reg) == mtrr::write_protected);
    CHECK(range4::get(reg) == mtrr::write_back);
    CHECK(range5::get(reg) == 0xFFULL);
    CHECK(range6::get(reg) == 0xEEULL);
    CHECK(range7::get(reg) == 0xDDULL);
}

TEST_CASE("mtrr::fix04k_C0000")
{
    using namespace intel_x64::mtrr::fix04k_C0000;

    set(0xFFFFFFFF11111111ULL);
    CHECK(get() == 0xFFFFFFFF11111111ULL);
    dump(0);

    range0::set(mtrr::uncacheable);
    range1::set(mtrr::write_combining);
    range2::set(mtrr::write_through);
    range3::set(mtrr::write_protected);
    range4::set(mtrr::write_back);
    range5::set(0xFFULL);
    range6::set(0xEEULL);
    range7::set(0xDDULL);

    CHECK(range0::get() == mtrr::uncacheable);
    CHECK(range1::get() == mtrr::write_combining);
    CHECK(range2::get() == mtrr::write_through);
    CHECK(range3::get() == mtrr::write_protected);
    CHECK(range4::get() == mtrr::write_back);
    CHECK(range5::get() == 0xFFULL);
    CHECK(range6::get() == 0xEEULL);
    CHECK(range7::get() == 0xDDULL);

    auto reg = 0x0ULL;
    reg = range0::set(reg, mtrr::uncacheable);
    reg = range1::set(reg, mtrr::write_combining);
    reg = range2::set(reg, mtrr::write_through);
    reg = range3::set(reg, mtrr::write_protected);
    reg = range4::set(reg, mtrr::write_back);
    reg = range5::set(reg, 0xFFULL);
    reg = range6::set(reg, 0xEEULL);
    reg = range7::set(reg, 0xDDULL);

    CHECK(range0::get(reg) == mtrr::uncacheable);
    CHECK(range1::get(reg) == mtrr::write_combining);
    CHECK(range2::get(reg) == mtrr::write_through);
    CHECK(range3::get(reg) == mtrr::write_protected);
    CHECK(range4::get(reg) == mtrr::write_back);
    CHECK(range5::get(reg) == 0xFFULL);
    CHECK(range6::get(reg) == 0xEEULL);
    CHECK(range7::get(reg) == 0xDDULL);
}

TEST_CASE("mtrr::fix04k_C8000")
{
    using namespace intel_x64::mtrr::fix04k_C8000;

    set(0xFFFFFFFF11111111ULL);
    CHECK(get() == 0xFFFFFFFF11111111ULL);
    dump(0);

    range0::set(mtrr::uncacheable);
    range1::set(mtrr::write_combining);
    range2::set(mtrr::write_through);
    range3::set(mtrr::write_protected);
    range4::set(mtrr::write_back);
    range5::set(0xFFULL);
    range6::set(0xEEULL);
    range7::set(0xDDULL);

    CHECK(range0::get() == mtrr::uncacheable);
    CHECK(range1::get() == mtrr::write_combining);
    CHECK(range2::get() == mtrr::write_through);
    CHECK(range3::get() == mtrr::write_protected);
    CHECK(range4::get() == mtrr::write_back);
    CHECK(range5::get() == 0xFFULL);
    CHECK(range6::get() == 0xEEULL);
    CHECK(range7::get() == 0xDDULL);

    auto reg = 0x0ULL;
    reg = range0::set(reg, mtrr::uncacheable);
    reg = range1::set(reg, mtrr::write_combining);
    reg = range2::set(reg, mtrr::write_through);
    reg = range3::set(reg, mtrr::write_protected);
    reg = range4::set(reg, mtrr::write_back);
    reg = range5::set(reg, 0xFFULL);
    reg = range6::set(reg, 0xEEULL);
    reg = range7::set(reg, 0xDDULL);

    CHECK(range0::get(reg) == mtrr::uncacheable);
    CHECK(range1::get(reg) == mtrr::write_combining);
    CHECK(range2::get(reg) == mtrr::write_through);
    CHECK(range3::get(reg) == mtrr::write_protected);
    CHECK(range4::get(reg) == mtrr::write_back);
    CHECK(range5::get(reg) == 0xFFULL);
    CHECK(range6::get(reg) == 0xEEULL);
    CHECK(range7::get(reg) == 0xDDULL);
}

TEST_CASE("mtrr::fix04k_D0000")
{
    using namespace intel_x64::mtrr::fix04k_D0000;

    set(0xFFFFFFFF11111111ULL);
    CHECK(get() == 0xFFFFFFFF11111111ULL);
    dump(0);

    range0::set(mtrr::uncacheable);
    range1::set(mtrr::write_combining);
    range2::set(mtrr::write_through);
    range3::set(mtrr::write_protected);
    range4::set(mtrr::write_back);
    range5::set(0xFFULL);
    range6::set(0xEEULL);
    range7::set(0xDDULL);

    CHECK(range0::get() == mtrr::uncacheable);
    CHECK(range1::get() == mtrr::write_combining);
    CHECK(range2::get() == mtrr::write_through);
    CHECK(range3::get() == mtrr::write_protected);
    CHECK(range4::get() == mtrr::write_back);
    CHECK(range5::get() == 0xFFULL);
    CHECK(range6::get() == 0xEEULL);
    CHECK(range7::get() == 0xDDULL);

    auto reg = 0x0ULL;
    reg = range0::set(reg, mtrr::uncacheable);
    reg = range1::set(reg, mtrr::write_combining);
    reg = range2::set(reg, mtrr::write_through);
    reg = range3::set(reg, mtrr::write_protected);
    reg = range4::set(reg, mtrr::write_back);
    reg = range5::set(reg, 0xFFULL);
    reg = range6::set(reg, 0xEEULL);
    reg = range7::set(reg, 0xDDULL);

    CHECK(range0::get(reg) == mtrr::uncacheable);
    CHECK(range1::get(reg) == mtrr::write_combining);
    CHECK(range2::get(reg) == mtrr::write_through);
    CHECK(range3::get(reg) == mtrr::write_protected);
    CHECK(range4::get(reg) == mtrr::write_back);
    CHECK(range5::get(reg) == 0xFFULL);
    CHECK(range6::get(reg) == 0xEEULL);
    CHECK(range7::get(reg) == 0xDDULL);
}

TEST_CASE("mtrr::fix04k_D8000")
{
    using namespace intel_x64::mtrr::fix04k_D8000;

    set(0xFFFFFFFF11111111ULL);
    CHECK(get() == 0xFFFFFFFF11111111ULL);
    dump(0);

    range0::set(mtrr::uncacheable);
    range1::set(mtrr::write_combining);
    range2::set(mtrr::write_through);
    range3::set(mtrr::write_protected);
    range4::set(mtrr::write_back);
    range5::set(0xFFULL);
    range6::set(0xEEULL);
    range7::set(0xDDULL);

    CHECK(range0::get() == mtrr::uncacheable);
    CHECK(range1::get() == mtrr::write_combining);
    CHECK(range2::get() == mtrr::write_through);
    CHECK(range3::get() == mtrr::write_protected);
    CHECK(range4::get() == mtrr::write_back);
    CHECK(range5::get() == 0xFFULL);
    CHECK(range6::get() == 0xEEULL);
    CHECK(range7::get() == 0xDDULL);

    auto reg = 0x0ULL;
    reg = range0::set(reg, mtrr::uncacheable);
    reg = range1::set(reg, mtrr::write_combining);
    reg = range2::set(reg, mtrr::write_through);
    reg = range3::set(reg, mtrr::write_protected);
    reg = range4::set(reg, mtrr::write_back);
    reg = range5::set(reg, 0xFFULL);
    reg = range6::set(reg, 0xEEULL);
    reg = range7::set(reg, 0xDDULL);

    CHECK(range0::get(reg) == mtrr::uncacheable);
    CHECK(range1::get(reg) == mtrr::write_combining);
    CHECK(range2::get(reg) == mtrr::write_through);
    CHECK(range3::get(reg) == mtrr::write_protected);
    CHECK(range4::get(reg) == mtrr::write_back);
    CHECK(range5::get(reg) == 0xFFULL);
    CHECK(range6::get(reg) == 0xEEULL);
    CHECK(range7::get(reg) == 0xDDULL);
}

TEST_CASE("mtrr::fix04k_E0000")
{
    using namespace intel_x64::mtrr::fix04k_E0000;

    set(0xFFFFFFFF11111111ULL);
    CHECK(get() == 0xFFFFFFFF11111111ULL);
    dump(0);

    range0::set(mtrr::uncacheable);
    range1::set(mtrr::write_combining);
    range2::set(mtrr::write_through);
    range3::set(mtrr::write_protected);
    range4::set(mtrr::write_back);
    range5::set(0xFFULL);
    range6::set(0xEEULL);
    range7::set(0xDDULL);

    CHECK(range0::get() == mtrr::uncacheable);
    CHECK(range1::get() == mtrr::write_combining);
    CHECK(range2::get() == mtrr::write_through);
    CHECK(range3::get() == mtrr::write_protected);
    CHECK(range4::get() == mtrr::write_back);
    CHECK(range5::get() == 0xFFULL);
    CHECK(range6::get() == 0xEEULL);
    CHECK(range7::get() == 0xDDULL);

    auto reg = 0x0ULL;
    reg = range0::set(reg, mtrr::uncacheable);
    reg = range1::set(reg, mtrr::write_combining);
    reg = range2::set(reg, mtrr::write_through);
    reg = range3::set(reg, mtrr::write_protected);
    reg = range4::set(reg, mtrr::write_back);
    reg = range5::set(reg, 0xFFULL);
    reg = range6::set(reg, 0xEEULL);
    reg = range7::set(reg, 0xDDULL);

    CHECK(range0::get(reg) == mtrr::uncacheable);
    CHECK(range1::get(reg) == mtrr::write_combining);
    CHECK(range2::get(reg) == mtrr::write_through);
    CHECK(range3::get(reg) == mtrr::write_protected);
    CHECK(range4::get(reg) == mtrr::write_back);
    CHECK(range5::get(reg) == 0xFFULL);
    CHECK(range6::get(reg) == 0xEEULL);
    CHECK(range7::get(reg) == 0xDDULL);
}

TEST_CASE("mtrr::fix04k_E8000")
{
    using namespace intel_x64::mtrr::fix04k_E8000;

    set(0xFFFFFFFF11111111ULL);
    CHECK(get() == 0xFFFFFFFF11111111ULL);
    dump(0);

    range0::set(mtrr::uncacheable);
    range1::set(mtrr::write_combining);
    range2::set(mtrr::write_through);
    range3::set(mtrr::write_protected);
    range4::set(mtrr::write_back);
    range5::set(0xFFULL);
    range6::set(0xEEULL);
    range7::set(0xDDULL);

    CHECK(range0::get() == mtrr::uncacheable);
    CHECK(range1::get() == mtrr::write_combining);
    CHECK(range2::get() == mtrr::write_through);
    CHECK(range3::get() == mtrr::write_protected);
    CHECK(range4::get() == mtrr::write_back);
    CHECK(range5::get() == 0xFFULL);
    CHECK(range6::get() == 0xEEULL);
    CHECK(range7::get() == 0xDDULL);

    auto reg = 0x0ULL;
    reg = range0::set(reg, mtrr::uncacheable);
    reg = range1::set(reg, mtrr::write_combining);
    reg = range2::set(reg, mtrr::write_through);
    reg = range3::set(reg, mtrr::write_protected);
    reg = range4::set(reg, mtrr::write_back);
    reg = range5::set(reg, 0xFFULL);
    reg = range6::set(reg, 0xEEULL);
    reg = range7::set(reg, 0xDDULL);

    CHECK(range0::get(reg) == mtrr::uncacheable);
    CHECK(range1::get(reg) == mtrr::write_combining);
    CHECK(range2::get(reg) == mtrr::write_through);
    CHECK(range3::get(reg) == mtrr::write_protected);
    CHECK(range4::get(reg) == mtrr::write_back);
    CHECK(range5::get(reg) == 0xFFULL);
    CHECK(range6::get(reg) == 0xEEULL);
    CHECK(range7::get(reg) == 0xDDULL);
}

TEST_CASE("mtrr::fix04k_F0000")
{
    using namespace intel_x64::mtrr::fix04k_F0000;

    set(0xFFFFFFFF11111111ULL);
    CHECK(get() == 0xFFFFFFFF11111111ULL);
    dump(0);

    range0::set(mtrr::uncacheable);
    range1::set(mtrr::write_combining);
    range2::set(mtrr::write_through);
    range3::set(mtrr::write_protected);
    range4::set(mtrr::write_back);
    range5::set(0xFFULL);
    range6::set(0xEEULL);
    range7::set(0xDDULL);

    CHECK(range0::get() == mtrr::uncacheable);
    CHECK(range1::get() == mtrr::write_combining);
    CHECK(range2::get() == mtrr::write_through);
    CHECK(range3::get() == mtrr::write_protected);
    CHECK(range4::get() == mtrr::write_back);
    CHECK(range5::get() == 0xFFULL);
    CHECK(range6::get() == 0xEEULL);
    CHECK(range7::get() == 0xDDULL);

    auto reg = 0x0ULL;
    reg = range0::set(reg, mtrr::uncacheable);
    reg = range1::set(reg, mtrr::write_combining);
    reg = range2::set(reg, mtrr::write_through);
    reg = range3::set(reg, mtrr::write_protected);
    reg = range4::set(reg, mtrr::write_back);
    reg = range5::set(reg, 0xFFULL);
    reg = range6::set(reg, 0xEEULL);
    reg = range7::set(reg, 0xDDULL);

    CHECK(range0::get(reg) == mtrr::uncacheable);
    CHECK(range1::get(reg) == mtrr::write_combining);
    CHECK(range2::get(reg) == mtrr::write_through);
    CHECK(range3::get(reg) == mtrr::write_protected);
    CHECK(range4::get(reg) == mtrr::write_back);
    CHECK(range5::get(reg) == 0xFFULL);
    CHECK(range6::get(reg) == 0xEEULL);
    CHECK(range7::get(reg) == 0xDDULL);
}

TEST_CASE("mtrr::fix04k_F8000")
{
    using namespace intel_x64::mtrr::fix04k_F8000;

    set(0xFFFFFFFF11111111ULL);
    CHECK(get() == 0xFFFFFFFF11111111ULL);
    dump(0);

    range0::set(mtrr::uncacheable);
    range1::set(mtrr::write_combining);
    range2::set(mtrr::write_through);
    range3::set(mtrr::write_protected);
    range4::set(mtrr::write_back);
    range5::set(0xFFULL);
    range6::set(0xEEULL);
    range7::set(0xDDULL);

    CHECK(range0::get() == mtrr::uncacheable);
    CHECK(range1::get() == mtrr::write_combining);
    CHECK(range2::get() == mtrr::write_through);
    CHECK(range3::get() == mtrr::write_protected);
    CHECK(range4::get() == mtrr::write_back);
    CHECK(range5::get() == 0xFFULL);
    CHECK(range6::get() == 0xEEULL);
    CHECK(range7::get() == 0xDDULL);

    auto reg = 0x0ULL;
    reg = range0::set(reg, mtrr::uncacheable);
    reg = range1::set(reg, mtrr::write_combining);
    reg = range2::set(reg, mtrr::write_through);
    reg = range3::set(reg, mtrr::write_protected);
    reg = range4::set(reg, mtrr::write_back);
    reg = range5::set(reg, 0xFFULL);
    reg = range6::set(reg, 0xEEULL);
    reg = range7::set(reg, 0xDDULL);

    CHECK(range0::get(reg) == mtrr::uncacheable);
    CHECK(range1::get(reg) == mtrr::write_combining);
    CHECK(range2::get(reg) == mtrr::write_through);
    CHECK(range3::get(reg) == mtrr::write_protected);
    CHECK(range4::get(reg) == mtrr::write_back);
    CHECK(range5::get(reg) == 0xFFULL);
    CHECK(range6::get(reg) == 0xEEULL);
    CHECK(range7::get(reg) == 0xDDULL);
}
