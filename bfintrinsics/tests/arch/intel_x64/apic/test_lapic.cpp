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
#include <intrinsics.h>
#include <hippomocks.h>

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

using namespace intel_x64;
using namespace lapic;

std::map<msrs::field_type, msrs::value_type> g_msrs;
std::map<cpuid::field_type, cpuid::value_type> g_edx_cpuid;

extern "C" uint64_t
_read_msr(uint32_t addr) noexcept
{ return g_msrs[addr]; }

extern "C" void
_write_msr(uint32_t addr, uint64_t val) noexcept
{ g_msrs[addr] = val; }

extern "C" uint32_t
_cpuid_edx(uint32_t val) noexcept
{ return g_edx_cpuid[val]; }


TEST_CASE("ia32_apic_base")
{
    using namespace ::intel_x64::msrs::ia32_apic_base;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_apic_base_bsp")
{
    using namespace ::intel_x64::msrs::ia32_apic_base;

    bsp::enable();
    CHECK(bsp::is_enabled());
    bsp::disable();
    CHECK(bsp::is_disabled());

    bsp::enable(bsp::mask);
    CHECK(bsp::is_enabled(bsp::mask));
    bsp::disable(0x0);
    CHECK(bsp::is_disabled(0x0));
}

TEST_CASE("ia32_apic_base_extd")
{
    using namespace ::intel_x64::msrs::ia32_apic_base;

    extd::enable();
    CHECK(extd::is_enabled());
    extd::disable();
    CHECK(extd::is_disabled());

    extd::enable(extd::mask);
    CHECK(extd::is_enabled(extd::mask));
    extd::disable(0x0);
    CHECK(extd::is_disabled(0x0));
}

TEST_CASE("ia32_apic_base_en")
{
    using namespace ::intel_x64::msrs::ia32_apic_base;

    en::enable();
    CHECK(en::is_enabled());
    en::disable();
    CHECK(en::is_disabled());

    en::enable(en::mask);
    CHECK(en::is_enabled(en::mask));
    en::disable(0x0);
    CHECK(en::is_disabled(0x0));
}

TEST_CASE("ia32_apic_base_state")
{
    using namespace ::intel_x64::msrs::ia32_apic_base;

    state::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(state::get() == (state::mask >> state::from));

    state::set(state::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(state::get(state::mask) == (state::mask >> state::from));

    state::disable();
    CHECK(state::get() == state::disabled);
    state::disable(state::disabled);
    CHECK(state::get(state::disabled << state::from) == state::disabled);
    state::dump(0);

    state::enable_xapic();
    CHECK(state::get() == state::xapic);
    state::enable_xapic(state::xapic);
    CHECK(state::get(state::xapic << state::from) == state::xapic);
    state::dump(0);

    state::enable_x2apic();
    CHECK(state::get() == state::x2apic);
    state::enable_x2apic(state::x2apic);
    CHECK(state::get(state::x2apic << state::from) == state::x2apic);
    state::dump(0);

    state::set(state::invalid);
    CHECK(state::get() == state::invalid);
    state::dump(0);
}

TEST_CASE("ia32_apic_base_apic_base")
{
    using namespace ::intel_x64::msrs::ia32_apic_base;

    apic_base::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(apic_base::get() == (apic_base::mask));

    apic_base::set(apic_base::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(apic_base::get(apic_base::mask) == (apic_base::mask));
}

TEST_CASE("lapic_icr_vector")
{
    using namespace icr;

    auto reg = 0x0ULL;

    reg = vector::set(reg, 0x33ULL);
    CHECK(vector::get(reg) == 0x33ULL);
    CHECK_NOTHROW(vector::dump(0x0ULL, reg));
    CHECK_NOTHROW(icr::dump(0x0ULL, reg));
}

TEST_CASE("lapic_icr_delivery_mode")
{
    using namespace icr;

    auto reg = 0x0ULL;

    reg = delivery_mode::set(reg, delivery_mode::fixed);
    CHECK(delivery_mode::get(reg) == delivery_mode::fixed);
    CHECK_NOTHROW(delivery_mode::dump(0x0ULL, reg));

    reg = delivery_mode::set(reg, delivery_mode::fixed);
    CHECK(delivery_mode::get(reg) == delivery_mode::fixed);
    CHECK_NOTHROW(delivery_mode::dump(0x0ULL, reg));

    reg = delivery_mode::set(reg, delivery_mode::smi);
    CHECK(delivery_mode::get(reg) == delivery_mode::smi);
    CHECK_NOTHROW(delivery_mode::dump(0x0ULL, reg));

    reg = delivery_mode::set(reg, delivery_mode::nmi);
    CHECK(delivery_mode::get(reg) == delivery_mode::nmi);
    CHECK_NOTHROW(delivery_mode::dump(0x0ULL, reg));

    reg = delivery_mode::set(reg, delivery_mode::init);
    CHECK(delivery_mode::get(reg) == delivery_mode::init);
    CHECK_NOTHROW(delivery_mode::dump(0x0ULL, reg));

    reg = delivery_mode::set(reg, delivery_mode::extint);
    CHECK(delivery_mode::get(reg) == delivery_mode::extint);
    CHECK_NOTHROW(delivery_mode::dump(0x0ULL, reg));

    CHECK_THROWS(delivery_mode::dump(0x0ULL, 0x1ULL << delivery_mode::from));
}

TEST_CASE("lapic_icr_destination_mode")
{
    using namespace icr;

    auto reg = 0x0ULL;

    reg = destination_mode::set(reg, destination_mode::physical);
    CHECK(destination_mode::get(reg) == destination_mode::physical);
    CHECK_NOTHROW(destination_mode::dump(0x0ULL, reg));

    reg = destination_mode::set(reg, destination_mode::logical);
    CHECK(destination_mode::get(reg) == destination_mode::logical);
    CHECK_NOTHROW(destination_mode::dump(0x0ULL, reg));
}

TEST_CASE("lapic_icr_delivery_status")
{
    using namespace icr;

    auto reg = 0x0ULL;

    reg = delivery_status::set(reg, delivery_status::send_pending);
    CHECK(delivery_status::get(reg) == delivery_status::send_pending);
    CHECK_NOTHROW(delivery_status::dump(0x0ULL, reg));

    reg = delivery_status::set(reg, delivery_status::idle);
    CHECK(delivery_status::get(reg) == delivery_status::idle);
    CHECK_NOTHROW(delivery_status::dump(0x0ULL, reg));
}

TEST_CASE("lapic_icr_level")
{
    using namespace icr;

    auto reg = 0x0ULL;

    reg = level::enable(reg);
    CHECK(level::is_enabled(reg));
    CHECK_NOTHROW(level::dump(0x0ULL, level::is_enabled(reg)));

    reg = level::disable(reg);
    CHECK(level::is_disabled(reg));
    CHECK_NOTHROW(level::dump(0x0ULL, level::is_disabled(reg)));
}

TEST_CASE("lapic_icr_trigger_mode")
{
    using namespace icr;

    auto reg = 0x0ULL;

    reg = trigger_mode::set(reg, trigger_mode::level);
    CHECK(reg == trigger_mode::mask);
    CHECK_NOTHROW(trigger_mode::dump(0x0ULL, reg));

    reg = trigger_mode::set(reg, trigger_mode::edge);
    CHECK(reg == 0);
    CHECK_NOTHROW(trigger_mode::dump(0x0ULL, reg));
}

TEST_CASE("lapic_icr_destination_shorthand")
{
    using namespace icr;

    auto reg = 0x0ULL;

    reg = destination_shorthand::set(reg, destination_shorthand::self);
    CHECK(destination_shorthand::get(reg) == destination_shorthand::self);
    CHECK_NOTHROW(destination_shorthand::dump(0x0ULL, reg));

    reg = destination_shorthand::set(reg, destination_shorthand::all_incl_self);
    CHECK(destination_shorthand::get(reg) == destination_shorthand::all_incl_self);
    CHECK_NOTHROW(destination_shorthand::dump(0x0ULL, reg));

    reg = destination_shorthand::set(reg, destination_shorthand::all_excl_self);
    CHECK(destination_shorthand::get(reg) == destination_shorthand::all_excl_self);
    CHECK_NOTHROW(destination_shorthand::dump(0x0ULL, reg));

    reg = destination_shorthand::set(reg, destination_shorthand::none);
    CHECK(destination_shorthand::get(reg) == destination_shorthand::none);
    CHECK_NOTHROW(destination_shorthand::dump(0x0ULL, reg));
}

TEST_CASE("lapic_icr_x2apic_destination")
{
    using namespace icr;

    auto reg = 0x0ULL;

    reg = x2apic_destination::set(reg, 0xDEADBEEFULL);
    CHECK(x2apic_destination::get(reg) == 0xDEADBEEFULL);
    CHECK_NOTHROW(x2apic_destination::dump(0x0ULL, reg));
}

TEST_CASE("lapic_icr_xapic_destination")
{
    using namespace icr;

    auto reg = 0x0ULL;

    reg = xapic_destination::set(reg, 0xDEADBEEFULL);
    CHECK(xapic_destination::get(reg) == 0xEFULL);
    CHECK_NOTHROW(xapic_destination::dump(0x0ULL, reg));
}

TEST_CASE("lapic_self_ipi")
{
    auto reg = 0x0ULL;

    reg = self_ipi::vector::set(reg, 0xBEEF);
    CHECK(self_ipi::vector::get(reg) == 0xEFU);
    CHECK_NOTHROW(self_ipi::dump(0x0ULL, reg));
}

TEST_CASE("lapic_version")
{
    CHECK_NOTHROW(version::dump(0x0ULL, 0x0ULL));
}

TEST_CASE("lapic_version_version")
{
    auto reg = 0x0ULL;

    reg = version::version::set(reg, 0xFF42ULL);
    CHECK(version::version::get(reg) == 0x42ULL);
    CHECK_NOTHROW(version::version::dump(0x0ULL, reg));
}

TEST_CASE("lapic_version_max_lvt_entry_minus_one")
{
    auto reg = 0x0ULL;

    reg = version::max_lvt_entry_minus_one::set(reg, 0x3ULL);
    CHECK(version::max_lvt_entry_minus_one::get(reg) == 0x3ULL);
    CHECK_NOTHROW(version::max_lvt_entry_minus_one::dump(0x0ULL, reg));
}

TEST_CASE("lapic_version_suppress_eoi_broadcast_supported")
{
    auto reg = 0x0ULL;

    reg = version::suppress_eoi_broadcast_supported::enable(reg);
    CHECK(version::suppress_eoi_broadcast_supported::is_enabled(reg));

    reg = version::suppress_eoi_broadcast_supported::disable(reg);
    CHECK(version::suppress_eoi_broadcast_supported::is_disabled(reg));
}

TEST_CASE("lapic_svr")
{
    using namespace svr;

    auto reg = 0x0ULL;

    reg = vector::set(reg, 0x33ULL);
    CHECK(vector::get(reg) == 0x33ULL);
    CHECK_NOTHROW(vector::dump(0x0ULL, reg));
    CHECK_NOTHROW(svr::dump(0x0ULL, reg));
}

TEST_CASE("lapic_svr_apic_enable_bit")
{
    auto reg = 0x0ULL;

    reg = svr::apic_enable_bit::enable(reg);
    CHECK(svr::apic_enable_bit::is_enabled(reg));

    reg = svr::apic_enable_bit::disable(reg);
    CHECK(svr::apic_enable_bit::is_disabled(reg));

    CHECK_NOTHROW(svr::apic_enable_bit::dump(0x0ULL, reg));
}

TEST_CASE("lapic_svr_focus_checking")
{
    auto reg = 0x0ULL;

    reg = svr::focus_checking::enable(reg);
    CHECK(svr::focus_checking::is_enabled(reg));

    reg = svr::focus_checking::disable(reg);
    CHECK(svr::focus_checking::is_disabled(reg));

    CHECK_NOTHROW(svr::focus_checking::dump(0x0ULL, reg));
}

TEST_CASE("lapic_svr_suppress_eoi_broadcast")
{
    auto reg = 0x0ULL;

    reg = svr::suppress_eoi_broadcast::enable(reg);
    CHECK(svr::suppress_eoi_broadcast::is_enabled(reg));

    reg = svr::suppress_eoi_broadcast::disable(reg);
    CHECK(svr::suppress_eoi_broadcast::is_disabled(reg));

    CHECK_NOTHROW(svr::suppress_eoi_broadcast::dump(0x0ULL, reg));
}

TEST_CASE("lapic_is_present")
{
    using namespace cpuid::feature_information;

    g_edx_cpuid[addr] = edx::apic::mask;
    CHECK(lapic::is_present());
    g_edx_cpuid[addr] = 0x0ULL;
    CHECK(!lapic::is_present());
}

#endif
