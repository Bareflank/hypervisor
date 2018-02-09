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

TEST_CASE("test name goes here")
{
    CHECK(true);
}

std::map<msrs::field_type, msrs::value_type> g_msrs;

std::map<cpuid::field_type, cpuid::value_type> g_ecx_cpuid;

extern "C" uint64_t
_read_msr(uint32_t addr) noexcept
{ return g_msrs[addr]; }

extern "C" void
_write_msr(uint32_t addr, uint64_t val) noexcept
{ g_msrs[addr] = val; }

struct cpuid_regs {
    cpuid::value_type ecx;
};

struct cpuid_regs g_regs;

extern "C" uint32_t
_cpuid_ecx(uint32_t val) noexcept
{ return g_ecx_cpuid[val]; }

TEST_CASE("msrs_ia32_x2apic_apicid")
{
    using namespace msrs::ia32_x2apic_apicid;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("msrs_ia32_x2apic_version")
{
    using namespace msrs::ia32_x2apic_version;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("msrs_ia32_x2apic_tpr")
{
    using namespace msrs::ia32_x2apic_tpr;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("msrs_ia32_x2apic_ppr")
{
    using namespace msrs::ia32_x2apic_ppr;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("msrs_ia32_x2apic_eoi")
{
    using namespace msrs::ia32_x2apic_eoi;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(g_msrs[addr] == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("msrs_ia32_x2apic_ldr")
{
    using namespace msrs::ia32_x2apic_ldr;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("msrs_ia32_x2apic_ldr_logical_id")
{
    using namespace msrs::ia32_x2apic_ldr;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(logical_id::get() == (logical_id::mask >> logical_id::from));

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(logical_id::get(logical_id::mask) == (logical_id::mask >> logical_id::from));
}

TEST_CASE("msrs_ia32_x2apic_ldr_cluster_id")
{
    using namespace msrs::ia32_x2apic_ldr;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(cluster_id::get() == (cluster_id::mask >> cluster_id::from));

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(cluster_id::get(cluster_id::mask) == (cluster_id::mask >> cluster_id::from));
}

TEST_CASE("msrs_ia32_x2apic_sivr")
{
    using namespace msrs::ia32_x2apic_sivr;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("msrs_ia32_x2apic_sivr_vector")
{
    using namespace msrs::ia32_x2apic_sivr;

    vector::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(vector::get() == (vector::mask >> vector::from));

    vector::set(vector::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(vector::get(vector::mask) == (vector::mask >> vector::from));
}

TEST_CASE("msrs_ia32_x2apic_sivr_apic_enable_bit")
{
    using namespace msrs::ia32_x2apic_sivr;

    apic_enable_bit::enable();
    CHECK(apic_enable_bit::is_enabled());
    apic_enable_bit::disable();
    CHECK(apic_enable_bit::is_disabled());

    apic_enable_bit::enable(apic_enable_bit::mask);
    CHECK(apic_enable_bit::is_enabled(apic_enable_bit::mask));
    apic_enable_bit::disable(0x0);
    CHECK(apic_enable_bit::is_disabled(0x0));
}

TEST_CASE("msrs_ia32_x2apic_sivr_focus_checking")
{
    using namespace msrs::ia32_x2apic_sivr;

    focus_checking::enable();
    CHECK(focus_checking::is_enabled());
    focus_checking::disable();
    CHECK(focus_checking::is_disabled());

    focus_checking::enable(0x0);
    CHECK(focus_checking::is_enabled(0x0));
    focus_checking::disable(focus_checking::mask);
    CHECK(focus_checking::is_disabled(focus_checking::mask));
}

TEST_CASE("msrs_ia32_x2apic_sivr_suppress_eoi_broadcast")
{
    using namespace msrs::ia32_x2apic_sivr;

    suppress_eoi_broadcast::enable();
    CHECK(suppress_eoi_broadcast::is_enabled());
    suppress_eoi_broadcast::disable();
    CHECK(suppress_eoi_broadcast::is_disabled());

    suppress_eoi_broadcast::enable(suppress_eoi_broadcast::mask);
    CHECK(suppress_eoi_broadcast::is_enabled(suppress_eoi_broadcast::mask));
    suppress_eoi_broadcast::disable(0x0);
    CHECK(suppress_eoi_broadcast::is_disabled(0x0));
}

TEST_CASE("msrs_ia32_x2apic_isr0")
{
    using namespace msrs::ia32_x2apic_isr0;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("msrs_ia32_x2apic_isr1")
{
    using namespace msrs::ia32_x2apic_isr1;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("msrs_ia32_x2apic_isr2")
{
    using namespace msrs::ia32_x2apic_isr2;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("msrs_ia32_x2apic_isr3")
{
    using namespace msrs::ia32_x2apic_isr3;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("msrs_ia32_x2apic_isr4")
{
    using namespace msrs::ia32_x2apic_isr4;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("msrs_ia32_x2apic_isr5")
{
    using namespace msrs::ia32_x2apic_isr5;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("msrs_ia32_x2apic_isr6")
{
    using namespace msrs::ia32_x2apic_isr6;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("msrs_ia32_x2apic_isr7")
{
    using namespace msrs::ia32_x2apic_isr7;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("msrs_ia32_x2apic_tmr0")
{
    using namespace msrs::ia32_x2apic_tmr0;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("msrs_ia32_x2apic_tmr1")
{
    using namespace msrs::ia32_x2apic_tmr1;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("msrs_ia32_x2apic_tmr2")
{
    using namespace msrs::ia32_x2apic_tmr2;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("msrs_ia32_x2apic_tmr3")
{
    using namespace msrs::ia32_x2apic_tmr3;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("msrs_ia32_x2apic_tmr4")
{
    using namespace msrs::ia32_x2apic_tmr4;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("msrs_ia32_x2apic_tmr5")
{
    using namespace msrs::ia32_x2apic_tmr5;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("msrs_ia32_x2apic_tmr6")
{
    using namespace msrs::ia32_x2apic_tmr6;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("msrs_ia32_x2apic_tmr7")
{
    using namespace msrs::ia32_x2apic_tmr7;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("msrs_ia32_x2apic_irr0")
{
    using namespace msrs::ia32_x2apic_irr0;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("msrs_ia32_x2apic_irr1")
{
    using namespace msrs::ia32_x2apic_irr1;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("msrs_ia32_x2apic_irr2")
{
    using namespace msrs::ia32_x2apic_irr2;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("msrs_ia32_x2apic_irr3")
{
    using namespace msrs::ia32_x2apic_irr3;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("msrs_ia32_x2apic_irr4")
{
    using namespace msrs::ia32_x2apic_irr4;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("msrs_ia32_x2apic_irr5")
{
    using namespace msrs::ia32_x2apic_irr5;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("msrs_ia32_x2apic_irr6")
{
    using namespace msrs::ia32_x2apic_irr6;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("msrs_ia32_x2apic_irr7")
{
    using namespace msrs::ia32_x2apic_irr7;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("msrs_ia32_x2apic_esr")
{
    using namespace msrs::ia32_x2apic_esr;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("msrs_ia32_x2apic_lvt_cmci")
{
    using namespace msrs::ia32_x2apic_lvt_cmci;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("msrs_ia32_x2apic_lvt_cmci_vector")
{
    using namespace msrs::ia32_x2apic_lvt_cmci;

    vector::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(vector::get() == (vector::mask >> vector::from));

    vector::set(vector::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(vector::get(vector::mask) == (vector::mask >> vector::from));
}

TEST_CASE("msrs_ia32_x2apic_lvt_cmci_delivery_mode")
{
    using namespace msrs::ia32_x2apic_lvt_cmci;

    delivery_mode::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(delivery_mode::get() == (delivery_mode::mask >> delivery_mode::from));

    delivery_mode::set(delivery_mode::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(delivery_mode::get(delivery_mode::mask) == (delivery_mode::mask >> delivery_mode::from));

    delivery_mode::set(0x0ULL);
    delivery_mode::dump(0);
    delivery_mode::set(0x2ULL);
    delivery_mode::dump(0);
    delivery_mode::set(0x4ULL);
    delivery_mode::dump(0);
    delivery_mode::set(0x5ULL);
    delivery_mode::dump(0);
    delivery_mode::set(0x7ULL);
    delivery_mode::dump(0);
    delivery_mode::set(0x1ULL);
    delivery_mode::dump(0);
}

TEST_CASE("msrs_ia32_x2apic_lvt_cmci_delivery_status")
{
    using namespace msrs::ia32_x2apic_lvt_cmci;

    delivery_status::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(delivery_status::get() == (delivery_status::mask >> delivery_status::from));

    delivery_status::set(delivery_status::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(delivery_status::get(delivery_status::mask) == (delivery_status::mask >> delivery_status::from));

    delivery_status::set(0x0000000000000000ULL);
    dump(0);
    delivery_status::set(0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("msrs_ia32_x2apic_lvt_cmci_mask_bit")
{
    using namespace msrs::ia32_x2apic_lvt_cmci;

    mask_bit::enable();
    CHECK(mask_bit::is_enabled());
    mask_bit::disable();
    CHECK(mask_bit::is_disabled());

    mask_bit::enable(mask_bit::mask);
    CHECK(mask_bit::is_enabled(mask_bit::mask));
    mask_bit::disable(0x0);
    CHECK(mask_bit::is_disabled(0x0));
}

TEST_CASE("msrs_ia32_x2apic_icr")
{
    using namespace msrs::ia32_x2apic_icr;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("msrs_ia32_x2apic_icr_vector")
{
    using namespace msrs::ia32_x2apic_icr;

    vector::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(vector::get() == (vector::mask >> vector::from));

    vector::set(vector::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(vector::get(vector::mask) == (vector::mask >> vector::from));
}

TEST_CASE("msrs_ia32_x2apic_icr_delivery_mode")
{
    using namespace msrs::ia32_x2apic_icr;

    delivery_mode::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(delivery_mode::get() == (delivery_mode::mask >> delivery_mode::from));

    delivery_mode::set(delivery_mode::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(delivery_mode::get(delivery_mode::mask) == (delivery_mode::mask >> delivery_mode::from));

    delivery_mode::set(0x0ULL);
    delivery_mode::dump(0);
    delivery_mode::set(0x2ULL);
    delivery_mode::dump(0);
    delivery_mode::set(0x4ULL);
    delivery_mode::dump(0);
    delivery_mode::set(0x5ULL);
    delivery_mode::dump(0);
    delivery_mode::set(0x7ULL);
    delivery_mode::dump(0);
    delivery_mode::set(0x1ULL);
    delivery_mode::dump(0);
}

TEST_CASE("msrs_ia32_x2apic_icr_destination_mode")
{
    using namespace msrs::ia32_x2apic_icr;

    destination_mode::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(destination_mode::get() == (destination_mode::mask >> destination_mode::from));

    destination_mode::set(destination_mode::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(destination_mode::get(destination_mode::mask) == (destination_mode::mask >> destination_mode::from));

    destination_mode::set(0x0000000000000000ULL);
    dump(0);
    destination_mode::set(0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("msrs_ia32_x2apic_icr_delivery_status")
{
    using namespace msrs::ia32_x2apic_icr;

    delivery_status::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(delivery_status::get() == (delivery_status::mask >> delivery_status::from));

    delivery_status::set(delivery_status::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(delivery_status::get(delivery_status::mask) == (delivery_status::mask >> delivery_status::from));

    delivery_status::set(0x0000000000000000ULL);
    dump(0);
    delivery_status::set(0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("msrs_ia32_x2apic_icr_level")
{
    using namespace msrs::ia32_x2apic_icr;

    level::enable();
    CHECK(level::is_enabled());
    level::disable();
    CHECK(level::is_disabled());

    level::enable(level::mask);
    CHECK(level::is_enabled(level::mask));
    level::disable(0x0);
    CHECK(level::is_disabled(0x0));
}

TEST_CASE("msrs_ia32_x2apic_icr_trigger_mode")
{
    using namespace msrs::ia32_x2apic_icr;

    trigger_mode::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(trigger_mode::get() == (trigger_mode::mask >> trigger_mode::from));

    trigger_mode::set(trigger_mode::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(trigger_mode::get(trigger_mode::mask) == (trigger_mode::mask >> trigger_mode::from));

    trigger_mode::set(0x0000000000000000ULL);
    dump(0);
    trigger_mode::set(0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("msrs_ia32_x2apic_icr_destination_shorthand")
{
    using namespace msrs::ia32_x2apic_icr;

    destination_shorthand::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(destination_shorthand::get() == (destination_shorthand::mask >> destination_shorthand::from));

    destination_shorthand::set(destination_shorthand::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(destination_shorthand::get(destination_shorthand::mask) == (destination_shorthand::mask >> destination_shorthand::from));

    destination_shorthand::set(0x0ULL);
    destination_shorthand::dump(0);
    destination_shorthand::set(0x1ULL);
    destination_shorthand::dump(0);
    destination_shorthand::set(0x2ULL);
    destination_shorthand::dump(0);
    destination_shorthand::set(0x3ULL);
    destination_shorthand::dump(0);
}

TEST_CASE("msrs_ia32_x2apic_icr_destination_field")
{
    using namespace msrs::ia32_x2apic_icr;

    destination_field::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(destination_field::get() == (destination_field::mask >> destination_field::from));

    destination_field::set(destination_field::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(destination_field::get(destination_field::mask) == (destination_field::mask >> destination_field::from));
}

TEST_CASE("msrs_ia32_x2apic_lvt_timer")
{
    using namespace msrs::ia32_x2apic_lvt_timer;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("msrs_ia32_x2apic_lvt_timer_vector")
{
    using namespace msrs::ia32_x2apic_lvt_timer;

    vector::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(vector::get() == (vector::mask >> vector::from));

    vector::set(vector::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(vector::get(vector::mask) == (vector::mask >> vector::from));
}

TEST_CASE("msrs_ia32_x2apic_lvt_timer_delivery_status")
{
    using namespace msrs::ia32_x2apic_lvt_timer;

    delivery_status::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(delivery_status::get() == (delivery_status::mask >> delivery_status::from));

    delivery_status::set(delivery_status::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(delivery_status::get(delivery_status::mask) == (delivery_status::mask >> delivery_status::from));

    delivery_status::set(0x0000000000000000ULL);
    dump(0);
    delivery_status::set(0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("msrs_ia32_x2apic_lvt_timer_mask_bit")
{
    using namespace msrs::ia32_x2apic_lvt_timer;

    mask_bit::enable();
    CHECK(mask_bit::is_enabled());
    mask_bit::disable();
    CHECK(mask_bit::is_disabled());

    mask_bit::enable(mask_bit::mask);
    CHECK(mask_bit::is_enabled(mask_bit::mask));
    mask_bit::disable(0x0);
    CHECK(mask_bit::is_disabled(0x0));
}

TEST_CASE("msrs_ia32_x2apic_lvt_timer_timer_mode")
{
    using namespace msrs::ia32_x2apic_lvt_timer;

    timer_mode::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(timer_mode::get() == (timer_mode::mask >> timer_mode::from));

    timer_mode::set(timer_mode::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(timer_mode::get(timer_mode::mask) == (timer_mode::mask >> timer_mode::from));

    timer_mode::set(0x0ULL);
    timer_mode::dump(0);
    timer_mode::set(0x1ULL);
    timer_mode::dump(0);
    timer_mode::set(0x2ULL);
    timer_mode::dump(0);
    timer_mode::set(0x3ULL);
    timer_mode::dump(0);
}

TEST_CASE("msrs_ia32_x2apic_lvt_thermal")
{
    using namespace msrs::ia32_x2apic_lvt_thermal;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("msrs_ia32_x2apic_lvt_thermal_vector")
{
    using namespace msrs::ia32_x2apic_lvt_thermal;

    vector::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(vector::get() == (vector::mask >> vector::from));

    vector::set(vector::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(vector::get(vector::mask) == (vector::mask >> vector::from));
}

TEST_CASE("msrs_ia32_x2apic_lvt_thermal_delivery_mode")
{
    using namespace msrs::ia32_x2apic_lvt_thermal;

    delivery_mode::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(delivery_mode::get() == (delivery_mode::mask >> delivery_mode::from));

    delivery_mode::set(delivery_mode::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(delivery_mode::get(delivery_mode::mask) == (delivery_mode::mask >> delivery_mode::from));

    delivery_mode::set(0x0ULL);
    delivery_mode::dump(0);
    delivery_mode::set(0x2ULL);
    delivery_mode::dump(0);
    delivery_mode::set(0x4ULL);
    delivery_mode::dump(0);
    delivery_mode::set(0x5ULL);
    delivery_mode::dump(0);
    delivery_mode::set(0x7ULL);
    delivery_mode::dump(0);
    delivery_mode::set(0x1ULL);
    delivery_mode::dump(0);
}

TEST_CASE("msrs_ia32_x2apic_lvt_thermal_delivery_status")
{
    using namespace msrs::ia32_x2apic_lvt_thermal;

    delivery_status::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(delivery_status::get() == (delivery_status::mask >> delivery_status::from));

    delivery_status::set(delivery_status::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(delivery_status::get(delivery_status::mask) == (delivery_status::mask >> delivery_status::from));

    delivery_status::set(0x0000000000000000ULL);
    dump(0);
    delivery_status::set(0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("msrs_ia32_x2apic_lvt_thermal_mask_bit")
{
    using namespace msrs::ia32_x2apic_lvt_thermal;

    mask_bit::enable();
    CHECK(mask_bit::is_enabled());
    mask_bit::disable();
    CHECK(mask_bit::is_disabled());

    mask_bit::enable(mask_bit::mask);
    CHECK(mask_bit::is_enabled(mask_bit::mask));
    mask_bit::disable(0x0);
    CHECK(mask_bit::is_disabled(0x0));
}

TEST_CASE("msrs_ia32_x2apic_lvt_pmi")
{
    using namespace msrs::ia32_x2apic_lvt_pmi;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("msrs_ia32_x2apic_lvt_pmi_vector")
{
    using namespace msrs::ia32_x2apic_lvt_pmi;

    vector::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(vector::get() == (vector::mask >> vector::from));

    vector::set(vector::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(vector::get(vector::mask) == (vector::mask >> vector::from));
}

TEST_CASE("msrs_ia32_x2apic_lvt_pmi_delivery_mode")
{
    using namespace msrs::ia32_x2apic_lvt_pmi;

    delivery_mode::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(delivery_mode::get() == (delivery_mode::mask >> delivery_mode::from));

    delivery_mode::set(delivery_mode::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(delivery_mode::get(delivery_mode::mask) == (delivery_mode::mask >> delivery_mode::from));

    delivery_mode::set(0x0ULL);
    delivery_mode::dump(0);
    delivery_mode::set(0x2ULL);
    delivery_mode::dump(0);
    delivery_mode::set(0x4ULL);
    delivery_mode::dump(0);
    delivery_mode::set(0x5ULL);
    delivery_mode::dump(0);
    delivery_mode::set(0x7ULL);
    delivery_mode::dump(0);
    delivery_mode::set(0x1ULL);
    delivery_mode::dump(0);
}

TEST_CASE("msrs_ia32_x2apic_lvt_pmi_delivery_status")
{
    using namespace msrs::ia32_x2apic_lvt_pmi;

    delivery_status::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(delivery_status::get() == (delivery_status::mask >> delivery_status::from));

    delivery_status::set(delivery_status::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(delivery_status::get(delivery_status::mask) == (delivery_status::mask >> delivery_status::from));

    delivery_status::set(0x0000000000000000ULL);
    dump(0);
}

TEST_CASE("msrs_ia32_x2apic_lvt_pmi_mask_bit")
{
    using namespace msrs::ia32_x2apic_lvt_pmi;

    mask_bit::enable();
    CHECK(mask_bit::is_enabled());
    mask_bit::disable();
    CHECK(mask_bit::is_disabled());

    mask_bit::enable(mask_bit::mask);
    CHECK(mask_bit::is_enabled(mask_bit::mask));
    mask_bit::disable(0x0);
    CHECK(mask_bit::is_disabled(0x0));
}

TEST_CASE("msrs_ia32_x2apic_lvt_lint0")
{
    using namespace msrs::ia32_x2apic_lvt_lint0;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("msrs_ia32_x2apic_lvt_lint0_vector")
{
    using namespace msrs::ia32_x2apic_lvt_lint0;

    vector::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(vector::get() == (vector::mask >> vector::from));

    vector::set(vector::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(vector::get(vector::mask) == (vector::mask >> vector::from));
}

TEST_CASE("msrs_ia32_x2apic_lvt_lint0_delivery_mode")
{
    using namespace msrs::ia32_x2apic_lvt_lint0;

    delivery_mode::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(delivery_mode::get() == (delivery_mode::mask >> delivery_mode::from));

    delivery_mode::set(delivery_mode::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(delivery_mode::get(delivery_mode::mask) == (delivery_mode::mask >> delivery_mode::from));

    delivery_mode::set(0x0ULL);
    delivery_mode::dump(0);
    delivery_mode::set(0x2ULL);
    delivery_mode::dump(0);
    delivery_mode::set(0x4ULL);
    delivery_mode::dump(0);
    delivery_mode::set(0x5ULL);
    delivery_mode::dump(0);
    delivery_mode::set(0x7ULL);
    delivery_mode::dump(0);
    delivery_mode::set(0x1ULL);
    delivery_mode::dump(0);
}

TEST_CASE("msrs_ia32_x2apic_lvt_lint0_delivery_status")
{
    using namespace msrs::ia32_x2apic_lvt_lint0;

    delivery_status::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(delivery_status::get() == (delivery_status::mask >> delivery_status::from));

    delivery_status::set(delivery_status::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(delivery_status::get(delivery_status::mask) == (delivery_status::mask >> delivery_status::from));

    delivery_status::set(0x0000000000000000ULL);
    dump(0);
    delivery_status::set(0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("msrs_ia32_x2apic_lvt_lint0_polarity")
{
    using namespace msrs::ia32_x2apic_lvt_lint0;

    polarity::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(polarity::get() == (polarity::mask >> polarity::from));

    polarity::set(polarity::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(polarity::get(polarity::mask) == (polarity::mask >> polarity::from));

    polarity::set(0x0000000000000000ULL);
    dump(0);
    polarity::set(0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("msrs_ia32_x2apic_lvt_lint0_remote_irr")
{
    using namespace msrs::ia32_x2apic_lvt_lint0;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(remote_irr::get() == (remote_irr::mask >> remote_irr::from));

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(remote_irr::get(remote_irr::mask) == (remote_irr::mask >> remote_irr::from));
}

TEST_CASE("msrs_ia32_x2apic_lvt_lint0_trigger_mode")
{
    using namespace msrs::ia32_x2apic_lvt_lint0;

    trigger_mode::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(trigger_mode::get() == (trigger_mode::mask >> trigger_mode::from));

    trigger_mode::set(trigger_mode::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(trigger_mode::get(trigger_mode::mask) == (trigger_mode::mask >> trigger_mode::from));

    trigger_mode::set(0x0000000000000000ULL);
    dump(0);
    trigger_mode::set(0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("msrs_ia32_x2apic_lvt_lint0_mask_bit")
{
    using namespace msrs::ia32_x2apic_lvt_lint0;

    mask_bit::enable();
    CHECK(mask_bit::is_enabled());
    mask_bit::disable();
    CHECK(mask_bit::is_disabled());

    mask_bit::enable(mask_bit::mask);
    CHECK(mask_bit::is_enabled(mask_bit::mask));
    mask_bit::disable(0x0);
    CHECK(mask_bit::is_disabled(0x0));
}

TEST_CASE("msrs_ia32_x2apic_lvt_lint1")
{
    using namespace msrs::ia32_x2apic_lvt_lint1;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("msrs_ia32_x2apic_lvt_lint1_vector")
{
    using namespace msrs::ia32_x2apic_lvt_lint1;

    vector::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(vector::get() == (vector::mask >> vector::from));

    vector::set(vector::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(vector::get(vector::mask) == (vector::mask >> vector::from));
}

TEST_CASE("msrs_ia32_x2apic_lvt_lint1_delivery_mode")
{
    using namespace msrs::ia32_x2apic_lvt_lint1;

    delivery_mode::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(delivery_mode::get() == (delivery_mode::mask >> delivery_mode::from));

    delivery_mode::set(delivery_mode::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(delivery_mode::get(delivery_mode::mask) == (delivery_mode::mask >> delivery_mode::from));

    delivery_mode::set(0x0ULL);
    delivery_mode::dump(0);
    delivery_mode::set(0x2ULL);
    delivery_mode::dump(0);
    delivery_mode::set(0x4ULL);
    delivery_mode::dump(0);
    delivery_mode::set(0x5ULL);
    delivery_mode::dump(0);
    delivery_mode::set(0x7ULL);
    delivery_mode::dump(0);
    delivery_mode::set(0x1ULL);
    delivery_mode::dump(0);
}

TEST_CASE("msrs_ia32_x2apic_lvt_lint1_delivery_status")
{
    using namespace msrs::ia32_x2apic_lvt_lint1;

    delivery_status::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(delivery_status::get() == (delivery_status::mask >> delivery_status::from));

    delivery_status::set(delivery_status::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(delivery_status::get(delivery_status::mask) == (delivery_status::mask >> delivery_status::from));

    delivery_status::set(0x0000000000000000ULL);
    dump(0);
    delivery_status::set(0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("msrs_ia32_x2apic_lvt_lint1_polarity")
{
    using namespace msrs::ia32_x2apic_lvt_lint1;

    polarity::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(polarity::get() == (polarity::mask >> polarity::from));

    polarity::set(polarity::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(polarity::get(polarity::mask) == (polarity::mask >> polarity::from));

    polarity::set(0x0000000000000000ULL);
    dump(0);
    polarity::set(0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("msrs_ia32_x2apic_lvt_lint1_remote_irr")
{
    using namespace msrs::ia32_x2apic_lvt_lint1;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(remote_irr::get() == (remote_irr::mask >> remote_irr::from));

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(remote_irr::get(remote_irr::mask) == (remote_irr::mask >> remote_irr::from));
}

TEST_CASE("msrs_ia32_x2apic_lvt_lint1_trigger_mode")
{
    using namespace msrs::ia32_x2apic_lvt_lint1;

    trigger_mode::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(trigger_mode::get() == (trigger_mode::mask >> trigger_mode::from));

    trigger_mode::set(trigger_mode::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(trigger_mode::get(trigger_mode::mask) == (trigger_mode::mask >> trigger_mode::from));

    trigger_mode::set(0x0000000000000000ULL);
    dump(0);
    trigger_mode::set(0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("msrs_ia32_x2apic_lvt_lint1_mask_bit")
{
    using namespace msrs::ia32_x2apic_lvt_lint1;

    mask_bit::enable();
    CHECK(mask_bit::is_enabled());
    mask_bit::disable();
    CHECK(mask_bit::is_disabled());

    mask_bit::enable(mask_bit::mask);
    CHECK(mask_bit::is_enabled(mask_bit::mask));
    mask_bit::disable(0x0);
    CHECK(mask_bit::is_disabled(0x0));
}

TEST_CASE("msrs_ia32_x2apic_lvt_error")
{
    using namespace msrs::ia32_x2apic_lvt_error;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("msrs_ia32_x2apic_lvt_error_vector")
{
    using namespace msrs::ia32_x2apic_lvt_error;

    vector::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(vector::get() == (vector::mask >> vector::from));

    vector::set(vector::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(vector::get(vector::mask) == (vector::mask >> vector::from));
}

TEST_CASE("msrs_ia32_x2apic_lvt_error_delivery_status")
{
    using namespace msrs::ia32_x2apic_lvt_error;

    delivery_status::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(delivery_status::get() == (delivery_status::mask >> delivery_status::from));

    delivery_status::set(delivery_status::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(delivery_status::get(delivery_status::mask) == (delivery_status::mask >> delivery_status::from));

    delivery_status::set(0x0000000000000000ULL);
    dump(0);
    delivery_status::set(0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("msrs_ia32_x2apic_init_count")
{
    using namespace msrs::ia32_x2apic_init_count;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("msrs_ia32_x2apic_cur_count")
{
    using namespace msrs::ia32_x2apic_cur_count;

    g_msrs[addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("msrs_ia32_x2apic_div_conf")
{
    using namespace msrs::ia32_x2apic_div_conf;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("msrs_ia32_x2apic_div_conf_div_val")
{
    using namespace msrs::ia32_x2apic_div_conf;

    div_val::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(div_val::get() == (div_val::mask >> div_val::from));

    div_val::set(div_val::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(div_val::get(div_val::mask) == (div_val::mask >> div_val::from));

    div_val::set(div_val::div_by_2);
    CHECK(div_val::get() == div_val::div_by_2);
    div_val::dump(0);

    div_val::set(div_val::div_by_4);
    CHECK(div_val::get() == div_val::div_by_4);
    div_val::dump(0);

    div_val::set(div_val::div_by_8);
    CHECK(div_val::get() == div_val::div_by_8);
    div_val::dump(0);

    div_val::set(div_val::div_by_16);
    CHECK(div_val::get() == div_val::div_by_16);
    div_val::dump(0);

    div_val::set(div_val::div_by_32);
    CHECK(div_val::get() == div_val::div_by_32);
    div_val::dump(0);

    div_val::set(div_val::div_by_64);
    CHECK(div_val::get() == div_val::div_by_64);
    div_val::dump(0);

    div_val::set(div_val::div_by_128);
    CHECK(div_val::get() == div_val::div_by_128);
    div_val::dump(0);

    div_val::set(div_val::div_by_1);
    CHECK(div_val::get() == div_val::div_by_1);
    div_val::dump(0);
}

TEST_CASE("msrs_ia32_x2apic_self_ipi")
{
    using namespace msrs::ia32_x2apic_self_ipi;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(g_msrs[addr] == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("msrs_ia32_x2apic_self_ipi_vector")
{
    using namespace msrs::ia32_x2apic_self_ipi;

    set(0x0000000000000000ULL);
    vector::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(g_msrs[addr] == vector::mask);

    vector::set(vector::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(g_msrs[addr] == vector::mask);
}

TEST_CASE("x2apic_supported")
{
    g_ecx_cpuid[cpuid::feature_information::addr] =
        cpuid::feature_information::ecx::x2apic::mask;
    CHECK(x2apic::supported());

    g_ecx_cpuid[cpuid::feature_information::addr] = 0x0;
    CHECK_FALSE(x2apic::supported());
}

TEST_CASE("x2apic_control_validate_gpa_op")
{
    x2apic_control ctrl;

    CHECK(ctrl.validate_gpa_op(0xFEE00000ULL, lapic_control::read) == -1);      // Non-existent Register
    CHECK(ctrl.validate_gpa_op(0xFEE00030ULL, lapic_control::write) == -1);     // Unwritable Register (version)
    CHECK(ctrl.validate_gpa_op(0xFEE000B0ULL, lapic_control::read) == -1);      // Unreadable Register (eoi)
    CHECK(ctrl.validate_gpa_op(0xFEE00020ULL, lapic_control::read) == 0x2U);    // Successful Operation

    // x2apic vs xapic register conflicts
    CHECK(ctrl.validate_gpa_op(0xFEE00020ULL, lapic_control::write) == -1);     // ID Write
    CHECK(ctrl.validate_gpa_op(0xFEE00090ULL, lapic_control::read) == -1);      // APR Read
    CHECK(ctrl.validate_gpa_op(0xFEE00090ULL, lapic_control::write) == -1);     // APR Write
    CHECK(ctrl.validate_gpa_op(0xFEE000C0ULL, lapic_control::read) == -1);      // RRD Read
    CHECK(ctrl.validate_gpa_op(0xFEE000C0ULL, lapic_control::write) == -1);     // RRD Write
    CHECK(ctrl.validate_gpa_op(0xFEE000D0ULL, lapic_control::write) == -1);     // LDR Write
    CHECK(ctrl.validate_gpa_op(0xFEE000E0ULL, lapic_control::read) == -1);      // DFR Read
    CHECK(ctrl.validate_gpa_op(0xFEE000E0ULL, lapic_control::write) == -1);     // DFR Write
    CHECK(ctrl.validate_gpa_op(0xFEE00280ULL, lapic_control::write) == 0x28U);  // ESR Write
    CHECK(ctrl.validate_gpa_op(0xFEE00310ULL, lapic_control::read) == -1);      // ICR High Read
    CHECK(ctrl.validate_gpa_op(0xFEE00310ULL, lapic_control::write) == -1);     // ICR High Write
    CHECK(ctrl.validate_gpa_op(0xFEE003F0ULL, lapic_control::read) == -1);      // Self IPI Read
    CHECK(ctrl.validate_gpa_op(0xFEE003F0ULL, lapic_control::write) == 0x3FU);  // Self IPI Write
}

TEST_CASE("x2apic_control_validate_msr_op")
{
    x2apic_control ctrl;

    CHECK(ctrl.validate_msr_op(0x00000000ULL, lapic_control::read) == -1);      // Out of Lower Bound Register
    CHECK(ctrl.validate_msr_op(0xFFFFFFFFULL, lapic_control::read) == -1);      // Out of Upper Bound Register
    CHECK(ctrl.validate_msr_op(0x00000800ULL, lapic_control::read) == -1);      // Non-existent Register
    CHECK(ctrl.validate_msr_op(0x00000803ULL, lapic_control::write) == -1);     // Unwritable Register (version)
    CHECK(ctrl.validate_msr_op(0x0000080BULL, lapic_control::read) == -1);      // Unreadable Register (eoi)
    CHECK(ctrl.validate_msr_op(0x00000802ULL, lapic_control::read) == 0x2U);    // Successful Operation

    // x2apic vs xapic register conflicts
    CHECK(ctrl.validate_msr_op(0x00000802ULL, lapic_control::write) == -1);     // ID Write
    CHECK(ctrl.validate_msr_op(0x00000809ULL, lapic_control::read) == -1);      // APR Read
    CHECK(ctrl.validate_msr_op(0x00000809ULL, lapic_control::write) == -1);     // APR Write
    CHECK(ctrl.validate_msr_op(0x0000080CULL, lapic_control::read) == -1);      // RRD Read
    CHECK(ctrl.validate_msr_op(0x0000080CULL, lapic_control::write) == -1);     // RRD Write
    CHECK(ctrl.validate_msr_op(0x0000080DULL, lapic_control::write) == -1);     // LDR Write
    CHECK(ctrl.validate_msr_op(0x0000080EULL, lapic_control::read) == -1);      // DFR Read
    CHECK(ctrl.validate_msr_op(0x0000080EULL, lapic_control::write) == -1);     // DFR Write
    CHECK(ctrl.validate_msr_op(0x00000828ULL, lapic_control::write) == 0x28U);  // ESR Write
    CHECK(ctrl.validate_msr_op(0x00000831ULL, lapic_control::read) == -1);      // ICR High Read
    CHECK(ctrl.validate_msr_op(0x00000831ULL, lapic_control::write) == -1);     // ICR High Write
    CHECK(ctrl.validate_msr_op(0x0000083FULL, lapic_control::read) == -1);      // Self IPI Read
    CHECK(ctrl.validate_msr_op(0x0000083FULL, lapic_control::write) == 0x3FU);  // Self IPI Write
}

TEST_CASE("x2apic_control_read_register")
{
    x2apic_control ctrl;

    g_msrs[msrs::ia32_x2apic_apicid::addr] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(ctrl.read_register(0x02U) == 0xFFFFFFFFFFFFFFFFULL);

    g_msrs[msrs::ia32_x2apic_apicid::addr] = 0x0ULL;
    CHECK(ctrl.read_register(0x02U) == 0x0ULL);
}

TEST_CASE("x2apic_control_write_register")
{
    x2apic_control ctrl;

    ctrl.write_register(0x02U, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(ctrl.read_id() == 0xFFFFFFFFFFFFFFFFULL);

    ctrl.write_register(0x02U, 0x0ULL);
    CHECK(ctrl.read_id() == 0x0ULL);
}

TEST_CASE("x2apic_control_read_id")
{
    x2apic_control ctrl;

    CHECK(ctrl.validate_gpa_op(0xFEE00000ULL, lapic_control::read) == -1);      // Non-existent Register
    CHECK(ctrl.validate_gpa_op(0xFEE00030ULL, lapic_control::write) == -1);     // Unwritable Register (version)
    CHECK(ctrl.validate_gpa_op(0xFEE000B0ULL, lapic_control::read) == -1);      // Unreadable Register (eoi)
    CHECK(ctrl.validate_gpa_op(0xFEE00020ULL, lapic_control::read) == 0x2U);    // Successful Operation

    // x2apic vs xapic register conflicts
    CHECK(ctrl.validate_gpa_op(0xFEE00020ULL, lapic_control::write) == -1);     // ID Write
    CHECK(ctrl.validate_gpa_op(0xFEE00090ULL, lapic_control::read) == -1);      // APR Read
    CHECK(ctrl.validate_gpa_op(0xFEE00090ULL, lapic_control::write) == -1);     // APR Write
    CHECK(ctrl.validate_gpa_op(0xFEE000C0ULL, lapic_control::read) == -1);      // RRD Read
    CHECK(ctrl.validate_gpa_op(0xFEE000C0ULL, lapic_control::write) == -1);     // RRD Write
    CHECK(ctrl.validate_gpa_op(0xFEE000D0ULL, lapic_control::write) == -1);     // LDR Write
    CHECK(ctrl.validate_gpa_op(0xFEE000E0ULL, lapic_control::read) == -1);      // DFR Read
    CHECK(ctrl.validate_gpa_op(0xFEE000E0ULL, lapic_control::write) == -1);     // DFR Write
    CHECK(ctrl.validate_gpa_op(0xFEE00280ULL, lapic_control::write) == 0x28U);  // ESR Write
    CHECK(ctrl.validate_gpa_op(0xFEE00310ULL, lapic_control::read) == -1);      // ICR High Read
    CHECK(ctrl.validate_gpa_op(0xFEE00310ULL, lapic_control::write) == -1);     // ICR High Write
    CHECK(ctrl.validate_gpa_op(0xFEE003F0ULL, lapic_control::read) == -1);      // Self IPI Read
    CHECK(ctrl.validate_gpa_op(0xFEE003F0ULL, lapic_control::write) == 0x3FU);  // Self IPI Write
}

#endif
