//
// Bareflank Extended APIs
//
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
#include <arch/intel_x64/apic/ioapic.h>

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

TEST_CASE("ioapic: check read/write attributes")
{
    for (uint8_t i = 0U; i < ioapic::rte_end; ++i) {
        switch (i) {
            case ioapic::ver::offset:
            case ioapic::arb::offset:
                CHECK(ioapic::is_read_only(i));
                break;
            case 3U:
            case 4U:
            case 5U:
            case 6U:
            case 7U:
            case 8U:
            case 9U:
            case 10U:
            case 11U:
            case 12U:
            case 13U:
            case 14U:
            case 15U:
                CHECK_FALSE(ioapic::exists(i));
                break;
            default:
                CHECK(ioapic::is_read_write(i));
                break;
        }
    }
}

TEST_CASE("ioapic: id")
{
    uint32_t reg = 0U;
    uint8_t id = 3U;

    reg = ioapic::id::set(reg, id);
    CHECK(ioapic::id::get(reg) == id);
    ioapic::id::dump(0U, reg);
}

TEST_CASE("ioapic: ver")
{
    uint32_t reg = ioapic::ver::default_val;
    uint32_t version = 2U;
    uint32_t max_rte = 23U;

    CHECK(ioapic::ver::version::get(reg) == 17U);
    CHECK(ioapic::ver::max_rte_number::get(reg) == 23U);

    reg = ioapic::ver::version::set(reg, 2U);
    reg = ioapic::ver::max_rte_number::set(reg, 30U);

    CHECK(ioapic::ver::version::get(reg) == 2U);
    CHECK(ioapic::ver::max_rte_number::get(reg) == 30U);

    ioapic::ver::dump(0U, reg);
}

TEST_CASE("ioapic: arb")
{
    uint32_t reg = 0x03000000U;

    CHECK(ioapic::arb::id::get(reg) == 3U);
    reg = ioapic::arb::id::set(reg, 2U);
    CHECK(ioapic::arb::id::get(reg) == 2U);

    ioapic::arb::dump(0U, reg);
}

TEST_CASE("ioapic: rte vector")
{
    uint64_t entry = 0ULL;

    entry = ioapic::rte::vector::set(entry, 0xFFU);
    CHECK(ioapic::rte::vector::get(entry) == 0xFFU);

    ioapic::rte::dump(0, entry);
}

TEST_CASE("ioapic: rte delivery_mode")
{
    uint64_t entry = 0ULL;

    entry = ioapic::rte::delivery_mode::set(entry, 0U);
    CHECK(ioapic::rte::delivery_mode::get(entry) == ioapic::rte::delivery_mode::fixed);

    entry = ioapic::rte::delivery_mode::set(entry, 1U);
    CHECK(ioapic::rte::delivery_mode::get(entry) == ioapic::rte::delivery_mode::lowest_priority);
    ioapic::rte::delivery_mode::dump(0U, entry);

    entry = ioapic::rte::delivery_mode::set(entry, 2U);
    CHECK(ioapic::rte::delivery_mode::get(entry) == ioapic::rte::delivery_mode::smi);

    entry = ioapic::rte::delivery_mode::set(entry, 4U);
    CHECK(ioapic::rte::delivery_mode::get(entry) == ioapic::rte::delivery_mode::nmi);

    entry = ioapic::rte::delivery_mode::set(entry, 5U);
    CHECK(ioapic::rte::delivery_mode::get(entry) == ioapic::rte::delivery_mode::init);

    entry = ioapic::rte::delivery_mode::set(entry, 7U);
    CHECK(ioapic::rte::delivery_mode::get(entry) == ioapic::rte::delivery_mode::extint);
}

TEST_CASE("ioapic: rte destination_mode")
{
    uint64_t entry = 0ULL;

    entry = ioapic::rte::destination_mode::set(entry, 0U);
    CHECK(ioapic::rte::destination_mode::get(entry) == ioapic::rte::destination_mode::physical);
    ioapic::rte::destination_mode::dump(0U, entry);

    entry = ioapic::rte::destination_mode::set(entry, 1U);
    CHECK(ioapic::rte::destination_mode::get(entry) == ioapic::rte::destination_mode::logical);
    ioapic::rte::destination_mode::dump(0U, entry);
}

TEST_CASE("ioapic: rte delivery_status")
{
    uint64_t entry = 0ULL;

    entry = ioapic::rte::delivery_status::set(entry, 0U);
    CHECK(ioapic::rte::delivery_status::get(entry) == ioapic::rte::delivery_status::idle);
    ioapic::rte::delivery_status::dump(0U, entry);

    entry = ioapic::rte::delivery_status::set(entry, 1U);
    CHECK(ioapic::rte::delivery_status::get(entry) == ioapic::rte::delivery_status::send_pending);
    ioapic::rte::delivery_status::dump(0U, entry);
}

TEST_CASE("ioapic: rte polarity")
{
    uint64_t entry = 0ULL;

    entry = ioapic::rte::polarity::set(entry, 0U);
    CHECK(ioapic::rte::polarity::get(entry) == ioapic::rte::polarity::active_high);
    ioapic::rte::polarity::dump(0U, entry);

    entry = ioapic::rte::polarity::set(entry, 1U);
    CHECK(ioapic::rte::polarity::get(entry) == ioapic::rte::polarity::active_low);
    ioapic::rte::polarity::dump(0U, entry);
}

TEST_CASE("ioapic: rte remote_irr")
{
    uint64_t entry = 0ULL;

    CHECK(ioapic::rte::remote_irr::is_disabled(entry));

    entry = ioapic::rte::remote_irr::enable(entry);
    CHECK(ioapic::rte::remote_irr::is_enabled(entry));

    entry = ioapic::rte::remote_irr::disable(entry);
    CHECK(ioapic::rte::remote_irr::is_disabled(entry));

    ioapic::rte::remote_irr::dump(0U, entry);
}

TEST_CASE("ioapic: rte trigger_mode")
{
    uint64_t entry = 0ULL;

    entry = ioapic::rte::trigger_mode::set(entry, 0U);
    CHECK(ioapic::rte::trigger_mode::get(entry) == ioapic::rte::trigger_mode::edge);
    ioapic::rte::trigger_mode::dump(0U, entry);

    entry = ioapic::rte::trigger_mode::set(entry, 1U);
    CHECK(ioapic::rte::trigger_mode::get(entry) == ioapic::rte::trigger_mode::level);
    ioapic::rte::trigger_mode::dump(0U, entry);
}

TEST_CASE("ioapic: rte mask_bit")
{
    uint64_t entry = 0ULL;

    CHECK(ioapic::rte::mask_bit::is_disabled(entry));

    entry = ioapic::rte::mask_bit::enable(entry);
    CHECK(ioapic::rte::mask_bit::is_enabled(entry));

    entry = ioapic::rte::mask_bit::disable(entry);
    CHECK(ioapic::rte::mask_bit::is_disabled(entry));

    ioapic::rte::mask_bit::dump(0U, entry);
}

TEST_CASE("ioapic: rte logical_destination")
{
    uint64_t entry = 0ULL;

    entry = ioapic::rte::logical_destination::set(entry, 0xBFU);
    CHECK(ioapic::rte::logical_destination::get(entry) == 0xBFU);
    ioapic::rte::logical_destination::dump(0U, entry);
}

TEST_CASE("ioapic: rte physical_destination")
{
    uint64_t entry = 0ULL;

    entry = ioapic::rte::physical_destination::set(entry, 0xBFU);
    CHECK(ioapic::rte::physical_destination::get(entry) == 0x0FU);
    ioapic::rte::physical_destination::dump(0U, entry);
}

#endif
