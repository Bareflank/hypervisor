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
#include <bfbitmanip.h>

TEST_CASE("set bit")
{
    CHECK(set_bit(0x00000000U, 0) == 0x00000001U);
    CHECK(set_bit(0x00000000U, 8) == 0x00000100U);
}

TEST_CASE("clear bit")
{
    CHECK(clear_bit(0xFFFFFFFFU, 0) == 0xFFFFFFFEU);
    CHECK(clear_bit(0xFFFFFFFFU, 8) == 0xFFFFFEFFU);
}

TEST_CASE("get bit")
{
    CHECK(get_bit(0xFFFFFFFFU, 0) == 1);
    CHECK(get_bit(0x00000000U, 0) == 0);
    CHECK(get_bit(0xFFFFFFFFU, 8) == 1);
    CHECK(get_bit(0x00000000U, 8) == 0);
}

TEST_CASE("is bit set")
{
    CHECK(is_bit_set(0xFFFFFFFFU, 0));
    CHECK(!is_bit_set(0x00000000U, 0));
    CHECK(is_bit_set(0xFFFFFFFFU, 8));
    CHECK(!is_bit_set(0x00000000U, 8));
}

TEST_CASE("is bit cleared")
{
    CHECK(!is_bit_cleared(0xFFFFFFFFU, 0));
    CHECK(is_bit_cleared(0x00000000U, 0));
    CHECK(!is_bit_cleared(0xFFFFFFFFU, 8));
    CHECK(is_bit_cleared(0x00000000U, 8));
}

TEST_CASE("num bits set")
{
    CHECK(num_bits_set(0xFFFFFFFFU) == 32);
    CHECK(num_bits_set(0x00000000U) == 0);
}

TEST_CASE("get bits")
{
    CHECK(get_bits(0xFFFFFFFFU, 0x11111111U) == 0x11111111U);
    CHECK(get_bits(0x00000000U, 0x11111111U) == 0x00000000U);
    CHECK(get_bits(0x88888888U, 0x11111111U) == 0x00000000U);
    CHECK(get_bits(0xF0F0F0F0U, 0x11111111U) == 0x10101010U);
}

TEST_CASE("set bits")
{
    CHECK(set_bits(0xFFFFFFFFU, 0x00111100U, 0x00000000U) == 0xFFEEEEFFU);
    CHECK(set_bits(0x00000000U, 0x00111100U, 0xFFFFFFFFU) == 0x00111100U);
    CHECK(set_bits(0x88888888U, 0x00111100U, 0x00111100U) == 0x88999988U);
    CHECK(set_bits(0xF0F0F0F0U, 0x00111100U, 0x00111100U) == 0xF0F1F1F0U);
}

TEST_CASE("bitmanip_eapis: set bit from span")
{
    auto buf = std::make_unique<unsigned[]>(10);
    auto buf_view = gsl::make_span(buf.get(), 10);

    memset(buf.get(), 0, 10 * sizeof(unsigned));
    set_bit(buf_view, 0);
    CHECK(buf_view[0] == 0x1);

    memset(buf.get(), 0, 10 * sizeof(unsigned));
    set_bit(buf_view, 8);
    CHECK(buf_view[0] == 0x100);

    memset(buf.get(), 0, 10 * sizeof(unsigned));
    set_bit(buf_view, 48);
    CHECK(buf_view[1] == 0x10000);

    memset(buf.get(), 0, 10 * sizeof(unsigned));
    CHECK_THROWS(set_bit(buf_view, 1000000));
}

TEST_CASE("bitmanip_eapis: clear bit from span")
{
    auto buf = std::make_unique<unsigned[]>(10);
    auto buf_view = gsl::make_span(buf.get(), 10);

    memset(buf.get(), 0xFF, 10 * sizeof(unsigned));
    clear_bit(buf_view, 0);
    CHECK(buf_view[0] == 0xFFFFFFFE);

    memset(buf.get(), 0xFF, 10 * sizeof(unsigned));
    clear_bit(buf_view, 8);
    CHECK(buf_view[0] == 0xFFFFFEFF);

    memset(buf.get(), 0xFF, 10 * sizeof(unsigned));
    clear_bit(buf_view, 48);
    CHECK(buf_view[1] == 0xFFFEFFFF);

    memset(buf.get(), 0xFF, 10 * sizeof(unsigned));
    CHECK_THROWS(clear_bit(buf_view, 1000000));
}
