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

#include <map>

#include <bfgsl.h>
#include <debug/serial/serial_pl011.h>

using namespace bfvmm;

static uint8_t g_mmio[0x1000];
static const uintptr_t g_pmmio = reinterpret_cast<uintptr_t>(&g_mmio[0]);

TEST_CASE("serial: constructor")
{
    serial_pl011 ser(g_pmmio);
    CHECK(ser.port() == g_pmmio);
}

TEST_CASE("serial: success")
{
    uint32_t brd_int = 0, brd_frac = 0;
    serial_pl011 instance(g_pmmio);

    CHECK(instance.port() == g_pmmio);
    CHECK_NOTHROW(instance.baud_rate_divisor(brd_int, brd_frac));
    CHECK(brd_int == DEFAULT_BAUD_RATE_INT);
    CHECK(brd_frac == DEFAULT_BAUD_RATE_FRAC);
    CHECK(instance.data_bits() == serial_pl011::DEFAULT_DATA_BITS);
    CHECK(instance.stop_bits() == serial_pl011::DEFAULT_STOP_BITS);
    CHECK(instance.parity_bits() == serial_pl011::DEFAULT_PARITY_BITS);

    CHECK((g_mmio[serial_pl011::uartibrd_reg]) == DEFAULT_BAUD_RATE_INT);
    CHECK((g_mmio[serial_pl011::uartfbrd_reg]) == DEFAULT_BAUD_RATE_FRAC);
    CHECK((g_mmio[serial_pl011::uartlcr_h_reg] & serial_pl011::uartlcr_h_fifo_enable) != 0);
    CHECK((g_mmio[serial_pl011::uartlcr_h_reg] & serial_pl011::uartlcr_h_wlen_mask) == serial_pl011::DEFAULT_DATA_BITS);
    CHECK((g_mmio[serial_pl011::uartlcr_h_reg] & serial_pl011::uartlcr_h_stop_mask) == serial_pl011::DEFAULT_STOP_BITS);
    CHECK((g_mmio[serial_pl011::uartlcr_h_reg] & serial_pl011::uartlcr_h_parity_mask) == serial_pl011::DEFAULT_PARITY_BITS);
}

TEST_CASE("serial: port and set_port")
{
    serial_pl011 instance(g_pmmio);
    auto const invport = gsl::narrow_cast<uintptr_t>(~DEFAULT_COM_PORT & 0xffff);

    instance.set_port(invport);
    CHECK(instance.port() == invport);

    instance.set_port(DEFAULT_COM_PORT);
    CHECK(instance.port() == DEFAULT_COM_PORT);
}

TEST_CASE("serial: set_baud_rate_success")
{
    serial_pl011 instance(g_pmmio);

    instance.set_baud_rate_divisor(0xffffffffu, 0xffffffffu);

    uint32_t brd_int = 0, brd_frac = 0;
    instance.baud_rate_divisor(brd_int, brd_frac);
    CHECK(brd_int == 0xffffu);
    CHECK(brd_frac == 0x3fu);
}

TEST_CASE("serial: set_data_bits_success")
{
    serial_pl011 instance(g_pmmio);

    instance.set_data_bits(serial_pl011::char_length_5);
    CHECK(instance.data_bits() == serial_pl011::char_length_5);
    instance.set_data_bits(serial_pl011::char_length_6);
    CHECK(instance.data_bits() == serial_pl011::char_length_6);
    instance.set_data_bits(serial_pl011::char_length_7);
    CHECK(instance.data_bits() == serial_pl011::char_length_7);
    instance.set_data_bits(serial_pl011::char_length_8);
    CHECK(instance.data_bits() == serial_pl011::char_length_8);
}

TEST_CASE("serial: set_data_bits_success_extra_bits")
{
    serial_pl011 instance(g_pmmio);

    auto bits = serial_pl011::DEFAULT_DATA_BITS | ~serial_pl011::uartlcr_h_wlen_mask;
    instance.set_data_bits(static_cast<serial_pl011::data_bits_t>(bits));

    CHECK(instance.data_bits() == serial_pl011::DEFAULT_DATA_BITS);
    CHECK(instance.stop_bits() == serial_pl011::DEFAULT_STOP_BITS);
    CHECK(instance.parity_bits() == serial_pl011::DEFAULT_PARITY_BITS);
}

TEST_CASE("serial: set_stop_bits_success")
{
    serial_pl011 instance(g_pmmio);

    instance.set_stop_bits(serial_pl011::stop_bits_1);
    CHECK(instance.stop_bits() == serial_pl011::stop_bits_1);
    instance.set_stop_bits(serial_pl011::stop_bits_2);
    CHECK(instance.stop_bits() == serial_pl011::stop_bits_2);
}

TEST_CASE("serial: set_stop_bits_success_extra_bits")
{
    serial_pl011 instance(g_pmmio);

    auto bits = serial_pl011::DEFAULT_STOP_BITS | ~serial_pl011::uartlcr_h_stop_mask;
    instance.set_stop_bits(static_cast<serial_pl011::stop_bits_t>(bits));

    CHECK(instance.data_bits() == serial_pl011::DEFAULT_DATA_BITS);
    CHECK(instance.stop_bits() == serial_pl011::DEFAULT_STOP_BITS);
    CHECK(instance.parity_bits() == serial_pl011::DEFAULT_PARITY_BITS);
}

TEST_CASE("serial: set_parity_bits_success")
{
    serial_pl011 instance(g_pmmio);

    instance.set_parity_bits(serial_pl011::parity_none);
    CHECK(instance.parity_bits() == serial_pl011::parity_none);
    instance.set_parity_bits(serial_pl011::parity_odd);
    CHECK(instance.parity_bits() == serial_pl011::parity_odd);
    instance.set_parity_bits(serial_pl011::parity_even);
    CHECK(instance.parity_bits() == serial_pl011::parity_even);
    instance.set_parity_bits(serial_pl011::parity_mark);
    CHECK(instance.parity_bits() == serial_pl011::parity_mark);
    instance.set_parity_bits(serial_pl011::parity_space);
    CHECK(instance.parity_bits() == serial_pl011::parity_space);
}

TEST_CASE("serial: set_parity_bits_success_extra_bits")
{
    serial_pl011 instance(g_pmmio);

    auto bits = serial_pl011::DEFAULT_PARITY_BITS | ~serial_pl011::uartlcr_h_parity_mask;
    instance.set_parity_bits(static_cast<serial_pl011::parity_bits_t>(bits));

    CHECK(instance.data_bits() == serial_pl011::DEFAULT_DATA_BITS);
    CHECK(instance.stop_bits() == serial_pl011::DEFAULT_STOP_BITS);
    CHECK(instance.parity_bits() == serial_pl011::DEFAULT_PARITY_BITS);
}

TEST_CASE("serial: write character")
{
    g_mmio[serial_pl011::uartfr_reg] = serial_pl011::uartfr_tx_empty;

    serial_pl011 instance(g_pmmio);
    instance.write('c');
}
