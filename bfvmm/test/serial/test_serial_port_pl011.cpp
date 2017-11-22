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

#include <serial/serial_port_pl011.h>
#include <hippomocks.h>
#include <map>
#include <bfgsl.h>

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

static std::map<serial_port_pl011::port_type, serial_port_pl011::value_type_32> g_ports;

static uint32_t
mock_ind(uint16_t port) noexcept
{
    return g_ports[port];
}

static void
mock_outd(uint16_t port, uint32_t val) noexcept
{
    g_ports[port] = val;
}

static void
mock_serial(MockRepository &mocks)
{
    mocks.OnCallFunc(_outd).Do(mock_outd);
    mocks.OnCallFunc(_ind).Do(mock_ind);
}

TEST_CASE("serial: constructor_null_intrinsics")
{
    MockRepository mocks;
    mock_serial(mocks);

    CHECK_NOTHROW(std::make_unique<serial_port_pl011>());
}

TEST_CASE("serial: success")
{
    MockRepository mocks;
    mock_serial(mocks);

    uint32_t brd_int = 0, brd_frac = 0;

    CHECK(serial_port_pl011::instance()->port() == DEFAULT_COM_PORT);
    CHECK_NOTHROW(serial_port_pl011::instance()->baud_rate_divisor(brd_int, brd_frac));
    CHECK(brd_int == DEFAULT_BAUD_RATE_INT);
    CHECK(brd_frac == DEFAULT_BAUD_RATE_FRAC);
    CHECK(serial_port_pl011::instance()->data_bits() == serial_port_pl011::DEFAULT_DATA_BITS);
    CHECK(serial_port_pl011::instance()->stop_bits() == serial_port_pl011::DEFAULT_STOP_BITS);
    CHECK(serial_port_pl011::instance()->parity_bits() == serial_port_pl011::DEFAULT_PARITY_BITS);

    CHECK((g_ports[DEFAULT_COM_PORT + serial_pl011::uartibrd_reg]) == DEFAULT_BAUD_RATE_INT);
    CHECK((g_ports[DEFAULT_COM_PORT + serial_pl011::uartfbrd_reg]) == DEFAULT_BAUD_RATE_FRAC);
    CHECK((g_ports[DEFAULT_COM_PORT + serial_pl011::uartlcr_h_reg] & serial_pl011::uartlcr_h_fifo_enable) != 0);
    CHECK((g_ports[DEFAULT_COM_PORT + serial_pl011::uartlcr_h_reg] & serial_pl011::uartlcr_h_wlen_mask) == serial_port_pl011::DEFAULT_DATA_BITS);
    CHECK((g_ports[DEFAULT_COM_PORT + serial_pl011::uartlcr_h_reg] & serial_pl011::uartlcr_h_stop_mask) == serial_port_pl011::DEFAULT_STOP_BITS);
    CHECK((g_ports[DEFAULT_COM_PORT + serial_pl011::uartlcr_h_reg] & serial_pl011::uartlcr_h_parity_mask) == serial_port_pl011::DEFAULT_PARITY_BITS);
}

TEST_CASE("serial: port and set_port")
{
    MockRepository mocks;
    mock_serial(mocks);

    auto const invport = gsl::narrow_cast<serial_port_pl011::port_type>(~DEFAULT_COM_PORT & 0xffff);

    serial_port_pl011::instance()->set_port(invport);
    CHECK(serial_port_pl011::instance()->port() == invport);

    serial_port_pl011::instance()->set_port(DEFAULT_COM_PORT);
    CHECK(serial_port_pl011::instance()->port() == DEFAULT_COM_PORT);
}

TEST_CASE("serial: set_baud_rate_success")
{
    MockRepository mocks;
    mock_serial(mocks);

    auto serial = std::make_unique<serial_port_pl011>();

    serial->set_baud_rate_divisor(0xffffffffu, 0xffffffffu);

    uint32_t brd_int = 0, brd_frac = 0;
    serial->baud_rate_divisor(brd_int, brd_frac);
    CHECK(brd_int == 0xffffu);
    CHECK(brd_frac == 0x3fu);
}

TEST_CASE("serial: set_data_bits_success")
{
    MockRepository mocks;
    mock_serial(mocks);

    auto serial = std::make_unique<serial_port_pl011>();

    serial->set_data_bits(serial_port_pl011::char_length_5);
    CHECK(serial->data_bits() == serial_port_pl011::char_length_5);
    serial->set_data_bits(serial_port_pl011::char_length_6);
    CHECK(serial->data_bits() == serial_port_pl011::char_length_6);
    serial->set_data_bits(serial_port_pl011::char_length_7);
    CHECK(serial->data_bits() == serial_port_pl011::char_length_7);
    serial->set_data_bits(serial_port_pl011::char_length_8);
    CHECK(serial->data_bits() == serial_port_pl011::char_length_8);
}

TEST_CASE("serial: set_data_bits_success_extra_bits")
{
    MockRepository mocks;
    mock_serial(mocks);

    auto serial = std::make_unique<serial_port_pl011>();

    auto bits = serial_port_pl011::DEFAULT_DATA_BITS | ~serial_pl011::uartlcr_h_wlen_mask;
    serial->set_data_bits(static_cast<serial_port_pl011::data_bits_t>(bits));

    CHECK(serial->data_bits() == serial_port_pl011::DEFAULT_DATA_BITS);
    CHECK(serial->stop_bits() == serial_port_pl011::DEFAULT_STOP_BITS);
    CHECK(serial->parity_bits() == serial_port_pl011::DEFAULT_PARITY_BITS);
}

TEST_CASE("serial: set_stop_bits_success")
{
    MockRepository mocks;
    mock_serial(mocks);

    auto serial = std::make_unique<serial_port_pl011>();

    serial->set_stop_bits(serial_port_pl011::stop_bits_1);
    CHECK(serial->stop_bits() == serial_port_pl011::stop_bits_1);
    serial->set_stop_bits(serial_port_pl011::stop_bits_2);
    CHECK(serial->stop_bits() == serial_port_pl011::stop_bits_2);
}

TEST_CASE("serial: set_stop_bits_success_extra_bits")
{
    MockRepository mocks;
    mock_serial(mocks);

    auto serial = std::make_unique<serial_port_pl011>();

    auto bits = serial_port_pl011::DEFAULT_STOP_BITS | ~serial_pl011::uartlcr_h_stop_mask;
    serial->set_stop_bits(static_cast<serial_port_pl011::stop_bits_t>(bits));

    CHECK(serial->data_bits() == serial_port_pl011::DEFAULT_DATA_BITS);
    CHECK(serial->stop_bits() == serial_port_pl011::DEFAULT_STOP_BITS);
    CHECK(serial->parity_bits() == serial_port_pl011::DEFAULT_PARITY_BITS);
}

TEST_CASE("serial: set_parity_bits_success")
{
    MockRepository mocks;
    mock_serial(mocks);

    auto serial = std::make_unique<serial_port_pl011>();

    serial->set_parity_bits(serial_port_pl011::parity_none);
    CHECK(serial->parity_bits() == serial_port_pl011::parity_none);
    serial->set_parity_bits(serial_port_pl011::parity_odd);
    CHECK(serial->parity_bits() == serial_port_pl011::parity_odd);
    serial->set_parity_bits(serial_port_pl011::parity_even);
    CHECK(serial->parity_bits() == serial_port_pl011::parity_even);
    serial->set_parity_bits(serial_port_pl011::parity_mark);
    CHECK(serial->parity_bits() == serial_port_pl011::parity_mark);
    serial->set_parity_bits(serial_port_pl011::parity_space);
    CHECK(serial->parity_bits() == serial_port_pl011::parity_space);
}

TEST_CASE("serial: set_parity_bits_success_extra_bits")
{
    MockRepository mocks;
    mock_serial(mocks);

    auto serial = std::make_unique<serial_port_pl011>();

    auto bits = serial_port_pl011::DEFAULT_PARITY_BITS | ~serial_pl011::uartlcr_h_parity_mask;
    serial->set_parity_bits(static_cast<serial_port_pl011::parity_bits_t>(bits));

    CHECK(serial->data_bits() == serial_port_pl011::DEFAULT_DATA_BITS);
    CHECK(serial->stop_bits() == serial_port_pl011::DEFAULT_STOP_BITS);
    CHECK(serial->parity_bits() == serial_port_pl011::DEFAULT_PARITY_BITS);
}

TEST_CASE("serial: write character")
{
    MockRepository mocks;
    mock_serial(mocks);

    g_ports[DEFAULT_COM_PORT + serial_pl011::uartfr_reg] = serial_pl011::uartfr_tx_empty;

    auto serial = std::make_unique<serial_port_pl011>();
    serial->write('c');
}

TEST_CASE("serial: write string")
{
    MockRepository mocks;
    mock_serial(mocks);

    g_ports[DEFAULT_COM_PORT + serial_pl011::uartfr_reg] = serial_pl011::uartfr_tx_empty;

    auto serial = std::make_unique<serial_port_pl011>();
    serial->write("hello world");
}

TEST_CASE("serial: write char buffer")
{
    MockRepository mocks;
    mock_serial(mocks);

    g_ports[DEFAULT_COM_PORT + serial_pl011::uartfr_reg] = serial_pl011::uartfr_tx_empty;

    auto serial = std::make_unique<serial_port_pl011>();
    serial->write("hello world", 12);
}

#endif
