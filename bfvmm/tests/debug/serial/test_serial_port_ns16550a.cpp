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
#include <bfvmm/debug/serial/serial_port_ns16550a.h>

static std::map<serial_port_ns16550a::port_type, serial_port_ns16550a::value_type_8> g_ports;

extern "C" uint8_t
_inb(uint16_t port) noexcept
{ return gsl::narrow_cast<serial_port_ns16550a::value_type_8>(g_ports[port]); }

extern "C" void
_outb(uint16_t port, uint8_t val) noexcept
{ g_ports[port] = val; }

extern "C" uint32_t
_ind(uint16_t port) noexcept
{ return g_ports[port]; }

extern "C" void
_outd(uint16_t port, uint32_t val) noexcept
{ g_ports[port] = gsl::narrow_cast<serial_port_ns16550a::value_type_8>(val); }

TEST_CASE("serial: support")
{
    CHECK_NOTHROW(_inb(0));
    CHECK_NOTHROW(_outb(0, 0));
    CHECK_NOTHROW(_ind(0));
    CHECK_NOTHROW(_outd(0, 0));
}

TEST_CASE("serial: constructor_null_intrinsics")
{
    CHECK_NOTHROW(std::make_unique<serial_port_ns16550a>());
}

TEST_CASE("serial: success")
{
    CHECK(serial_port_ns16550a::instance()->port() == DEFAULT_COM_PORT);
    CHECK(serial_port_ns16550a::instance()->baud_rate() == serial_port_ns16550a::DEFAULT_BAUD_RATE);
    CHECK(serial_port_ns16550a::instance()->data_bits() == serial_port_ns16550a::DEFAULT_DATA_BITS);
    CHECK(serial_port_ns16550a::instance()->stop_bits() == serial_port_ns16550a::DEFAULT_STOP_BITS);
    CHECK(serial_port_ns16550a::instance()->parity_bits() == serial_port_ns16550a::DEFAULT_PARITY_BITS);

    CHECK((g_ports[DEFAULT_COM_PORT + serial_ns16550a::baud_rate_lo_reg]) == ((serial_port_ns16550a::DEFAULT_BAUD_RATE & 0x00FF) >> 0));
    CHECK((g_ports[DEFAULT_COM_PORT + serial_ns16550a::baud_rate_hi_reg]) == ((serial_port_ns16550a::DEFAULT_BAUD_RATE & 0xFF00) >> 8));
    CHECK((g_ports[DEFAULT_COM_PORT + serial_ns16550a::fifo_control_reg] & serial_ns16550a::fifo_control_enable_fifos) != 0);
    CHECK((g_ports[DEFAULT_COM_PORT + serial_ns16550a::fifo_control_reg] & serial_ns16550a::fifo_control_clear_recieve_fifo) != 0);
    CHECK((g_ports[DEFAULT_COM_PORT + serial_ns16550a::fifo_control_reg] & serial_ns16550a::fifo_control_clear_transmit_fifo) != 0);
    CHECK((g_ports[DEFAULT_COM_PORT + serial_ns16550a::line_control_reg] & serial_ns16550a::line_control_data_mask) == serial_port_ns16550a::DEFAULT_DATA_BITS);
    CHECK((g_ports[DEFAULT_COM_PORT + serial_ns16550a::line_control_reg] & serial_ns16550a::line_control_stop_mask) == serial_port_ns16550a::DEFAULT_STOP_BITS);
    CHECK((g_ports[DEFAULT_COM_PORT + serial_ns16550a::line_control_reg] & serial_ns16550a::line_control_parity_mask) == serial_port_ns16550a::DEFAULT_PARITY_BITS);
}

TEST_CASE("serial: port and set_port")
{
    auto const invport = gsl::narrow_cast<serial_port_ns16550a::port_type>(~DEFAULT_COM_PORT & 0xffff);

    serial_port_ns16550a::instance()->set_port(invport);
    CHECK(serial_port_ns16550a::instance()->port() == invport);

    serial_port_ns16550a::instance()->set_port(DEFAULT_COM_PORT);
    CHECK(serial_port_ns16550a::instance()->port() == DEFAULT_COM_PORT);
}

TEST_CASE("serial: set_baud_rate_success")
{
    auto serial = std::make_unique<serial_port_ns16550a>();

    serial->set_baud_rate(serial_port_ns16550a::baud_rate_50);
    CHECK(serial->baud_rate() == serial_port_ns16550a::baud_rate_50);
    serial->set_baud_rate(serial_port_ns16550a::baud_rate_75);
    CHECK(serial->baud_rate() == serial_port_ns16550a::baud_rate_75);
    serial->set_baud_rate(serial_port_ns16550a::baud_rate_110);
    CHECK(serial->baud_rate() == serial_port_ns16550a::baud_rate_110);
    serial->set_baud_rate(serial_port_ns16550a::baud_rate_150);
    CHECK(serial->baud_rate() == serial_port_ns16550a::baud_rate_150);
    serial->set_baud_rate(serial_port_ns16550a::baud_rate_300);
    CHECK(serial->baud_rate() == serial_port_ns16550a::baud_rate_300);
    serial->set_baud_rate(serial_port_ns16550a::baud_rate_600);
    CHECK(serial->baud_rate() == serial_port_ns16550a::baud_rate_600);
    serial->set_baud_rate(serial_port_ns16550a::baud_rate_1200);
    CHECK(serial->baud_rate() == serial_port_ns16550a::baud_rate_1200);
    serial->set_baud_rate(serial_port_ns16550a::baud_rate_1800);
    CHECK(serial->baud_rate() == serial_port_ns16550a::baud_rate_1800);
    serial->set_baud_rate(serial_port_ns16550a::baud_rate_2000);
    CHECK(serial->baud_rate() == serial_port_ns16550a::baud_rate_2000);
    serial->set_baud_rate(serial_port_ns16550a::baud_rate_2400);
    CHECK(serial->baud_rate() == serial_port_ns16550a::baud_rate_2400);
    serial->set_baud_rate(serial_port_ns16550a::baud_rate_3600);
    CHECK(serial->baud_rate() == serial_port_ns16550a::baud_rate_3600);
    serial->set_baud_rate(serial_port_ns16550a::baud_rate_4800);
    CHECK(serial->baud_rate() == serial_port_ns16550a::baud_rate_4800);
    serial->set_baud_rate(serial_port_ns16550a::baud_rate_7200);
    CHECK(serial->baud_rate() == serial_port_ns16550a::baud_rate_7200);
    serial->set_baud_rate(serial_port_ns16550a::baud_rate_9600);
    CHECK(serial->baud_rate() == serial_port_ns16550a::baud_rate_9600);
    serial->set_baud_rate(serial_port_ns16550a::baud_rate_19200);
    CHECK(serial->baud_rate() == serial_port_ns16550a::baud_rate_19200);
    serial->set_baud_rate(serial_port_ns16550a::baud_rate_38400);
    CHECK(serial->baud_rate() == serial_port_ns16550a::baud_rate_38400);
    serial->set_baud_rate(serial_port_ns16550a::baud_rate_57600);
    CHECK(serial->baud_rate() == serial_port_ns16550a::baud_rate_57600);
    serial->set_baud_rate(serial_port_ns16550a::baud_rate_115200);
    CHECK(serial->baud_rate() == serial_port_ns16550a::baud_rate_115200);
}

TEST_CASE("serial: set_data_bits_success")
{
    auto serial = std::make_unique<serial_port_ns16550a>();

    serial->set_data_bits(serial_port_ns16550a::char_length_5);
    CHECK(serial->data_bits() == serial_port_ns16550a::char_length_5);
    serial->set_data_bits(serial_port_ns16550a::char_length_6);
    CHECK(serial->data_bits() == serial_port_ns16550a::char_length_6);
    serial->set_data_bits(serial_port_ns16550a::char_length_7);
    CHECK(serial->data_bits() == serial_port_ns16550a::char_length_7);
    serial->set_data_bits(serial_port_ns16550a::char_length_8);
    CHECK(serial->data_bits() == serial_port_ns16550a::char_length_8);
}

TEST_CASE("serial: set_data_bits_success_extra_bits")
{
    auto serial = std::make_unique<serial_port_ns16550a>();

    auto bits = serial_port_ns16550a::DEFAULT_DATA_BITS | ~serial_ns16550a::line_control_data_mask;
    serial->set_data_bits(static_cast<serial_port_ns16550a::data_bits_t>(bits));

    CHECK(serial->data_bits() == serial_port_ns16550a::DEFAULT_DATA_BITS);
    CHECK(serial->stop_bits() == serial_port_ns16550a::DEFAULT_STOP_BITS);
    CHECK(serial->parity_bits() == serial_port_ns16550a::DEFAULT_PARITY_BITS);
}

TEST_CASE("serial: set_stop_bits_success")
{
    auto serial = std::make_unique<serial_port_ns16550a>();

    serial->set_stop_bits(serial_port_ns16550a::stop_bits_1);
    CHECK(serial->stop_bits() == serial_port_ns16550a::stop_bits_1);
    serial->set_stop_bits(serial_port_ns16550a::stop_bits_2);
    CHECK(serial->stop_bits() == serial_port_ns16550a::stop_bits_2);
}

TEST_CASE("serial: set_stop_bits_success_extra_bits")
{
    auto serial = std::make_unique<serial_port_ns16550a>();

    auto bits = serial_port_ns16550a::DEFAULT_STOP_BITS | ~serial_ns16550a::line_control_stop_mask;
    serial->set_stop_bits(static_cast<serial_port_ns16550a::stop_bits_t>(bits));

    CHECK(serial->data_bits() == serial_port_ns16550a::DEFAULT_DATA_BITS);
    CHECK(serial->stop_bits() == serial_port_ns16550a::DEFAULT_STOP_BITS);
    CHECK(serial->parity_bits() == serial_port_ns16550a::DEFAULT_PARITY_BITS);
}

TEST_CASE("serial: set_parity_bits_success")
{
    auto serial = std::make_unique<serial_port_ns16550a>();

    serial->set_parity_bits(serial_port_ns16550a::parity_none);
    CHECK(serial->parity_bits() == serial_port_ns16550a::parity_none);
    serial->set_parity_bits(serial_port_ns16550a::parity_odd);
    CHECK(serial->parity_bits() == serial_port_ns16550a::parity_odd);
    serial->set_parity_bits(serial_port_ns16550a::parity_even);
    CHECK(serial->parity_bits() == serial_port_ns16550a::parity_even);
    serial->set_parity_bits(serial_port_ns16550a::parity_mark);
    CHECK(serial->parity_bits() == serial_port_ns16550a::parity_mark);
    serial->set_parity_bits(serial_port_ns16550a::parity_space);
    CHECK(serial->parity_bits() == serial_port_ns16550a::parity_space);
}

TEST_CASE("serial: set_parity_bits_success_extra_bits")
{
    auto serial = std::make_unique<serial_port_ns16550a>();

    auto bits = serial_port_ns16550a::DEFAULT_PARITY_BITS | ~serial_ns16550a::line_control_parity_mask;
    serial->set_parity_bits(static_cast<serial_port_ns16550a::parity_bits_t>(bits));

    CHECK(serial->data_bits() == serial_port_ns16550a::DEFAULT_DATA_BITS);
    CHECK(serial->stop_bits() == serial_port_ns16550a::DEFAULT_STOP_BITS);
    CHECK(serial->parity_bits() == serial_port_ns16550a::DEFAULT_PARITY_BITS);
}

TEST_CASE("serial: write character")
{
    g_ports[DEFAULT_COM_PORT + serial_ns16550a::line_status_reg] = 0xFF;

    auto serial = std::make_unique<serial_port_ns16550a>();
    serial->write('c');
}

TEST_CASE("serial: write string")
{
    g_ports[DEFAULT_COM_PORT + serial_ns16550a::line_status_reg] = 0xFF;

    auto serial = std::make_unique<serial_port_ns16550a>();
    serial->write("hello world");
}

TEST_CASE("serial: write char buffer")
{
    g_ports[DEFAULT_COM_PORT + serial_ns16550a::line_status_reg] = 0xFF;

    auto serial = std::make_unique<serial_port_ns16550a>();
    serial->write("hello world", 12);
}
