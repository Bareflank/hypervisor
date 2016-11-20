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
#include <serial/serial_port_intel_x64.h>

#include <map>
static std::map<uint16_t, uint8_t> g_ports;

extern "C" uint8_t
__inb(uint16_t port) noexcept
{
    return g_ports[port];
}

extern "C" void
__outb(uint16_t port, uint8_t val) noexcept
{
    g_ports[port] = val;
}

void
serial_ut::test_serial_null_intrinsics()
{
    this->expect_no_exception([&] { std::make_shared<serial_port_intel_x64>(); });
}

void
serial_ut::test_serial_success()
{
    this->expect_true(serial_port_intel_x64::instance()->port() == serial_intel_x64::DEFAULT_COM_PORT);
    this->expect_true(serial_port_intel_x64::instance()->baud_rate() == serial_port_intel_x64::DEFAULT_BAUD_RATE);
    this->expect_true(serial_port_intel_x64::instance()->data_bits() == serial_port_intel_x64::DEFAULT_DATA_BITS);
    this->expect_true(serial_port_intel_x64::instance()->stop_bits() == serial_port_intel_x64::DEFAULT_STOP_BITS);
    this->expect_true(serial_port_intel_x64::instance()->parity_bits() == serial_port_intel_x64::DEFAULT_PARITY_BITS);

    this->expect_true((g_ports[serial_intel_x64::DEFAULT_COM_PORT + serial_intel_x64::baud_rate_lo_reg]) == ((serial_port_intel_x64::DEFAULT_BAUD_RATE & 0x00FF) >> 0));
    this->expect_true((g_ports[serial_intel_x64::DEFAULT_COM_PORT + serial_intel_x64::baud_rate_hi_reg]) == ((serial_port_intel_x64::DEFAULT_BAUD_RATE & 0xFF00) >> 8));
    this->expect_true((g_ports[serial_intel_x64::DEFAULT_COM_PORT + serial_intel_x64::fifo_control_reg] & serial_intel_x64::fifo_control_enable_fifos) != 0);
    this->expect_true((g_ports[serial_intel_x64::DEFAULT_COM_PORT + serial_intel_x64::fifo_control_reg] & serial_intel_x64::fifo_control_clear_recieve_fifo) != 0);
    this->expect_true((g_ports[serial_intel_x64::DEFAULT_COM_PORT + serial_intel_x64::fifo_control_reg] & serial_intel_x64::fifo_control_clear_transmit_fifo) != 0);
    this->expect_true((g_ports[serial_intel_x64::DEFAULT_COM_PORT + serial_intel_x64::line_control_reg] & serial_intel_x64::line_control_data_mask) == serial_port_intel_x64::DEFAULT_DATA_BITS);
    this->expect_true((g_ports[serial_intel_x64::DEFAULT_COM_PORT + serial_intel_x64::line_control_reg] & serial_intel_x64::line_control_stop_mask) == serial_port_intel_x64::DEFAULT_STOP_BITS);
    this->expect_true((g_ports[serial_intel_x64::DEFAULT_COM_PORT + serial_intel_x64::line_control_reg] & serial_intel_x64::line_control_parity_mask) == serial_port_intel_x64::DEFAULT_PARITY_BITS);
}

void
serial_ut::test_serial_set_baud_rate_success()
{
    auto serial = std::make_unique<serial_port_intel_x64>();

    serial->set_baud_rate(serial_port_intel_x64::baud_rate_50);
    this->expect_true(serial->baud_rate() == serial_port_intel_x64::baud_rate_50);
    serial->set_baud_rate(serial_port_intel_x64::baud_rate_75);
    this->expect_true(serial->baud_rate() == serial_port_intel_x64::baud_rate_75);
    serial->set_baud_rate(serial_port_intel_x64::baud_rate_110);
    this->expect_true(serial->baud_rate() == serial_port_intel_x64::baud_rate_110);
    serial->set_baud_rate(serial_port_intel_x64::baud_rate_150);
    this->expect_true(serial->baud_rate() == serial_port_intel_x64::baud_rate_150);
    serial->set_baud_rate(serial_port_intel_x64::baud_rate_300);
    this->expect_true(serial->baud_rate() == serial_port_intel_x64::baud_rate_300);
    serial->set_baud_rate(serial_port_intel_x64::baud_rate_600);
    this->expect_true(serial->baud_rate() == serial_port_intel_x64::baud_rate_600);
    serial->set_baud_rate(serial_port_intel_x64::baud_rate_1200);
    this->expect_true(serial->baud_rate() == serial_port_intel_x64::baud_rate_1200);
    serial->set_baud_rate(serial_port_intel_x64::baud_rate_1800);
    this->expect_true(serial->baud_rate() == serial_port_intel_x64::baud_rate_1800);
    serial->set_baud_rate(serial_port_intel_x64::baud_rate_2000);
    this->expect_true(serial->baud_rate() == serial_port_intel_x64::baud_rate_2000);
    serial->set_baud_rate(serial_port_intel_x64::baud_rate_2400);
    this->expect_true(serial->baud_rate() == serial_port_intel_x64::baud_rate_2400);
    serial->set_baud_rate(serial_port_intel_x64::baud_rate_3600);
    this->expect_true(serial->baud_rate() == serial_port_intel_x64::baud_rate_3600);
    serial->set_baud_rate(serial_port_intel_x64::baud_rate_4800);
    this->expect_true(serial->baud_rate() == serial_port_intel_x64::baud_rate_4800);
    serial->set_baud_rate(serial_port_intel_x64::baud_rate_7200);
    this->expect_true(serial->baud_rate() == serial_port_intel_x64::baud_rate_7200);
    serial->set_baud_rate(serial_port_intel_x64::baud_rate_9600);
    this->expect_true(serial->baud_rate() == serial_port_intel_x64::baud_rate_9600);
    serial->set_baud_rate(serial_port_intel_x64::baud_rate_19200);
    this->expect_true(serial->baud_rate() == serial_port_intel_x64::baud_rate_19200);
    serial->set_baud_rate(serial_port_intel_x64::baud_rate_38400);
    this->expect_true(serial->baud_rate() == serial_port_intel_x64::baud_rate_38400);
    serial->set_baud_rate(serial_port_intel_x64::baud_rate_57600);
    this->expect_true(serial->baud_rate() == serial_port_intel_x64::baud_rate_57600);
    serial->set_baud_rate(serial_port_intel_x64::baud_rate_115200);
    this->expect_true(serial->baud_rate() == serial_port_intel_x64::baud_rate_115200);
}

void
serial_ut::test_serial_set_data_bits_success()
{
    auto serial = std::make_unique<serial_port_intel_x64>();

    serial->set_data_bits(serial_port_intel_x64::char_length_5);
    this->expect_true(serial->data_bits() == serial_port_intel_x64::char_length_5);
    serial->set_data_bits(serial_port_intel_x64::char_length_6);
    this->expect_true(serial->data_bits() == serial_port_intel_x64::char_length_6);
    serial->set_data_bits(serial_port_intel_x64::char_length_7);
    this->expect_true(serial->data_bits() == serial_port_intel_x64::char_length_7);
    serial->set_data_bits(serial_port_intel_x64::char_length_8);
    this->expect_true(serial->data_bits() == serial_port_intel_x64::char_length_8);
}

void
serial_ut::test_serial_set_data_bits_success_extra_bits()
{
    auto serial = std::make_unique<serial_port_intel_x64>();

    auto bits = serial_port_intel_x64::DEFAULT_DATA_BITS | ~serial_intel_x64::line_control_data_mask;
    serial->set_data_bits(static_cast<serial_port_intel_x64::data_bits_t>(bits));

    this->expect_true(serial->data_bits() == serial_port_intel_x64::DEFAULT_DATA_BITS);
    this->expect_true(serial->stop_bits() == serial_port_intel_x64::DEFAULT_STOP_BITS);
    this->expect_true(serial->parity_bits() == serial_port_intel_x64::DEFAULT_PARITY_BITS);
}

void
serial_ut::test_serial_set_stop_bits_success()
{
    auto serial = std::make_unique<serial_port_intel_x64>();

    serial->set_stop_bits(serial_port_intel_x64::stop_bits_1);
    this->expect_true(serial->stop_bits() == serial_port_intel_x64::stop_bits_1);
    serial->set_stop_bits(serial_port_intel_x64::stop_bits_2);
    this->expect_true(serial->stop_bits() == serial_port_intel_x64::stop_bits_2);
}

void
serial_ut::test_serial_set_stop_bits_success_extra_bits()
{
    auto serial = std::make_unique<serial_port_intel_x64>();

    auto bits = serial_port_intel_x64::DEFAULT_STOP_BITS | ~serial_intel_x64::line_control_stop_mask;
    serial->set_stop_bits(static_cast<serial_port_intel_x64::stop_bits_t>(bits));

    this->expect_true(serial->data_bits() == serial_port_intel_x64::DEFAULT_DATA_BITS);
    this->expect_true(serial->stop_bits() == serial_port_intel_x64::DEFAULT_STOP_BITS);
    this->expect_true(serial->parity_bits() == serial_port_intel_x64::DEFAULT_PARITY_BITS);
}

void
serial_ut::test_serial_set_parity_bits_success()
{
    auto serial = std::make_unique<serial_port_intel_x64>();

    serial->set_parity_bits(serial_port_intel_x64::parity_none);
    this->expect_true(serial->parity_bits() == serial_port_intel_x64::parity_none);
    serial->set_parity_bits(serial_port_intel_x64::parity_odd);
    this->expect_true(serial->parity_bits() == serial_port_intel_x64::parity_odd);
    serial->set_parity_bits(serial_port_intel_x64::parity_even);
    this->expect_true(serial->parity_bits() == serial_port_intel_x64::parity_even);
    serial->set_parity_bits(serial_port_intel_x64::parity_mark);
    this->expect_true(serial->parity_bits() == serial_port_intel_x64::parity_mark);
    serial->set_parity_bits(serial_port_intel_x64::parity_space);
    this->expect_true(serial->parity_bits() == serial_port_intel_x64::parity_space);
}

void
serial_ut::test_serial_set_parity_bits_success_extra_bits()
{
    auto serial = std::make_unique<serial_port_intel_x64>();

    auto bits = serial_port_intel_x64::DEFAULT_PARITY_BITS | ~serial_intel_x64::line_control_parity_mask;
    serial->set_parity_bits(static_cast<serial_port_intel_x64::parity_bits_t>(bits));

    this->expect_true(serial->data_bits() == serial_port_intel_x64::DEFAULT_DATA_BITS);
    this->expect_true(serial->stop_bits() == serial_port_intel_x64::DEFAULT_STOP_BITS);
    this->expect_true(serial->parity_bits() == serial_port_intel_x64::DEFAULT_PARITY_BITS);
}

void
serial_ut::test_serial_write_character()
{
    g_ports[serial_intel_x64::DEFAULT_COM_PORT + serial_intel_x64::line_status_reg] = 0xFF;

    auto serial = std::make_unique<serial_port_intel_x64>();
    serial->write('c');
}

void
serial_ut::test_serial_write_string()
{
    g_ports[serial_intel_x64::DEFAULT_COM_PORT + serial_intel_x64::line_status_reg] = 0xFF;

    auto serial = std::make_unique<serial_port_intel_x64>();
    serial->write("hello world");
}
