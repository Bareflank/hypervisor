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

#include <bfgsl.h>
#include <serial/serial_port_ns16550a.h>

using namespace intrinsics;
using namespace portio;
using namespace serial_ns16550a;

serial_port_ns16550a::serial_port_ns16550a(serial_port_ns16550a::port_type port) noexcept :
    m_port(port)
{
    serial_port_ns16550a::value_type bits = 0;

    this->disable_dlab();

    bits |= fifo_control_enable_fifos;
    bits |= fifo_control_clear_recieve_fifo;
    bits |= fifo_control_clear_transmit_fifo;

    portio::outb(gsl::narrow_cast<port_addr_type>(m_port + interrupt_en_reg), gsl::narrow_cast<port_8bit_type>(0x00));
    portio::outb(gsl::narrow_cast<port_addr_type>(m_port + fifo_control_reg), gsl::narrow_cast<port_8bit_type>(bits));

    this->set_baud_rate(DEFAULT_BAUD_RATE);
    this->set_data_bits(DEFAULT_DATA_BITS);
    this->set_stop_bits(DEFAULT_STOP_BITS);
    this->set_parity_bits(DEFAULT_PARITY_BITS);
}

serial_port_ns16550a *
serial_port_ns16550a::instance() noexcept
{
    static serial_port_ns16550a serial{};
    return &serial;
}

void
serial_port_ns16550a::set_baud_rate(baud_rate_t rate) noexcept
{
    auto lsb = (rate & 0x000000FF) >> 0;
    auto msb = (rate & 0x0000FF00) >> 8;

    this->enable_dlab();

    portio::outb(gsl::narrow_cast<port_addr_type>(m_port + baud_rate_lo_reg), gsl::narrow_cast<port_8bit_type>(lsb));
    portio::outb(gsl::narrow_cast<port_addr_type>(m_port + baud_rate_hi_reg), gsl::narrow_cast<port_8bit_type>(msb));

    this->disable_dlab();
}

serial_port_ns16550a::baud_rate_t
serial_port_ns16550a::baud_rate() const noexcept
{
    this->enable_dlab();

    auto lsb = portio::inb(gsl::narrow_cast<port_addr_type>(m_port + baud_rate_lo_reg));
    auto msb = portio::inb(gsl::narrow_cast<port_addr_type>(m_port + baud_rate_hi_reg));

    this->disable_dlab();

    switch ((msb << 8) | lsb) {
        case baud_rate_50:
            return baud_rate_50;
        case baud_rate_75:
            return baud_rate_75;
        case baud_rate_110:
            return baud_rate_110;
        case baud_rate_150:
            return baud_rate_150;
        case baud_rate_300:
            return baud_rate_300;
        case baud_rate_600:
            return baud_rate_600;
        case baud_rate_1200:
            return baud_rate_1200;
        case baud_rate_1800:
            return baud_rate_1800;
        case baud_rate_2000:
            return baud_rate_2000;
        case baud_rate_2400:
            return baud_rate_2400;
        case baud_rate_3600:
            return baud_rate_3600;
        case baud_rate_4800:
            return baud_rate_4800;
        case baud_rate_7200:
            return baud_rate_7200;
        case baud_rate_9600:
            return baud_rate_9600;
        case baud_rate_19200:
            return baud_rate_19200;
        case baud_rate_38400:
            return baud_rate_38400;
        case baud_rate_57600:
            return baud_rate_57600;
        default:
            return baud_rate_115200;
    }
}

void
serial_port_ns16550a::set_data_bits(data_bits_t bits) noexcept
{
    auto reg = portio::inb(gsl::narrow_cast<port_addr_type>(m_port + line_control_reg));

    reg = reg & gsl::narrow_cast<decltype(reg)>(~line_control_data_mask);
    reg = reg | gsl::narrow_cast<decltype(reg)>(bits & line_control_data_mask);

    portio::outb(gsl::narrow_cast<port_addr_type>(m_port + line_control_reg), reg);
}

serial_port_ns16550a::data_bits_t
serial_port_ns16550a::data_bits() const noexcept
{
    auto reg = portio::inb(gsl::narrow_cast<port_addr_type>(m_port + line_control_reg));

    switch (reg & line_control_data_mask) {
        case char_length_5:
            return char_length_5;
        case char_length_6:
            return char_length_6;
        case char_length_7:
            return char_length_7;
        default:
            return char_length_8;
    }
}

void
serial_port_ns16550a::set_stop_bits(stop_bits_t bits) noexcept
{
    auto reg = portio::inb(gsl::narrow_cast<port_addr_type>(m_port + line_control_reg));

    reg = reg & gsl::narrow_cast<decltype(reg)>(~line_control_stop_mask);
    reg = reg | gsl::narrow_cast<decltype(reg)>(bits & line_control_stop_mask);

    portio::outb(gsl::narrow_cast<port_addr_type>(m_port + line_control_reg), reg);
}

serial_port_ns16550a::stop_bits_t
serial_port_ns16550a::stop_bits() const noexcept
{
    auto reg = portio::inb(gsl::narrow_cast<port_addr_type>(m_port + line_control_reg));

    switch (reg & line_control_stop_mask) {
        case stop_bits_1:
            return stop_bits_1;
        default:
            return stop_bits_2;
    }
}

void
serial_port_ns16550a::set_parity_bits(parity_bits_t bits) noexcept
{
    auto reg = portio::inb(gsl::narrow_cast<port_addr_type>(m_port + line_control_reg));

    reg = reg & gsl::narrow_cast<decltype(reg)>(~line_control_parity_mask);
    reg = reg | gsl::narrow_cast<decltype(reg)>(bits & line_control_parity_mask);

    portio::outb(gsl::narrow_cast<port_addr_type>(m_port + line_control_reg), reg);
}

serial_port_ns16550a::parity_bits_t
serial_port_ns16550a::parity_bits() const noexcept
{
    auto reg = portio::inb(gsl::narrow_cast<port_addr_type>(m_port + line_control_reg));

    switch (reg & line_control_parity_mask) {
        case parity_odd:
            return parity_odd;
        case parity_even:
            return parity_even;
        case parity_mark:
            return parity_mark;
        case parity_space:
            return parity_space;
        default:
            return parity_none;
    }
}

void
serial_port_ns16550a::write(char c) noexcept
{
    while (!get_line_status_empty_transmitter())
    { }

    portio::outb(m_port, gsl::narrow_cast<port_8bit_type>(c));
}

void
serial_port_ns16550a::write(const std::string &str) noexcept
{
    for (auto c : str) {
        this->write(c);
    }
}

void
serial_port_ns16550a::write(const char *str, size_t len) noexcept
{
    gsl::cstring_span<> span(str, gsl::narrow_cast<std::ptrdiff_t>(len));

    for (auto c : span) {
        this->write(c);
    }
}

void
serial_port_ns16550a::enable_dlab() const noexcept
{
    auto reg = portio::inb(gsl::narrow_cast<port_addr_type>(m_port + line_control_reg));
    reg = reg | gsl::narrow_cast<decltype(reg)>(dlab);
    portio::outb(gsl::narrow_cast<port_addr_type>(m_port + line_control_reg), reg);
}

void
serial_port_ns16550a::disable_dlab() const noexcept
{
    auto reg = portio::inb(gsl::narrow_cast<port_addr_type>(m_port + line_control_reg));
    reg = reg & gsl::narrow_cast<decltype(reg)>(~(dlab));
    portio::outb(gsl::narrow_cast<port_addr_type>(m_port + line_control_reg), reg);
}

bool
serial_port_ns16550a::get_line_status_empty_transmitter() const noexcept
{
    return (portio::inb(gsl::narrow_cast<port_addr_type>(m_port + line_status_reg)) & line_status_empty_transmitter) != 0;
}
