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

#include <serial/serial_port_intel_x64.h>

serial_port_intel_x64::serial_port_intel_x64(const std::shared_ptr<intrinsics_intel_x64> &intrinsics,
        uint16_t port) noexcept :
    m_port(port),
    m_intrinsics(intrinsics)
{
    if (!m_intrinsics)
        m_intrinsics = std::make_shared<intrinsics_intel_x64>();
}

serial_port_intel_x64 *
serial_port_intel_x64::instance(const std::shared_ptr<intrinsics_intel_x64> &intrinsics) noexcept
{
    static auto serial = std::shared_ptr<serial_port_intel_x64>();

    if (!serial)
    {
        serial = std::make_shared<serial_port_intel_x64>(intrinsics);
        serial->init();
    }

    return serial.get();
}

void
serial_port_intel_x64::init()
{
    uint8_t bits = 0;

    this->disable_dlab();

    bits |= FIFO_CONTROL_ENABLE_FIFOS;
    bits |= FIFO_CONTROL_CLEAR_RECIEVE_FIFO;
    bits |= FIFO_CONTROL_CLEAR_TRANSMIT_FIFO;

    m_intrinsics->write_portio_8(m_port + INTERRUPT_EN_REG, 0x00);
    m_intrinsics->write_portio_8(m_port + FIFO_CONTROL_REG, bits);

    this->set_baud_rate(DEFAULT_BAUD_RATE);
    this->set_data_bits(DEFAULT_DATA_BITS);
    this->set_stop_bits(DEFAULT_STOP_BITS);
    this->set_parity_bits(DEFAULT_PARITY_BITS);
}

void
serial_port_intel_x64::set_baud_rate(baud_rate_t rate) noexcept
{
    if (rate == 0)
        rate = DEFAULT_BAUD_RATE;

    auto lsb = (rate & 0x000000FF) >> 0;
    auto msb = (rate & 0x0000FF00) >> 8;

    this->enable_dlab();

    m_intrinsics->write_portio_8(m_port + BAUD_RATE_LO_REG, lsb);
    m_intrinsics->write_portio_8(m_port + BAUD_RATE_HI_REG, msb);

    this->disable_dlab();
}

serial_port_intel_x64::baud_rate_t
serial_port_intel_x64::baud_rate() const noexcept
{
    this->enable_dlab();

    uint16_t lsb = m_intrinsics->read_portio_8(m_port + BAUD_RATE_LO_REG);
    uint16_t msb = m_intrinsics->read_portio_8(m_port + BAUD_RATE_HI_REG);

    this->disable_dlab();

    switch ((msb << 8) | lsb)
    {
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
        case baud_rate_115200:
            return baud_rate_115200;
        default:
            return baud_rate_unknown;
    }
}

void
serial_port_intel_x64::set_data_bits(data_bits_t bits) noexcept
{
    auto reg = m_intrinsics->read_portio_8(m_port + LINE_CONTROL_REG);

    reg &= ~LINE_CONTROL_DATA_MASK;
    reg |= (bits & LINE_CONTROL_DATA_MASK);

    m_intrinsics->write_portio_8(m_port + LINE_CONTROL_REG, reg);
}

serial_port_intel_x64::data_bits_t
serial_port_intel_x64::data_bits() const noexcept
{
    auto reg = m_intrinsics->read_portio_8(m_port + LINE_CONTROL_REG);

    switch (reg & LINE_CONTROL_DATA_MASK)
    {
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
serial_port_intel_x64::set_stop_bits(stop_bits_t bits) noexcept
{
    auto reg = m_intrinsics->read_portio_8(m_port + LINE_CONTROL_REG);

    reg &= ~LINE_CONTROL_STOP_MASK;
    reg |= (bits & LINE_CONTROL_STOP_MASK);

    m_intrinsics->write_portio_8(m_port + LINE_CONTROL_REG, reg);
}

serial_port_intel_x64::stop_bits_t
serial_port_intel_x64::stop_bits() const noexcept
{
    auto reg = m_intrinsics->read_portio_8(m_port + LINE_CONTROL_REG);

    switch (reg & LINE_CONTROL_STOP_MASK)
    {
        case stop_bits_1:
            return stop_bits_1;
        default:
            return stop_bits_2;
    }
}

void
serial_port_intel_x64::set_parity_bits(parity_bits_t bits) noexcept
{
    auto reg = m_intrinsics->read_portio_8(m_port + LINE_CONTROL_REG);

    reg &= ~LINE_CONTROL_PARITY_MASK;
    reg |= (bits & LINE_CONTROL_PARITY_MASK);

    m_intrinsics->write_portio_8(m_port + LINE_CONTROL_REG, reg);
}

serial_port_intel_x64::parity_bits_t
serial_port_intel_x64::parity_bits() const noexcept
{
    auto reg = m_intrinsics->read_portio_8(m_port + LINE_CONTROL_REG);

    switch (reg & LINE_CONTROL_PARITY_MASK)
    {
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
serial_port_intel_x64::write(char c) noexcept
{
    while (line_status_empty_transmitter() == false);

    m_intrinsics->write_portio_8(m_port, c);
}

void
serial_port_intel_x64::write(const std::string &str) noexcept
{
    for (auto c : str)
        write(c);
}

void
serial_port_intel_x64::enable_dlab() const noexcept
{
    auto reg = m_intrinsics->read_portio_8(m_port + LINE_CONTROL_REG);
    reg |= DLAB;
    m_intrinsics->write_portio_8(m_port + LINE_CONTROL_REG, reg);
}

void
serial_port_intel_x64::disable_dlab() const noexcept
{
    auto reg = m_intrinsics->read_portio_8(m_port + LINE_CONTROL_REG);
    reg &= ~DLAB;
    m_intrinsics->write_portio_8(m_port + LINE_CONTROL_REG, reg);
}

bool
serial_port_intel_x64::line_status_empty_transmitter() const noexcept
{
    return (m_intrinsics->read_portio_8(m_port + LINE_STATUS_REG) &
            LINE_STATUS_EMPTY_TRANSMITTER) != 0;
}
