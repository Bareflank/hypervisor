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

#include <serial/serial_port_x86.h>

struct divisor_rate divisor_table[] =
{
    {50, 0x900},
    {75, 0x600},
    {110, 0x417},
    {150, 0x300},
    {300, 0x180},
    {600, 0xC0},
    {1200, 0x60},
    {1800, 0x40},
    {2000, 0x3A},
    {2400, 0x30},
    {3600, 0x20},
    {4800, 0x18},
    {7200, 0x10},
    {9600, 0xC},
    {19200, 0x6},
    {38400, 0x3},
    {57600, 0x2},
    {115200, 0x1},
    {0, 0},
};

struct parity_bits parity_table[] =
{
    { NONE, 0x00},
    { ODD,  0x08},
    { EVEN, 0x18},
    { MARK, 0x28},
    { SPACE, 0x38},
    { PARITY_MAX, 0x00 },
};

struct data_bits data_size_table[] =
{
    { 5, 0x00 },
    { 6, 0x01 },
    { 7, 0x02 },
    { 8, 0x03 },
    { 0, 0x00 },
};

serial_port_x86::serial_port_x86(uint8_t port, uint32_t baud, uint8_t data_size, PARITY_MODE parity, uint8_t stop_bits)
{
    switch (port)
    {
        case 1:
        {
            m_port = COM1_IO_PORT;
            break;
        }
        case 2:
        {
            m_port = COM2_IO_PORT;
            break;
        }
        case 3:
        {

            m_port = COM3_IO_PORT;
            break;
        }
        case 4:
        {
            m_port = COM4_IO_PORT;
            break;
        }
        default:
        {
            // Error case, not a valid port
            m_port = 0xFFFF;
            return;
        }
    }

    m_baud = baud;
    m_parity = parity;
    m_data_size = data_size;
    m_stop_bits = stop_bits;
}

serial_port_x86::~serial_port_x86(void)
{

}

serial::err
serial_port_x86::open(void)
{
    disable_interrupt_mode();

    set_baud_rate(m_baud);
    set_parity_mode(m_parity);
    set_data_size(m_data_size);
    set_stop_bits(m_stop_bits);
    enable_fifo();

    enable_interrupt_mode(m_interrupt_mode);

    return serial::success;
}

serial::err
serial_port_x86::close(void)
{
    return serial::success;
}

serial::err
serial_port_x86::set_baud_rate(uint32_t baud)
{
    if (baud > MAX_BAUD_RATE)
    {
        m_baud = MAX_BAUD_RATE;
    }

    if (baud < MIN_BAUD_RATE)
    {
        m_baud = MIN_BAUD_RATE;
    }

    m_baud = baud;

    // Set the DLAB bit, so we can configure the baud rate
    // of this port.
    m_intrinsics.write_portio_8(m_port + FCR_OFFSET, DLAB);

    // Set the baud rate
    m_intrinsics.write_portio_8(m_port + DL_LSB_OFFSET, baud_to_lo_divisor(m_baud));
    m_intrinsics.write_portio_8(m_port + DL_MSB_OFFSET, baud_to_hi_divisor(m_baud));

    return serial::success;
}

uint32_t
serial_port_x86::baud_rate(void)
{
    return m_baud;
}

serial::err
serial_port_x86::set_parity_mode(PARITY_MODE parity)
{
    uint8_t i = 0;
    uint8_t data_bits = 0;

    m_parity = parity;

    data_bits = m_intrinsics.read_portio_8(m_port + LCR_OFFSET);

    while (parity_table[i].mode < PARITY_MAX)
    {
        if (m_parity == parity_table[i].mode)
        {
            // Clear the data bits, leave the rest intact
            data_bits &= PARITY_MASK;

            // Set the new data size
            data_bits |= parity_table[i].parity_bits;
            break;
        }

        i++;
    }

    m_intrinsics.write_portio_8(m_port + LCR_OFFSET, data_bits);

    return serial::success;
}

uint8_t
serial_port_x86::parity_mode(void)
{
    return m_parity;
}

serial::err
serial_port_x86::set_data_size(uint8_t size)
{
    uint8_t i = 0;
    uint8_t data_bits = 0;

    // Update our internal storage of size
    m_data_size = size;

    data_bits = m_intrinsics.read_portio_8(m_port + LCR_OFFSET);

    while (data_size_table[i].data_size != 0)
    {
        if (size == data_size_table[i].data_size)
        {
            // Clear the data bits, leave the rest intact
            data_bits &= DATA_SIZE_MASK;

            // Set the new data size
            data_bits |= data_size_table[i].data_bits;
            break;
        }

        i++;
    }

    m_intrinsics.write_portio_8(m_port + LCR_OFFSET, data_bits);

    return serial::success;
}

uint8_t
serial_port_x86::data_size(void)
{
    return m_data_size;
}

serial::err
serial_port_x86::set_stop_bits(uint8_t bits)
{
    uint8_t stop_bits = 0;

    stop_bits = m_intrinsics.read_portio_8(m_port + LCR_OFFSET);

    // Clear the stop bits, leave the rest intact
    stop_bits &= 0xFB;

    if (bits != 1)
    {
        // If it isn't 1 stop bit, then it's either
        // 1.5 or 2 stop bits.
        stop_bits |= 0x04;
    }

    m_intrinsics.write_portio_8(m_port + LCR_OFFSET, stop_bits);

    return serial::success;
}

uint8_t
serial_port_x86::stop_bits(void)
{
    return m_stop_bits;
}

serial::err
serial_port_x86::enable_interrupt_mode(uint8_t interrupts)
{
    m_interrupt_mode = interrupts;

    // Enable interrupts
    m_intrinsics.write_portio_8(m_port + IER_OFFSET, m_interrupt_mode);

    return serial::success;
}

void
serial_port_x86::disable_interrupt_mode(void)
{
    m_interrupt_mode = 0;

    // Disable interrupts
    m_intrinsics.write_portio_8(m_port + IER_OFFSET, m_interrupt_mode);
}

uint8_t
serial_port_x86::interrupt_mode(void)
{
    return m_interrupt_mode;
}

serial::err
serial_port_x86::enable_fifo(void)
{
    m_fifo_enabled = true;
    uint8_t value = m_intrinsics.read_portio_8(m_port + FCR_OFFSET);

    value |= FCR_MASK;

    m_intrinsics.write_portio_8(m_port + FCR_OFFSET, value);

    return serial::success;
}

void
serial_port_x86::disable_fifo(void)
{
    m_fifo_enabled = false;
    uint8_t value = m_intrinsics.read_portio_8(m_port + FCR_OFFSET);

    value &= ~FCR_MASK;

    m_intrinsics.write_portio_8(m_port + FCR_OFFSET, value);
}

bool
serial_port_x86::fifo(void)
{
    return m_fifo_enabled;
}

void
serial_port_x86::write(char c)
{
    m_intrinsics.write_portio_8(m_port, c);
}

void
serial_port_x86::write(const char *str)
{
    if (str == 0)
        return;

    while (*str)
        write(*str++);
}

void
serial_port_x86::write(const char *str, int64_t len)
{
    if (str == 0)
        return;

    for (auto i = 0; i < len; i++)
        write(str[i]);
}

uint8_t
serial_port_x86::read(void)
{
    return m_intrinsics.read_portio_8(m_port);
}

// Note:
// The double not'ing is to ensure the integer is
// treated as a proper bool.

bool
serial_port_x86::data_ready(void)
{
    return !!(m_intrinsics.read_portio_8(m_port + LSR_OFFSET) & LSR_DR);
}

bool
serial_port_x86::overrun_error(void)
{
    return !!(m_intrinsics.read_portio_8(m_port + LSR_OFFSET) & LSR_OE);
}

bool
serial_port_x86::parity_error(void)
{
    return !!(m_intrinsics.read_portio_8(m_port + LSR_OFFSET) & LSR_PE);
}

bool
serial_port_x86::framing_error(void)
{
    return !!(m_intrinsics.read_portio_8(m_port + LSR_OFFSET) & LSR_FE);
}

bool
serial_port_x86::break_indicator(void)
{
    return !!(m_intrinsics.read_portio_8(m_port + LSR_OFFSET) & LSR_BI);
}

bool
serial_port_x86::transmit_hold_register_empty(void)
{
    return !!(m_intrinsics.read_portio_8(m_port + LSR_OFFSET) & LSR_THRE);
}

bool
serial_port_x86::transmitter_empty(void)
{
    return !!(m_intrinsics.read_portio_8(m_port + LSR_OFFSET) & LSR_TEMT);
}

bool
serial_port_x86::error_byte_rx_fifo(void)
{
    return !!(m_intrinsics.read_portio_8(m_port + LSR_OFFSET) & LSR_EBIF);
}

uint8_t
serial_port_x86::baud_to_lo_divisor(uint32_t baud)
{
    uint8_t i = 0;

    while (divisor_table[i].baud_rate != 0)
    {
        if (divisor_table[i].baud_rate == baud)
        {
            return 0xFF & divisor_table[i].divisor;
        }

        i++;
    }

    return 0;
}

uint8_t
serial_port_x86::baud_to_hi_divisor(uint32_t baud)
{
    uint8_t i = 0;

    while (divisor_table[i].baud_rate != 0)
    {
        if (divisor_table[i].baud_rate == baud)
        {
            return (0xFF00 & divisor_table[i].divisor) >> 8;
        }

        i++;
    }

    return 0;
}

