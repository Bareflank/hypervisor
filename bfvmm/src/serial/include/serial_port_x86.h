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

#ifndef SERIAL_X86__H
#define SERIAL_X86__H

#include <port_io.h>
#include <serial_port.h>
/**
 *  @file    serial.h
 *  @author  Brendan Kerrigan
 *  @date    2015/11/02
 *  @version 0.1
 *
 *  @brief Provide serial port access
 *
 *  @section DESCRIPTION
 *
 *  Provides a wrapper class around a serial port, which is
 *  accessed via port I/O.
 *
 *  Useful information:
 *  http://wiki.osdev.org/Serial_Ports
 *  http://www.sci.muni.cz/docs/pc/serport.txt
 *
 */

#define COM1_IO_PORT 0x3f8
#define COM2_IO_PORT 0x2f8
#define COM3_IO_PORT 0x3e8
#define COM4_IO_PORT 0x2e8

/* Limits */
#define MIN_DATA_SIZE 5
#define MAX_DATA_SIZE 8

#define MIN_STOP_BITS 2
#define MAX_STOP_BITS 2

#define MIN_INTERRUPT 0
#define MAX_INTERRUPT 15

/* Baud rate defines and lookup tables */
#define MIN_BAUD_RATE 50
#define MAX_BAUD_RATE 115200

struct __divisor_rate
{
    uint32_t baud_rate;
    uint16_t divisor;
};

extern struct __divisor_rate divisor_table[];

/* Parity defines and lookup tables */

#define PARITY_MASK             0xC7

struct __parity_bits
{
    PARITY_MODE mode;
    uint8_t parity_bits;
};

extern struct __parity_bits parity_table[];

/* Data size defines and lookup tables */
#define DATA_SIZE_MASK          0xFC

struct __data_bits
{
    uint8_t data_size;
    uint8_t data_bits;
};

extern struct __data_bits data_size_table[];

/* Receive buffer register */
#define RBR_OFFSET              0x00
/* Transmit hold register */
#define THR_OFFSET              0x00
/* Interrupt Enable register */
#define IER_OFFSET              0x01
/* Divisor latch registers */
#define DL_LSB_OFFSET           0x00
#define DL_MSB_OFFSET           0x01
/* Interrupt ID register */
#define IID_OFFSET              0x02
/* FIFO Control register */
#define FCR_OFFSET              0x02
#define FCR_MASK                (1<<0)

/* Line control register */
#define LCR_OFFSET              0x03
/* Modem control register */
#define MCR_OFFSET              0x04

/****************************************
 *   Line status register               *
 ****************************************/
// IO Offset
#define LSR_OFFSET              0x05
// Data ready flag
#define LSR_DR                  (1<<0)
// Overrun error flag
#define LSR_OE                  (1<<1)
// Parity error flag
#define LSR_PE                  (1<<2)
// Frame error flag
#define LSR_FE                  (1<<3)
// Break indicator flag
#define LSR_BI                  (1<<4)
// Transmit hold register empty flag
#define LSR_THRE                (1<<5)
// Transmit empty flag
#define LSR_TEMT                (1<<6)
// Error byte in FIFO
#define LSR_EBIF                (1<<7)


/* Modem status register */
#define MSR_OFFSET              0x06
#define SCRATCH_REG_OFFSET      0x07

/* Divisor latch access bit

    This is set in the LCR to mux
    the operational mode of the first
    two registers.
*/
#define DLAB                    ((uint8_t)0x80)

#define DATA_SIZE(x) (x-MIN_DATA_SIZE)

class serial_port_x86 : public serial_port
{

public:
    serial_port_x86(port_io &io, uint8_t port = 1, uint32_t baud = DEFAULT_BAUD_RATE, uint8_t data_bits = 8,
                    PARITY_MODE parity = NONE, uint8_t stop_bits = 1);
    ~serial_port_x86(void);

    serial::errno open(void);
    serial::errno close(void);

    serial::errno set_baud_rate(uint32_t baud);
    uint32_t baud_rate(void);

    serial::errno set_parity_mode(PARITY_MODE parity);
    uint8_t parity_mode(void);

    serial::errno set_data_size(uint8_t bits);
    uint8_t data_size(void);

    serial::errno set_stop_bits(uint8_t bits);
    uint8_t stop_bits(void);

    serial::errno enable_interrupt_mode(uint8_t mode);
    void disable_interrupt_mode(void);
    uint8_t interrupt_mode(void);

    serial::errno enable_fifo(void);
    void disable_fifo(void);
    bool fifo(void);

    void write(uint8_t);
    void write(int8_t *bytes);
    uint8_t read(void);

    /* LSR methods */
    bool data_ready(void);
    bool overrun_error(void);
    bool parity_error(void);
    bool framing_error(void);
    bool break_indicator(void);
    bool transmit_hold_register_empty(void);
    bool transmitter_empty(void);
    bool error_byte_rx_fifo(void);

    serial_port &operator<<(uint8_t value) { write(value); return *this; }

private:
    // Get appropriate divisor for desired baud
    uint8_t baud_to_lo_divisor(uint32_t baud);
    uint8_t baud_to_hi_divisor(uint32_t baud);

    // Base IO port address
    uint16_t m_port;
    port_io &m_port_io;
};

#endif // SERIAL_PORT__H
