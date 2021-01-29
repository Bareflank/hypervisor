/**
 * @copyright
 * Copyright (C) 2020 Assured Information Security, Inc.
 *
 * @copyright
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * @copyright
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * @copyright
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <constants.h>
#include <intrinsic_inb.h>
#include <intrinsic_outb.h>
#include <types.h>

/** @brief defines the line status register  */
#define SERIAL_PORT ((uint16_t)HYPERVISOR_SERIAL_PORT)

/** @brief defines the baud rate (lo) register  */
#define BLR ((uint16_t)0U)
/** @brief defines the baud rate (hi) register  */
#define BHR ((uint16_t)1U)
/** @brief defines the interrupt enable register  */
#define IER ((uint16_t)1U)
/** @brief defines the FIFO control register  */
#define FCR ((uint16_t)2U)
/** @brief defines the line control register  */
#define LCR ((uint16_t)3U)

/** @brief defines the FIFO control register enable FIFO bit  */
#define FCR_ENABLE_FIFO ((uint8_t)(((uint8_t)1) << ((uint8_t)0)))
/** @brief defines the FIFO control register clear receive FIFO bit  */
#define FCR_CLEAR_RECEIVE_FIFO ((uint8_t)(((uint8_t)1) << ((uint8_t)1)))
/** @brief defines the FIFO control register clear transmit FIFO bit  */
#define FCR_CLEAR_TRANSMIT_FIFO ((uint8_t)(((uint8_t)1) << ((uint8_t)2)))

/**
 * <!-- description -->
 *   @brief Writes a byte to the requested serial port register.
 *
 * <!-- inputs/outputs -->
 *   @param reg the serial port register to write to
 *   @param val the byte to write to the requested serial port register
 */
static void
serial_outb(uint16_t reg, uint8_t const val)
{
    reg += SERIAL_PORT;
    intrinsic_outb(reg, val);
}

/**
 * <!-- description -->
 *   @brief Initializes the serial port for use
 */
void
serial_init(void)
{
    uint8_t bits = ((uint8_t)0);

    bits |= FCR_ENABLE_FIFO;
    bits |= FCR_CLEAR_RECEIVE_FIFO;
    bits |= FCR_CLEAR_TRANSMIT_FIFO;

    serial_outb(LCR, 0x80);
    serial_outb(BLR, 0x01);
    serial_outb(BHR, 0x00);
    serial_outb(LCR, 0x03);
    serial_outb(IER, 0x00);
    serial_outb(FCR, bits);
}
