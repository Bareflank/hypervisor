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

/** @brief defines the line status register  */
#define LSR ((uint16_t)5)
/** @brief defines the transmit FIFO empty bit in the LSR  */
#define LSR_TRANSMIT_FIFO_EMPTY ((uint8_t)(((uint8_t)1) << ((uint8_t)5)))

/**
 * <!-- description -->
 *   @brief Reads a byte from the requested serial port register.
 *
 * <!-- inputs/outputs -->
 *   @param reg the serial port register to read from
 *   @return the data read from the requested serial port register
 */
static uint8_t
serial_inb(uint16_t reg)
{
    reg += SERIAL_PORT;
    return intrinsic_inb(reg);
}

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
 *   @brief Writes a string to the serial port. Note that you must initialize
 *     the serial port before you can use it.
 *
 * <!-- inputs/outputs -->
 *   @param str the string to write to the serial port.
 */
void
serial_write(char const *const str)
{
    int i;

    while ((serial_inb(LSR) & LSR_TRANSMIT_FIFO_EMPTY) == 0) {
    }

    for (i = 0; str[i] != '\0'; ++i) {
        serial_outb(0, str[i]);
    }
}
