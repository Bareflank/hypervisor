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

#include <loader_intrinsics.h>
#include <loader_types.h>
#include <loader.h>

#define baud_rate_lo_reg ((uint16_t)0U)
#define baud_rate_hi_reg ((uint16_t)1U)
#define interrupt_en_reg ((uint16_t)1U)
#define fifo_control_reg ((uint16_t)2U)
#define line_control_reg ((uint16_t)3U)
#define line__status_reg ((uint16_t)5U)

#define fifo_control_enable_fifos ((uint8_t)1U << 0U)
#define fifo_control_clear_recieve_fifo ((uint8_t)1U << 1U)
#define fifo_control_clear_transmit_fifo ((uint8_t)1U << 2U)

static uint8_t
serial_inb(uint16_t addr)
{
    addr += 0x03F8U;
    return arch_inb(addr);
}

static void
serial_outb(uint16_t addr, uint8_t const data)
{
    addr += 0x03F8U;
    arch_outb(addr, data);
}

static uint8_t
serial_is_transmit_empty(void)
{
    return serial_inb(line__status_reg) & (1U << 5U);
}

void
arch_init_serial(void)
{
    uint8_t bits = 0U;
    bits |= fifo_control_enable_fifos;
    bits |= fifo_control_clear_recieve_fifo;
    bits |= fifo_control_clear_transmit_fifo;

    serial_outb(line_control_reg, 0x80);
    serial_outb(baud_rate_lo_reg, 0x01);
    serial_outb(baud_rate_hi_reg, 0x00);
    serial_outb(line_control_reg, 0x03);
    serial_outb(interrupt_en_reg, 0x00);
    serial_outb(fifo_control_reg, bits);
}

void
arch_write_serial(char const *const str)
{
    int i;
    while (serial_is_transmit_empty() == 0)
        ;

    for (i = 0; str[i] != '\0'; ++i) {
        serial_outb(0, str[i]);
    }
}
