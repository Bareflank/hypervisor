//
// Copyright (C) 2019 Assured Information Security, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include <debug/serial/serial_ns16550a.h>
#include <bfsupport.h>

namespace bfvmm
{

constexpr const uint8_t dlab = 1U << 7;

constexpr const uint16_t baud_rate_lo_reg = 0U;
constexpr const uint16_t baud_rate_hi_reg = 1U;
constexpr const uint16_t interrupt_en_reg = 1U;
constexpr const uint16_t fifo_control_reg = 2U;
constexpr const uint16_t line_control_reg = 3U;
constexpr const uint16_t line_status_reg = 5U;

constexpr const uint8_t fifo_control_enable_fifos = 1U << 0;
constexpr const uint8_t fifo_control_clear_recieve_fifo = 1U << 1;
constexpr const uint8_t fifo_control_clear_transmit_fifo = 1U << 2;

constexpr const uint8_t line_status_empty_transmitter = 1U << 5;

constexpr const uint8_t line_control_data_mask = 0x03;
constexpr const uint8_t line_control_stop_mask = 0x04;
constexpr const uint8_t line_control_parity_mask = 0x38;

serial_ns16550a::serial_ns16550a(uintptr_t port) noexcept
{
#ifdef BF_AARCH64
    if (port == DEFAULT_COM_PORT) {
        auto platform_info = get_platform_info();
        port = platform_info->serial_address;
    }
#endif

    m_addr = port;

    this->disable_dlab();

    uint8_t bits = 0U;
    bits |= fifo_control_enable_fifos;
    bits |= fifo_control_clear_recieve_fifo;
    bits |= fifo_control_clear_transmit_fifo;

    outb(interrupt_en_reg, 0x00);
    outb(fifo_control_reg, bits);

    this->set_baud_rate(DEFAULT_BAUD_RATE);
    this->set_data_bits(DEFAULT_DATA_BITS);
    this->set_stop_bits(DEFAULT_STOP_BITS);
    this->set_parity_bits(DEFAULT_PARITY_BITS);
}

serial_ns16550a *
serial_ns16550a::instance() noexcept
{
    static serial_ns16550a serial{};
    return &serial;
}

void
serial_ns16550a::set_baud_rate(baud_rate_t rate) noexcept
{
    auto lsb = gsl::narrow_cast<uint8_t>((rate & 0x000000FF) >> 0);
    auto msb = gsl::narrow_cast<uint8_t>((rate & 0x0000FF00) >> 8);

    this->enable_dlab();

    outb(baud_rate_lo_reg, lsb);
    outb(baud_rate_hi_reg, msb);

    this->disable_dlab();
}

serial_ns16550a::baud_rate_t
serial_ns16550a::baud_rate() const noexcept
{
    this->enable_dlab();

    auto lsb = inb(baud_rate_lo_reg);
    auto msb = inb(baud_rate_hi_reg);

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
serial_ns16550a::set_data_bits(data_bits_t bits) noexcept
{
    auto reg = inb(line_control_reg);

    reg = reg & static_cast<decltype(reg)>(~line_control_data_mask);
    reg = reg | static_cast<decltype(reg)>(bits & line_control_data_mask);

    outb(line_control_reg, reg);
}

serial_ns16550a::data_bits_t
serial_ns16550a::data_bits() const noexcept
{
    auto reg = inb(line_control_reg);

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
serial_ns16550a::set_stop_bits(stop_bits_t bits) noexcept
{
    auto reg = inb(line_control_reg);

    reg = reg & static_cast<decltype(reg)>(~line_control_stop_mask);
    reg = reg | static_cast<decltype(reg)>(bits & line_control_stop_mask);

    outb(line_control_reg, reg);
}

serial_ns16550a::stop_bits_t
serial_ns16550a::stop_bits() const noexcept
{
    auto reg = inb(line_control_reg);

    switch (reg & line_control_stop_mask) {
        case stop_bits_1:
            return stop_bits_1;
        default:
            return stop_bits_2;
    }
}

void
serial_ns16550a::set_parity_bits(parity_bits_t bits) noexcept
{
    auto reg = inb(line_control_reg);

    reg = reg & static_cast<decltype(reg)>(~line_control_parity_mask);
    reg = reg | static_cast<decltype(reg)>(bits & line_control_parity_mask);

    outb(line_control_reg, reg);
}

serial_ns16550a::parity_bits_t
serial_ns16550a::parity_bits() const noexcept
{
    auto reg = inb(line_control_reg);

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

bool
serial_ns16550a::is_transmit_empty() const noexcept
{
    return (inb(line_status_reg) & line_status_empty_transmitter) != 0;
}

void
serial_ns16550a::write(char c) const noexcept
{
    while (!is_transmit_empty())
    { }

    outb(0, static_cast<uint8_t>(c));
}

void
serial_ns16550a::enable_dlab() const noexcept
{
    auto reg = inb(line_control_reg);
    reg = reg | static_cast<decltype(reg)>(dlab);
    outb(line_control_reg, reg);
}

void
serial_ns16550a::disable_dlab() const noexcept
{
    auto reg = inb(line_control_reg);
    reg = reg & static_cast<decltype(reg)>(~(dlab));
    outb(line_control_reg, reg);
}

}
