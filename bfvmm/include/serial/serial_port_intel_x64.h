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

#ifndef SERIAL_PORT_INTEL_X64_H
#define SERIAL_PORT_INTEL_X64_H

#include <string>
#include <memory>

#include <constants.h>
#include <intrinsics/portio_x64.h>

namespace serial_intel_x64
{
constexpr const x64::portio::port_8bit_type dlab = 1U << 7;

constexpr const x64::portio::port_addr_type baud_rate_lo_reg = 0U;
constexpr const x64::portio::port_addr_type baud_rate_hi_reg = 1U;
constexpr const x64::portio::port_addr_type interrupt_en_reg = 1U;
constexpr const x64::portio::port_addr_type fifo_control_reg = 2U;
constexpr const x64::portio::port_addr_type line_control_reg = 3U;
constexpr const x64::portio::port_addr_type line_status_reg = 5U;

constexpr const x64::portio::port_8bit_type fifo_control_enable_fifos = 1U << 0;
constexpr const x64::portio::port_8bit_type fifo_control_clear_recieve_fifo = 1U << 1;
constexpr const x64::portio::port_8bit_type fifo_control_clear_transmit_fifo = 1U << 2;
constexpr const x64::portio::port_8bit_type fifo_control_dma_mode_select = 1U << 3;

constexpr const x64::portio::port_8bit_type line_status_data_ready = 1U << 0;
constexpr const x64::portio::port_8bit_type line_status_overrun_error = 1U << 1;
constexpr const x64::portio::port_8bit_type line_status_parity_error = 1U << 2;
constexpr const x64::portio::port_8bit_type line_status_framing_error = 1U << 3;
constexpr const x64::portio::port_8bit_type line_status_break_interrupt = 1U << 4;
constexpr const x64::portio::port_8bit_type line_status_empty_transmitter = 1U << 5;
constexpr const x64::portio::port_8bit_type line_status_empty_data = 1U << 6;
constexpr const x64::portio::port_8bit_type line_status_recieved_fifo_error = 1U << 7;

constexpr const x64::portio::port_8bit_type line_control_data_mask = 0x03;
constexpr const x64::portio::port_8bit_type line_control_stop_mask = 0x04;
constexpr const x64::portio::port_8bit_type line_control_parity_mask = 0x38;
}

/// Serial Port (Intel x64)
///
/// This class implements the serial device for Intel specific archiectures.
/// All of the serial devices start off with the same default settings (minus
/// the port). There are no checks on the port # (in case a custom port number
/// is needed), and there are no checks to ensure that only one port is used
/// at a time. If custom port settings are required, once the serial port is
/// created, the custom settings can be setup by using the set_xxx functions.
/// The user should ensure that the settings worked by checking the result.
///
/// Also note, that by default, a FIFO is used / required, and interrupts are
/// disabled.
///
class serial_port_intel_x64
{
public:

    using port_type = x64::portio::port_addr_type;
    using value_type = x64::portio::port_8bit_type;

    enum baud_rate_t
    {
        baud_rate_50 = 0x0900,
        baud_rate_75 = 0x0600,
        baud_rate_110 = 0x0417,
        baud_rate_150 = 0x0300,
        baud_rate_300 = 0x0180,
        baud_rate_600 = 0x00C0,
        baud_rate_1200 = 0x0060,
        baud_rate_1800 = 0x0040,
        baud_rate_2000 = 0x003A,
        baud_rate_2400 = 0x0030,
        baud_rate_3600 = 0x0020,
        baud_rate_4800 = 0x0018,
        baud_rate_7200 = 0x0010,
        baud_rate_9600 = 0x000C,
        baud_rate_19200 = 0x0006,
        baud_rate_38400 = 0x0003,
        baud_rate_57600 = 0x0002,
        baud_rate_115200 = 0x0001
    };

    enum data_bits_t
    {
        char_length_5 = 0x00,
        char_length_6 = 0x01,
        char_length_7 = 0x02,
        char_length_8 = 0x03
    };

    enum stop_bits_t
    {
        stop_bits_1 = 0x00,
        stop_bits_2 = 0x04
    };

    enum parity_bits_t
    {
        parity_none = 0x00,
        parity_odd = 0x08,
        parity_even = 0x18,
        parity_mark = 0x28,
        parity_space = 0x38
    };

public:

    /// Default Constructor
    ///
    /// @expects none
    /// @ensures none
    ///
    serial_port_intel_x64(port_type port = DEFAULT_COM_PORT) noexcept;

    /// Destructor
    ///
    /// @expects none
    /// @ensures none
    ///
    ~serial_port_intel_x64() = default;

    /// Get Instance
    ///
    /// Get an instance to the class.
    ///
    /// @expects none
    /// @ensures ret != nullptr
    ///
    static serial_port_intel_x64 *instance() noexcept;

    /// Set Baud Rate
    ///
    /// Sets the rate at which the serial device will operate. Note that the
    /// rate paramter is actually the divisor that is used, and a custom one
    /// can be used if desired. If 0 is provided, the default baud rate is
    /// used instead.
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param rate desired baud rate
    ///
    void set_baud_rate(baud_rate_t rate) noexcept;

    /// Buad Rate
    ///
    /// Returns the baud rate of the serial device. If the serial device is
    /// set to a baud rate that this code does not recognize, unknown is
    /// returned.
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return the baud rate
    ///
    baud_rate_t baud_rate() const noexcept;

    /// Set Data Bits
    ///
    /// Sets the size of the data that is transmitted. For more information
    /// on the this field, please see http://wiki.osdev.org/Serial_Ports.
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param bits the desired data bits
    ///
    void set_data_bits(data_bits_t bits) noexcept;

    /// Data Bits
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return the serial device's data bits
    ///
    data_bits_t data_bits() const noexcept;

    /// Set Stop Bits
    ///
    /// Sets the stop bits used for transmission. For more information
    /// on the this field, please see http://wiki.osdev.org/Serial_Ports.
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param bits the desired stop bits
    ///
    void set_stop_bits(stop_bits_t bits) noexcept;

    /// Stop Bits
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return the serial device's stop bits
    ///
    stop_bits_t stop_bits() const noexcept;

    /// Set Parity Bits
    ///
    /// Sets the parity bits used for transmission. For more information
    /// on the this field, please see http://wiki.osdev.org/Serial_Ports.
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param bits the desired parity bits
    ///
    void set_parity_bits(parity_bits_t bits) noexcept;

    /// Parity Bits
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return the serial device's parity bits
    ///
    parity_bits_t parity_bits() const noexcept;

    /// Port
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return the serial device's port
    ///
    port_type port() const noexcept
    { return m_port; }

    /// Write Character
    ///
    /// Writes a character to the serial device.
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param c character to write
    ///
    void write(char c) noexcept;

    /// Write String
    ///
    /// Writes a string to the serial device.
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param str string to write
    ///
    void write(const std::string &str) noexcept
    {
        for (auto c : str)
            write(c);
    }

private:

    void enable_dlab() const noexcept;
    void disable_dlab() const noexcept;

    bool get_line_status_empty_transmitter() const noexcept;

private:

    port_type m_port;

public:

    serial_port_intel_x64(serial_port_intel_x64 &&) noexcept = default;
    serial_port_intel_x64 &operator=(serial_port_intel_x64 &&) noexcept = default;
    serial_port_intel_x64(const serial_port_intel_x64 &) = delete;
    serial_port_intel_x64 &operator=(const serial_port_intel_x64 &) = delete;
};

#endif
