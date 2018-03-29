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

#ifndef SERIAL_NS16550A_H
#define SERIAL_NS16550A_H

#include <intrinsics.h>
#include <bfconstants.h>

// -----------------------------------------------------------------------------
// Exports
// -----------------------------------------------------------------------------

#include <bfexports.h>

#ifndef STATIC_DEBUG
#ifdef SHARED_DEBUG
#define EXPORT_DEBUG EXPORT_SYM
#else
#define EXPORT_DEBUG IMPORT_SYM
#endif
#else
#define EXPORT_DEBUG
#endif

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4251)
#endif

// -----------------------------------------------------------------------------
// Definition
// -----------------------------------------------------------------------------

namespace bfvmm
{

/// Serial Port (NatSemi 16550A and compatible)
///
class EXPORT_DEBUG serial_ns16550a
{
public:

    /// @cond

    enum baud_rate_t {
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

    enum data_bits_t {
        char_length_5 = 0x00,
        char_length_6 = 0x01,
        char_length_7 = 0x02,
        char_length_8 = 0x03
    };

    enum stop_bits_t {
        stop_bits_1 = 0x00,
        stop_bits_2 = 0x04
    };

    enum parity_bits_t {
        parity_none = 0x00,
        parity_odd = 0x08,
        parity_even = 0x18,
        parity_mark = 0x28,
        parity_space = 0x38
    };

    /// @endcond

public:

    /// Constructor - uses the default port
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param port the IO port or MMIO address (platform-dependent)
    ///
    serial_ns16550a(uintptr_t port = DEFAULT_COM_PORT) noexcept;

    /// Destructor
    ///
    /// @expects none
    /// @ensures none
    ///
    ~serial_ns16550a() = default;

    /// Get Instance
    ///
    /// Get an instance to the class.
    ///
    /// @expects none
    /// @ensures ret != nullptr
    ///
    /// @return a singleton instance of serial_ns16550a
    ///
    static serial_ns16550a *instance() noexcept;

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

    /// Write Character
    ///
    /// Writes a character to the serial device.
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param c character to write
    ///
    void write(char c) const noexcept;

private:

    void enable_dlab() const noexcept;
    void disable_dlab() const noexcept;
    bool is_transmit_empty() const noexcept;

    uint8_t inb(uint16_t addr) const noexcept;
    void outb(uint16_t addr, uint8_t data) const noexcept;

    /// MMIO address or IO port
    uintptr_t m_addr;

public:

    /// @cond

    serial_ns16550a(serial_ns16550a &&) noexcept = default;
    serial_ns16550a &operator=(serial_ns16550a &&) noexcept = default;

    serial_ns16550a(const serial_ns16550a &) = delete;
    serial_ns16550a &operator=(const serial_ns16550a &) = delete;

    /// @endcond
};

}

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#endif
