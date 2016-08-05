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
#include <intrinsics/intrinsics_intel_x64.h>

#ifndef DEFAULT_COM_PORT
#define DEFAULT_COM_PORT COM1_PORT
#endif

#ifndef DEFAULT_BAUD_RATE
#define DEFAULT_BAUD_RATE baud_rate_115200
#endif

#ifndef DEFAULT_DATA_BITS
#define DEFAULT_DATA_BITS char_length_8
#endif

#ifndef DEFAULT_STOP_BITS
#define DEFAULT_STOP_BITS stop_bits_1
#endif

#ifndef DEFAULT_PARITY_BITS
#define DEFAULT_PARITY_BITS parity_none
#endif

#define DLAB                                                          (1 << 7)

#define BAUD_RATE_LO_REG                                              (0)
#define BAUD_RATE_HI_REG                                              (1)
#define INTERRUPT_EN_REG                                              (1)
#define FIFO_CONTROL_REG                                              (2)
#define LINE_CONTROL_REG                                              (3)
#define LINE_STATUS_REG                                               (5)

#define FIFO_CONTROL_ENABLE_FIFOS                                     (1 << 0)
#define FIFO_CONTROL_CLEAR_RECIEVE_FIFO                               (1 << 1)
#define FIFO_CONTROL_CLEAR_TRANSMIT_FIFO                              (1 << 2)
#define FIFO_CONTROL_DMA_MODE_SELECT                                  (1 << 3)

#define LINE_STATUS_DATA_READY                                        (1 << 0)
#define LINE_STATUS_OVERRUN_ERROR                                     (1 << 1)
#define LINE_STATUS_PARITY_ERROR                                      (1 << 2)
#define LINE_STATUS_FRAMING_ERROR                                     (1 << 3)
#define LINE_STATUS_BREAK_INTERRUPT                                   (1 << 4)
#define LINE_STATUS_EMPTY_TRANSMITTER                                 (1 << 5)
#define LINE_STATUS_EMPTY_DATA                                        (1 << 6)
#define LINE_STATUS_RECIEVED_FIFO_ERROR                               (1 << 7)

#define LINE_CONTROL_DATA_MASK                                        (0x03)
#define LINE_CONTROL_STOP_MASK                                        (0x04)
#define LINE_CONTROL_PARITY_MASK                                      (0x38)

/// Serial Port (Intel x64)
///
/// This class implements the serial device for Intel specific archiectures.
/// All of the serial devices start off with the same default settings (minus
/// the port). There are no checks on the port # (in case a custom port number
/// is needed), and there are no checks to ensure that only one port is used
/// as a time. If custom port settings are required, once the serial port is
/// created, the custom settings can be setup by using the set_xxx functions.
/// The user should ensure that the settings worked by checking the result.
///
/// Also note, that by default, a FIFO is used / required, and interrupts are
/// disabled.
///
class serial_port_intel_x64
{
public:

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
        baud_rate_115200 = 0x0001,
        baud_rate_unknown = 0x0000
    };

    enum data_bits_t
    {
        char_length_5 = 0x00,
        char_length_6 = 0x01,
        char_length_7 = 0x02,
        char_length_8 = 0x03,
    };

    enum stop_bits_t
    {
        stop_bits_1 = 0x00,
        stop_bits_2 = 0x04,
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
    serial_port_intel_x64(const std::shared_ptr<intrinsics_intel_x64> &intrinsics = nullptr,
                          uint16_t port = DEFAULT_COM_PORT) noexcept;

    /// Destructor
    ///
    virtual ~serial_port_intel_x64() {}

    /// Get Instance
    ///
    /// Get an instance to the class.
    ///
    static serial_port_intel_x64 *instance(const std::shared_ptr<intrinsics_intel_x64> &intrinsics = nullptr) noexcept;

    /// Initialize
    ///
    /// Initializes the serial device.
    ///
    virtual void init();

    /// Set Baud Rate
    ///
    /// Sets the rate at which the serial device will operate. Note that the
    /// rate paramter is actually the divisor that is used, and a custom one
    /// can be used if desired. If 0 is provided, the default baud rate is
    /// used instead.
    ///
    /// @param rate desired baud rate
    ///
    virtual void set_baud_rate(baud_rate_t rate) noexcept;

    /// Buad Rate
    ///
    /// Returns the baud rate of the serial device. If the serial device is
    /// set to a baud rate that this code does not recognize, unknown is
    /// returned.
    ///
    /// @return the baud rate
    ///
    virtual baud_rate_t baud_rate() const noexcept;

    /// Set Data Bits
    ///
    /// Sets the size of the data that is transmitted. For more information
    /// on the this field, please see http://wiki.osdev.org/Serial_Ports.
    ///
    /// @param bits the desired data bits
    ///
    virtual void set_data_bits(data_bits_t bits) noexcept;

    /// Data Bits
    ///
    /// @return the serial device's data bits
    ///
    virtual data_bits_t data_bits() const noexcept;

    /// Set Stop Bits
    ///
    /// Sets the stop bits used for transmission. For more information
    /// on the this field, please see http://wiki.osdev.org/Serial_Ports.
    ///
    /// @param bits the desired stop bits
    ///
    virtual void set_stop_bits(stop_bits_t bits) noexcept;

    /// Stop Bits
    ///
    /// @return the serial device's stop bits
    ///
    virtual stop_bits_t stop_bits() const noexcept;

    /// Set Parity Bits
    ///
    /// Sets the parity bits used for transmission. For more information
    /// on the this field, please see http://wiki.osdev.org/Serial_Ports.
    ///
    /// @param bits the desired parity bits
    ///
    virtual void set_parity_bits(parity_bits_t bits) noexcept;

    /// Parity Bits
    ///
    /// @return the serial device's parity bits
    ///
    virtual parity_bits_t parity_bits() const noexcept;

    // Port
    //
    /// @return the serial device's port
    ///
    virtual uint16_t port() const noexcept
    { return m_port; }

    /// Write Character
    ///
    /// Writes a character to the serial device.
    ///
    /// @param c character to write
    ///
    virtual void write(char c) noexcept;

    /// Write String
    ///
    /// Writes a string to the serial device.
    ///
    /// @param str string to write
    ///
    virtual void write(const std::string &str) noexcept;

public:

    /// Disable the copy consturctor
    ///
    serial_port_intel_x64(const serial_port_intel_x64 &) = delete;

    /// Disable the copy operator
    ///
    serial_port_intel_x64 &operator=(const serial_port_intel_x64 &) = delete;

private:

    void enable_dlab() const noexcept;
    void disable_dlab() const noexcept;

    bool line_status_empty_transmitter() const noexcept;

private:

    uint16_t m_port;
    std::shared_ptr<intrinsics_intel_x64> m_intrinsics;
};

#endif
