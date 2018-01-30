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

#ifndef SERIAL_PORT_PL011_H
#define SERIAL_PORT_PL011_H

#include <string>
#include <memory>

#include <bfconstants.h>

#include <intrinsics.h>
#include <bfvmm/debug/serial/serial_port_base.h>

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
// Constants
// -----------------------------------------------------------------------------

/// @cond

// from ARM PrimeCell UART (PL011) Technical Reference Manual
// http://infocenter.arm.com/help/topic/com.arm.doc.ddi0183f/DDI0183.pdf

namespace serial_pl011
{
constexpr const serial_port_base::port_type uartdr_reg = 0x000u;
constexpr const serial_port_base::port_type uartrsr_reg = 0x004u;
constexpr const serial_port_base::port_type uartecr_reg = 0x004u;
constexpr const serial_port_base::port_type uartfr_reg = 0x018u;
constexpr const serial_port_base::port_type uartilpr_reg = 0x020u;
constexpr const serial_port_base::port_type uartibrd_reg = 0x024u;
constexpr const serial_port_base::port_type uartfbrd_reg = 0x028u;
constexpr const serial_port_base::port_type uartlcr_h_reg = 0x02Cu;
constexpr const serial_port_base::port_type uartcr_reg = 0x030u;
constexpr const serial_port_base::port_type uartifls_reg = 0x034u;
constexpr const serial_port_base::port_type uartimsc_reg = 0x038u;
constexpr const serial_port_base::port_type uartris_reg = 0x03Cu;
constexpr const serial_port_base::port_type uartmis_reg = 0x040u;
constexpr const serial_port_base::port_type uarticr_reg = 0x044u;
constexpr const serial_port_base::port_type uartdmacr_reg = 0x048u;
constexpr const serial_port_base::port_type uartperiphid0_reg = 0xFE0u;
constexpr const serial_port_base::port_type uartperiphid1_reg = 0xFE4u;
constexpr const serial_port_base::port_type uartperiphid2_reg = 0xFE8u;
constexpr const serial_port_base::port_type uartperiphid3_reg = 0xFECu;
constexpr const serial_port_base::port_type uartpcellid0_reg = 0xFF0u;
constexpr const serial_port_base::port_type uartpcellid1_reg = 0xFF4u;
constexpr const serial_port_base::port_type uartpcellid2_reg = 0xFF8u;
constexpr const serial_port_base::port_type uartpcellid3_reg = 0xFFCu;

// Data register (UARTDR)
constexpr const serial_port_base::value_type_32 uartdr_overrun_error = 1U << 11;
constexpr const serial_port_base::value_type_32 uartdr_break_error = 1U << 10;
constexpr const serial_port_base::value_type_32 uartdr_parity_error = 1U << 9;
constexpr const serial_port_base::value_type_32 uartdr_framing_error = 1U << 8;
constexpr const serial_port_base::value_type_32 uartdr_data_mask = 0xFFu;

// Receive status register (UARTRSR)
// Error clear register (UARTECR)
constexpr const serial_port_base::value_type_32 uartrsr_overrun_error = 1U << 3;
constexpr const serial_port_base::value_type_32 uartrsr_break_error = 1U << 2;
constexpr const serial_port_base::value_type_32 uartrsr_parity_error = 1U << 1;
constexpr const serial_port_base::value_type_32 uartrsr_framing_error = 1U << 0;

// Flag register (UARTFR)
constexpr const serial_port_base::value_type_32 uartfr_ring_indicator = 1U << 8;
constexpr const serial_port_base::value_type_32 uartfr_tx_empty = 1U << 7;
constexpr const serial_port_base::value_type_32 uartfr_rx_full = 1U << 6;
constexpr const serial_port_base::value_type_32 uartfr_tx_full = 1U << 5;
constexpr const serial_port_base::value_type_32 uartfr_rx_empty = 1U << 4;
constexpr const serial_port_base::value_type_32 uartfr_busy = 1U << 3;
constexpr const serial_port_base::value_type_32 uartfr_dcd = 1U << 2;
constexpr const serial_port_base::value_type_32 uartfr_dsr = 1U << 1;
constexpr const serial_port_base::value_type_32 uartfr_cts = 1U << 0;

// Line control register (UARTLCR_H)
constexpr const serial_port_base::value_type_32 uartlcr_h_wlen_mask = 3U << 5;
constexpr const serial_port_base::value_type_32 uartlcr_h_wlen_8bit = 3U << 5;
constexpr const serial_port_base::value_type_32 uartlcr_h_wlen_7bit = 2U << 5;
constexpr const serial_port_base::value_type_32 uartlcr_h_wlen_6bit = 1U << 5;
constexpr const serial_port_base::value_type_32 uartlcr_h_wlen_5bit = 0U << 5;
constexpr const serial_port_base::value_type_32 uartlcr_h_fifo_enable = 1U << 4;
constexpr const serial_port_base::value_type_32 uartlcr_h_stop_mask = 1U << 3;
constexpr const serial_port_base::value_type_32 uartlcr_h_stop_1bit = 0U << 3;
constexpr const serial_port_base::value_type_32 uartlcr_h_stop_2bit = 1U << 3;
constexpr const serial_port_base::value_type_32 uartlcr_h_sps = 1U << 7;
constexpr const serial_port_base::value_type_32 uartlcr_h_eps = 1U << 2;
constexpr const serial_port_base::value_type_32 uartlcr_h_pen = 1U << 1;
constexpr const serial_port_base::value_type_32 uartlcr_h_parity_mask = uartlcr_h_sps | uartlcr_h_eps | uartlcr_h_pen;
constexpr const serial_port_base::value_type_32 uartlcr_h_parity_even = uartlcr_h_eps | uartlcr_h_pen;
constexpr const serial_port_base::value_type_32 uartlcr_h_parity_odd = uartlcr_h_pen;
constexpr const serial_port_base::value_type_32 uartlcr_h_parity_none = 0;
constexpr const serial_port_base::value_type_32 uartlcr_h_parity_one = uartlcr_h_pen | uartlcr_h_sps;
constexpr const serial_port_base::value_type_32 uartlcr_h_parity_zero = uartlcr_h_pen | uartlcr_h_sps | uartlcr_h_eps;
constexpr const serial_port_base::value_type_32 uartlcr_h_send_break = 1U << 0;

// Control register (UARTCR)
constexpr const serial_port_base::value_type_32 uartcr_ctse_n = 1U << 15;
constexpr const serial_port_base::value_type_32 uartcr_rtse_n = 1U << 14;
constexpr const serial_port_base::value_type_32 uartcr_out2 = 1U << 13;
constexpr const serial_port_base::value_type_32 uartcr_out1 = 1U << 12;
constexpr const serial_port_base::value_type_32 uartcr_rts = 1U << 11;
constexpr const serial_port_base::value_type_32 uartcr_dtr = 1U << 10;
constexpr const serial_port_base::value_type_32 uartcr_rx_en = 1U << 9;
constexpr const serial_port_base::value_type_32 uartcr_tx_en = 1U << 8;
constexpr const serial_port_base::value_type_32 uartcr_loopback_en = 1U << 7;
constexpr const serial_port_base::value_type_32 uartcr_sirlp = 1U << 2;
constexpr const serial_port_base::value_type_32 uartcr_siren = 1U << 1;
constexpr const serial_port_base::value_type_32 uartcr_uart_en = 1U << 0;

// Interrupt FIFO level select register (UARTIFLS)
constexpr const serial_port_base::value_type_32 uartifls_rxiflsel_mask = 7U << 3;
constexpr const serial_port_base::value_type_32 uartifls_rxiflsel_1_8 = 0U << 3;
constexpr const serial_port_base::value_type_32 uartifls_rxiflsel_1_4 = 1U << 3;
constexpr const serial_port_base::value_type_32 uartifls_rxiflsel_1_2 = 2U << 3;
constexpr const serial_port_base::value_type_32 uartifls_rxiflsel_3_4 = 3U << 3;
constexpr const serial_port_base::value_type_32 uartifls_rxiflsel_7_8 = 4U << 3;
constexpr const serial_port_base::value_type_32 uartifls_txiflsel_mask = 7U << 0;
constexpr const serial_port_base::value_type_32 uartifls_txiflsel_1_8 = 0U << 0;
constexpr const serial_port_base::value_type_32 uartifls_txiflsel_1_4 = 1U << 0;
constexpr const serial_port_base::value_type_32 uartifls_txiflsel_1_2 = 2U << 0;
constexpr const serial_port_base::value_type_32 uartifls_txiflsel_3_4 = 3U << 0;
constexpr const serial_port_base::value_type_32 uartifls_txiflsel_7_8 = 4U << 0;

// Interrupt mask set/clear register (UARTIMSC)
// Raw interrupt status register (UARTRIS)
// Masked interrupt status register (UARTMIS)
// Interrupt clear register (UARTICR)
constexpr const serial_port_base::value_type_32 uartinterrupt_oe = 1U << 10;
constexpr const serial_port_base::value_type_32 uartinterrupt_be = 1U << 9;
constexpr const serial_port_base::value_type_32 uartinterrupt_pe = 1U << 8;
constexpr const serial_port_base::value_type_32 uartinterrupt_fe = 1U << 7;
constexpr const serial_port_base::value_type_32 uartinterrupt_rt = 1U << 6;
constexpr const serial_port_base::value_type_32 uartinterrupt_tx = 1U << 5;
constexpr const serial_port_base::value_type_32 uartinterrupt_rx = 1U << 4;
constexpr const serial_port_base::value_type_32 uartinterrupt_dsrm = 1U << 3;
constexpr const serial_port_base::value_type_32 uartinterrupt_dcdm = 1U << 2;
constexpr const serial_port_base::value_type_32 uartinterrupt_ctsm = 1U << 1;
constexpr const serial_port_base::value_type_32 uartinterrupt_rim = 1U << 0;

// DMA control register (UARTDMACR)
constexpr const serial_port_base::value_type_32 uartdmacr_dmaonerr = 1U << 2;
constexpr const serial_port_base::value_type_32 uartdmacr_txdma_en = 1U << 1;
constexpr const serial_port_base::value_type_32 uartdmacr_rxdma_en = 1U << 0;

}

/// @endcond

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

/// Serial Port (ARM PrimeCell PL011)
///
/// This class implements the serial peripheral for ARM devices implementing
/// PrimeCell PL011 (note that many implement NatSemi NS16550A instead).
///
/// Note that by default, a FIFO is used / required, and interrupts are
/// disabled.
///
class EXPORT_DEBUG serial_port_pl011 : public serial_port_base
{
public:

public:

    /// @cond

    enum data_bits_t : value_type_32 {
        char_length_5 = serial_pl011::uartlcr_h_wlen_5bit,
        char_length_6 = serial_pl011::uartlcr_h_wlen_6bit,
        char_length_7 = serial_pl011::uartlcr_h_wlen_7bit,
        char_length_8 = serial_pl011::uartlcr_h_wlen_8bit,
    };

    enum stop_bits_t : value_type_32 {
        stop_bits_1 = serial_pl011::uartlcr_h_stop_1bit,
        stop_bits_2 = serial_pl011::uartlcr_h_stop_2bit,
    };

    enum parity_bits_t : value_type_32 {
        parity_none = serial_pl011::uartlcr_h_parity_none,
        parity_odd = serial_pl011::uartlcr_h_parity_odd,
        parity_even = serial_pl011::uartlcr_h_parity_even,
        parity_mark = serial_pl011::uartlcr_h_parity_one,
        parity_space = serial_pl011::uartlcr_h_parity_zero,
    };

    /// @endcond

public:

    /// Default Constructor
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param port the serial port to connect to
    ///
    serial_port_pl011(port_type port = DEFAULT_COM_PORT) noexcept;

    /// Destructor
    ///
    /// @expects none
    /// @ensures none
    ///
    ~serial_port_pl011() = default;

    /// Get Instance
    ///
    /// Get an instance to the class.
    ///
    /// @expects none
    /// @ensures ret != nullptr
    ///
    /// @return a singleton instance of serial_port_pl011
    ///
    static serial_port_pl011 *instance() noexcept;

    /// Set Baud Rate Divisor
    ///
    /// Sets the divisor used to generate the baud rate. The real baud rate
    /// will equal the UART clock divided by (int_part * 16 + frac_part).
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param int_part integer part of the divisor
    /// @param frac_part fractional part of the divisor
    ///
    void set_baud_rate_divisor(uint32_t int_part, uint32_t frac_part) noexcept;

    /// Baud Rate Divisor
    ///
    /// Gets the integer and fractional parts of the baud rate divisor.
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param int_part outparam for integer part of the divisor
    /// @param frac_part outparam for fractional part of the divisor
    ///
    void baud_rate_divisor(uint32_t &int_part, uint32_t &frac_part) const noexcept;

    /// Set Data Bits
    ///
    /// Sets the size of the data that is transmitted.
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
    /// Sets the stop bits used for transmission.
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
    /// Sets the parity bits used for transmission.
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

    /// Set Port
    ///
    /// Change the peripheral port/base address at runtime.
    ///
    /// @param port serial peripheral port or base address
    ///
    /// @expects none
    /// @ensures none
    ///
    virtual void set_port(port_type port) noexcept override
    {
        m_port = port;
    }

    /// Port
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return the serial device's port
    ///
    virtual port_type port() const noexcept override
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
    virtual void write(char c) noexcept override;

    using serial_port_base::write;

private:

    bool get_status_full_transmitter() const noexcept;

private:

    port_type m_port;

public:

    /// @cond

    serial_port_pl011(serial_port_pl011 &&) noexcept = default;
    serial_port_pl011 &operator=(serial_port_pl011 &&) noexcept = default;

    serial_port_pl011(const serial_port_pl011 &) = delete;
    serial_port_pl011 &operator=(const serial_port_pl011 &) = delete;

    /// @endcond
};

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#endif
