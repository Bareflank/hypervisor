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

#ifndef SERIAL_PORT_PL011_H
#define SERIAL_PORT_PL011_H

#include <memory>
#include <bfconstants.h>
#include <intrinsics.h>

// -----------------------------------------------------------------------------
// Definition
// -----------------------------------------------------------------------------

namespace bfvmm
{

/// Serial Port (ARM PrimeCell PL011)
///
/// This class implements the serial peripheral for ARM devices implementing
/// PrimeCell PL011 (note that many implement NatSemi NS16550A instead).
///
/// Note that by default, a FIFO is used / required, and interrupts are
/// disabled.
///
class serial_pl011
{
public:

    /// @cond

    // from ARM PrimeCell UART (PL011) Technical Reference Manual
    // http://infocenter.arm.com/help/topic/com.arm.doc.ddi0183f/DDI0183.pdf

    static constexpr ptrdiff_t uartdr_reg = 0x000u;
    static constexpr ptrdiff_t uartrsr_reg = 0x004u;
    static constexpr ptrdiff_t uartecr_reg = 0x004u;
    static constexpr ptrdiff_t uartfr_reg = 0x018u;
    static constexpr ptrdiff_t uartilpr_reg = 0x020u;
    static constexpr ptrdiff_t uartibrd_reg = 0x024u;
    static constexpr ptrdiff_t uartfbrd_reg = 0x028u;
    static constexpr ptrdiff_t uartlcr_h_reg = 0x02Cu;
    static constexpr ptrdiff_t uartcr_reg = 0x030u;
    static constexpr ptrdiff_t uartifls_reg = 0x034u;
    static constexpr ptrdiff_t uartimsc_reg = 0x038u;
    static constexpr ptrdiff_t uartris_reg = 0x03Cu;
    static constexpr ptrdiff_t uartmis_reg = 0x040u;
    static constexpr ptrdiff_t uarticr_reg = 0x044u;
    static constexpr ptrdiff_t uartdmacr_reg = 0x048u;
    static constexpr ptrdiff_t uartperiphid0_reg = 0xFE0u;
    static constexpr ptrdiff_t uartperiphid1_reg = 0xFE4u;
    static constexpr ptrdiff_t uartperiphid2_reg = 0xFE8u;
    static constexpr ptrdiff_t uartperiphid3_reg = 0xFECu;
    static constexpr ptrdiff_t uartpcellid0_reg = 0xFF0u;
    static constexpr ptrdiff_t uartpcellid1_reg = 0xFF4u;
    static constexpr ptrdiff_t uartpcellid2_reg = 0xFF8u;
    static constexpr ptrdiff_t uartpcellid3_reg = 0xFFCu;

    // Data register (UARTDR)
    static constexpr uint32_t uartdr_overrun_error = 1U << 11;
    static constexpr uint32_t uartdr_break_error = 1U << 10;
    static constexpr uint32_t uartdr_parity_error = 1U << 9;
    static constexpr uint32_t uartdr_framing_error = 1U << 8;
    static constexpr uint32_t uartdr_data_mask = 0xFFu;

    // Receive status register (UARTRSR)
    // Error clear register (UARTECR)
    static constexpr uint32_t uartrsr_overrun_error = 1U << 3;
    static constexpr uint32_t uartrsr_break_error = 1U << 2;
    static constexpr uint32_t uartrsr_parity_error = 1U << 1;
    static constexpr uint32_t uartrsr_framing_error = 1U << 0;

    // Flag register (UARTFR)
    static constexpr uint32_t uartfr_ring_indicator = 1U << 8;
    static constexpr uint32_t uartfr_tx_empty = 1U << 7;
    static constexpr uint32_t uartfr_rx_full = 1U << 6;
    static constexpr uint32_t uartfr_tx_full = 1U << 5;
    static constexpr uint32_t uartfr_rx_empty = 1U << 4;
    static constexpr uint32_t uartfr_busy = 1U << 3;
    static constexpr uint32_t uartfr_dcd = 1U << 2;
    static constexpr uint32_t uartfr_dsr = 1U << 1;
    static constexpr uint32_t uartfr_cts = 1U << 0;

    // Line control register (UARTLCR_H)
    static constexpr uint32_t uartlcr_h_wlen_mask = 3U << 5;
    static constexpr uint32_t uartlcr_h_wlen_8bit = 3U << 5;
    static constexpr uint32_t uartlcr_h_wlen_7bit = 2U << 5;
    static constexpr uint32_t uartlcr_h_wlen_6bit = 1U << 5;
    static constexpr uint32_t uartlcr_h_wlen_5bit = 0U << 5;
    static constexpr uint32_t uartlcr_h_fifo_enable = 1U << 4;
    static constexpr uint32_t uartlcr_h_stop_mask = 1U << 3;
    static constexpr uint32_t uartlcr_h_stop_1bit = 0U << 3;
    static constexpr uint32_t uartlcr_h_stop_2bit = 1U << 3;
    static constexpr uint32_t uartlcr_h_sps = 1U << 7;
    static constexpr uint32_t uartlcr_h_eps = 1U << 2;
    static constexpr uint32_t uartlcr_h_pen = 1U << 1;
    static constexpr uint32_t uartlcr_h_parity_mask = uartlcr_h_sps | uartlcr_h_eps | uartlcr_h_pen;
    static constexpr uint32_t uartlcr_h_parity_even = uartlcr_h_eps | uartlcr_h_pen;
    static constexpr uint32_t uartlcr_h_parity_odd = uartlcr_h_pen;
    static constexpr uint32_t uartlcr_h_parity_none = 0;
    static constexpr uint32_t uartlcr_h_parity_one = uartlcr_h_pen | uartlcr_h_sps;
    static constexpr uint32_t uartlcr_h_parity_zero = uartlcr_h_pen | uartlcr_h_sps | uartlcr_h_eps;
    static constexpr uint32_t uartlcr_h_send_break = 1U << 0;

    // Control register (UARTCR)
    static constexpr uint32_t uartcr_ctse_n = 1U << 15;
    static constexpr uint32_t uartcr_rtse_n = 1U << 14;
    static constexpr uint32_t uartcr_out2 = 1U << 13;
    static constexpr uint32_t uartcr_out1 = 1U << 12;
    static constexpr uint32_t uartcr_rts = 1U << 11;
    static constexpr uint32_t uartcr_dtr = 1U << 10;
    static constexpr uint32_t uartcr_rx_en = 1U << 9;
    static constexpr uint32_t uartcr_tx_en = 1U << 8;
    static constexpr uint32_t uartcr_loopback_en = 1U << 7;
    static constexpr uint32_t uartcr_sirlp = 1U << 2;
    static constexpr uint32_t uartcr_siren = 1U << 1;
    static constexpr uint32_t uartcr_uart_en = 1U << 0;

    // Interrupt FIFO level select register (UARTIFLS)
    static constexpr uint32_t uartifls_rxiflsel_mask = 7U << 3;
    static constexpr uint32_t uartifls_rxiflsel_1_8 = 0U << 3;
    static constexpr uint32_t uartifls_rxiflsel_1_4 = 1U << 3;
    static constexpr uint32_t uartifls_rxiflsel_1_2 = 2U << 3;
    static constexpr uint32_t uartifls_rxiflsel_3_4 = 3U << 3;
    static constexpr uint32_t uartifls_rxiflsel_7_8 = 4U << 3;
    static constexpr uint32_t uartifls_txiflsel_mask = 7U << 0;
    static constexpr uint32_t uartifls_txiflsel_1_8 = 0U << 0;
    static constexpr uint32_t uartifls_txiflsel_1_4 = 1U << 0;
    static constexpr uint32_t uartifls_txiflsel_1_2 = 2U << 0;
    static constexpr uint32_t uartifls_txiflsel_3_4 = 3U << 0;
    static constexpr uint32_t uartifls_txiflsel_7_8 = 4U << 0;

    // Interrupt mask set/clear register (UARTIMSC)
    // Raw interrupt status register (UARTRIS)
    // Masked interrupt status register (UARTMIS)
    // Interrupt clear register (UARTICR)
    static constexpr uint32_t uartinterrupt_oe = 1U << 10;
    static constexpr uint32_t uartinterrupt_be = 1U << 9;
    static constexpr uint32_t uartinterrupt_pe = 1U << 8;
    static constexpr uint32_t uartinterrupt_fe = 1U << 7;
    static constexpr uint32_t uartinterrupt_rt = 1U << 6;
    static constexpr uint32_t uartinterrupt_tx = 1U << 5;
    static constexpr uint32_t uartinterrupt_rx = 1U << 4;
    static constexpr uint32_t uartinterrupt_dsrm = 1U << 3;
    static constexpr uint32_t uartinterrupt_dcdm = 1U << 2;
    static constexpr uint32_t uartinterrupt_ctsm = 1U << 1;
    static constexpr uint32_t uartinterrupt_rim = 1U << 0;

    // DMA control register (UARTDMACR)
    static constexpr uint32_t uartdmacr_dmaonerr = 1U << 2;
    static constexpr uint32_t uartdmacr_txdma_en = 1U << 1;
    static constexpr uint32_t uartdmacr_rxdma_en = 1U << 0;

    /// @endcond

    /// @cond

    enum data_bits_t : uint32_t {
        char_length_5 = uartlcr_h_wlen_5bit,
        char_length_6 = uartlcr_h_wlen_6bit,
        char_length_7 = uartlcr_h_wlen_7bit,
        char_length_8 = uartlcr_h_wlen_8bit,
    };

    enum stop_bits_t : uint32_t {
        stop_bits_1 = uartlcr_h_stop_1bit,
        stop_bits_2 = uartlcr_h_stop_2bit,
    };

    enum parity_bits_t : uint32_t {
        parity_none = uartlcr_h_parity_none,
        parity_odd = uartlcr_h_parity_odd,
        parity_even = uartlcr_h_parity_even,
        parity_mark = uartlcr_h_parity_one,
        parity_space = uartlcr_h_parity_zero,
    };

    /// Constructor - accepts a target port address
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param port the MMIO base address (platform-dependent)
    ///
    serial_pl011(uintptr_t port = DEFAULT_COM_PORT) noexcept;

    /// Destructor
    ///
    /// @expects none
    /// @ensures none
    ///
    ~serial_pl011() = default;

#ifdef BF_AARCH64
    /// Get Instance
    ///
    /// Get an instance to the class.
    ///
    /// Because aarch64 is currently the only architecture that supports
    /// initializing a serial_pl011 with default constructor arguments, this
    /// method is only available on that architecture. Other architectures
    /// require this class to be instantiated with a specific virtual base
    /// address.
    ///
    /// @expects none
    /// @ensures ret != nullptr
    ///
    /// @return a singleton instance of serial_pl011
    ///
    static serial_pl011 *instance() noexcept;
#endif

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
    virtual void set_port(uintptr_t port) noexcept
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
    virtual uintptr_t port() const noexcept
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
    virtual void write(char c) noexcept;

private:

    bool get_status_full_transmitter() const noexcept;

    uint32_t read_32(ptrdiff_t offset) const noexcept;

    void write_32(ptrdiff_t offset, uint32_t data) const noexcept;

    uintptr_t m_port;

public:

    /// @cond

    serial_pl011(serial_pl011 &&) noexcept = default;
    serial_pl011 &operator=(serial_pl011 &&) noexcept = default;

    serial_pl011(const serial_pl011 &) = delete;
    serial_pl011 &operator=(const serial_pl011 &) = delete;

    /// @endcond
};
}

#endif
