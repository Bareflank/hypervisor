/// @copyright
/// Copyright (C) 2020 Assured Information Security, Inc.
///
/// @copyright
/// Permission is hereby granted, free of charge, to any person obtaining a copy
/// of this software and associated documentation files (the "Software"), to deal
/// in the Software without restriction, including without limitation the rights
/// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
/// copies of the Software, and to permit persons to whom the Software is
/// furnished to do so, subject to the following conditions:
///
/// @copyright
/// The above copyright notice and this permission notice shall be included in
/// all copies or substantial portions of the Software.
///
/// @copyright
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
/// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
/// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
/// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
/// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
/// SOFTWARE.

#ifndef SERIAL_WRITE_HPP
#define SERIAL_WRITE_HPP

#include <bsl/char_type.hpp>
#include <bsl/convert.hpp>
#include <bsl/cstr_type.hpp>
#include <bsl/is_constant_evaluated.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/touch.hpp>

namespace mk
{
    namespace details
    {
        /// @brief defines the line status register
        constexpr bsl::safe_uint16 LSR{bsl::to_u16(5)};

        /// @brief defines the transmit FIFO empty bit in the LSR
        constexpr bsl::safe_uint8 LSR_TRANSMIT_FIFO_EMPTY{bsl::to_u8(1) << bsl::to_u8(5)};

        /// <!-- description -->
        ///   @brief Reads a byte from the requested serial port register.
        ///
        /// <!-- inputs/outputs -->
        ///   @param reg the serial port register to read from
        ///   @return the data read from the requested serial port register
        ///
        [[nodiscard]] extern "C" auto serial_in(bsl::uint16 reg) noexcept -> bsl::uint8;

        /// <!-- description -->
        ///   @brief Writes a byte to the requested serial port register.
        ///
        /// <!-- inputs/outputs -->
        ///   @param reg the serial port register to write to
        ///   @param c the byte to write to the requested serial port register
        ///
        extern "C" void serial_out(bsl::uint16 reg, bsl::char_type const c) noexcept;
    }

    /// <!-- description -->
    ///   @brief Outputs a character to the serial port.
    ///
    /// <!-- inputs/outputs -->
    ///   @param c the character to output
    ///
    constexpr void
    serial_write(bsl::char_type const c) noexcept
    {
        if (bsl::is_constant_evaluated()) {
            return;
        }

        while (true) {
            bsl::safe_uint8 const status{
                details::serial_in((details::LSR + bsl::to_u16(HYPERVISOR_SERIAL_PORT)).get())};

            if ((status & details::LSR_TRANSMIT_FIFO_EMPTY).is_pos()) {
                break;
            }

            bsl::touch();
        }

        details::serial_out(bsl::to_u16(HYPERVISOR_SERIAL_PORT).get(), c);
    }

    /// <!-- description -->
    ///   @brief Outputs a string to the serial port.
    ///
    /// <!-- inputs/outputs -->
    ///   @param str the string to output
    ///
    constexpr void
    serial_write(bsl::cstr_type const str) noexcept
    {
        if (bsl::is_constant_evaluated()) {
            return;
        }

        for (bsl::safe_uintmax i{}; str[i.get()] != '\0'; ++i) {
            serial_write(str[i.get()]);
        }
    }
}

#endif
