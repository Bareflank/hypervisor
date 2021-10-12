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

#ifndef DEBUG_RING_WRITE_HPP
#define DEBUG_RING_WRITE_HPP

#include <debug_ring_t.hpp>

#include <bsl/carray.hpp>
#include <bsl/char_type.hpp>
#include <bsl/cstdint.hpp>
#include <bsl/cstr_type.hpp>
#include <bsl/touch.hpp>

namespace mk
{
    /// <!-- description -->
    ///   @brief Outputs a character to the serial port.
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_ring the debug ring to output to
    ///   @param c the character to output
    ///
    constexpr void
    debug_ring_write(loader::debug_ring_t &mut_ring, bsl::char_type const c) noexcept
    {
        bsl::uintmx mut_epos{mut_ring.epos};
        bsl::uintmx mut_spos{mut_ring.spos};

        *mut_ring.buf.at_if(mut_epos) = c;
        ++mut_epos;

        if (mut_epos >= mut_ring.buf.size()) {
            mut_epos = {};
        }
        else {
            bsl::touch();
        }

        if (mut_epos == mut_spos) {
            ++mut_spos;

            if (mut_spos >= mut_ring.buf.size()) {
                mut_spos = {};
            }
            else {
                bsl::touch();
            }
        }
        else {
            bsl::touch();
        }

        mut_ring.epos = mut_epos;
        mut_ring.spos = mut_spos;
    }

    /// <!-- description -->
    ///   @brief Outputs a string to the serial port.
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_ring the debug ring to output to
    ///   @param str the string to output
    ///   @param len the total number of bytes to output
    ///
    constexpr void
    debug_ring_write(
        loader::debug_ring_t &mut_ring, bsl::cstr_type const str, bsl::uintmx const len) noexcept
    {
        // NOLINTNEXTLINE(bsl-non-safe-integral-types-are-forbidden)
        for (bsl::uintmx mut_i{}; mut_i < len; ++mut_i) {
            bsl::char_type const c{str[mut_i]};
            if ('\0' == c) {
                return;
            }

            debug_ring_write(mut_ring, c);
        }
    }
}

#endif
