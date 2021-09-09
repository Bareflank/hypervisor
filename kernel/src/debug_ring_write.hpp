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

#include <bsl/char_type.hpp>
#include <bsl/cstdint.hpp>
#include <bsl/cstr_type.hpp>
#include <bsl/touch.hpp>

namespace mk
{
    extern "C"
    {
        /// @brief stores a pointer to the debug ring provided by the loader
        // NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
        extern loader::debug_ring_t *g_pmut_mut_debug_ring;
    }

    /// <!-- description -->
    ///   @brief Outputs a character to the serial port.
    ///
    /// <!-- inputs/outputs -->
    ///   @param c the character to output
    ///
    extern "C" constexpr void
    debug_ring_write(bsl::char_type const c) noexcept
    {
        bsl::uintmx mut_epos{g_pmut_mut_debug_ring->epos};
        bsl::uintmx mut_spos{g_pmut_mut_debug_ring->spos};

        if (!(g_pmut_mut_debug_ring->buf.size() > mut_epos)) {
            mut_epos = {};
        }
        else {
            bsl::touch();
        }

        *g_pmut_mut_debug_ring->buf.at_if(mut_epos) = c;
        ++mut_epos;

        if (!(g_pmut_mut_debug_ring->buf.size() > mut_epos)) {
            mut_epos = {};
        }
        else {
            bsl::touch();
        }

        if (mut_epos == mut_spos) {
            ++mut_spos;

            if (!(g_pmut_mut_debug_ring->buf.size() > mut_spos)) {
                mut_spos = {};
            }
            else {
                bsl::touch();
            }
        }
        else {
            bsl::touch();
        }

        g_pmut_mut_debug_ring->epos = mut_epos;
        g_pmut_mut_debug_ring->spos = mut_spos;
    }

    /// <!-- description -->
    ///   @brief Outputs a string to the serial port.
    ///
    /// <!-- inputs/outputs -->
    ///   @param str the string to output
    ///
    constexpr void
    debug_ring_write(bsl::cstr_type const str) noexcept
    {
        // NOLINTNEXTLINE(bsl-non-safe-integral-types-are-forbidden)
        for (bsl::uintmx mut_i{}; '\0' != str[mut_i]; ++mut_i) {
            debug_ring_write(str[mut_i]);
        }
    }
}

#endif
