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
#include <bsl/convert.hpp>
#include <bsl/cstr_type.hpp>
#include <bsl/cstring.hpp>
#include <bsl/is_constant_evaluated.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/touch.hpp>

namespace mk
{
    extern "C"
    {
        /// @brief stores a pointer to the debug ring provided by the loader
        // NOLINTNEXTLINE(bsl-var-braced-init)
        extern loader::debug_ring_t *g_debug_ring;
    }

    /// <!-- description -->
    ///   @brief Outputs a character to the serial port.
    ///
    /// <!-- inputs/outputs -->
    ///   @param c the character to output
    ///
    constexpr void
    debug_ring_write(bsl::char_type const c) noexcept
    {
        if (bsl::is_constant_evaluated()) {
            return;
        }

        bsl::safe_uintmax epos{g_debug_ring->epos};
        bsl::safe_uintmax spos{g_debug_ring->spos};

        if (!(g_debug_ring->buf.size() > epos)) {
            epos = {};
        }
        else {
            bsl::touch();
        }

        *g_debug_ring->buf.at_if(epos) = c;
        ++epos;

        if (!(g_debug_ring->buf.size() > epos)) {
            epos = {};
        }
        else {
            bsl::touch();
        }

        if (epos == spos) {
            ++spos;

            if (!(g_debug_ring->buf.size() > spos)) {
                spos = {};
            }
            else {
                bsl::touch();
            }
        }
        else {
            bsl::touch();
        }

        g_debug_ring->epos = epos.get();
        g_debug_ring->spos = spos.get();
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
        if (bsl::is_constant_evaluated()) {
            return;
        }

        for (bsl::safe_uintmax i{}; str[i.get()] != '\0'; ++i) {
            debug_ring_write(str[i.get()]);
        }
    }
}

#endif
