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
        // NOLINTNEXTLINE(bsl-var-braced-init)
        extern loader::debug_ring_t *g_pmut_mut_debug_ring;
    }

    /// NOTE:
    /// - There are a lot of Clang Tidy exceptions here. The rules that have
    ///   exceptions are all self imposed to ensure that safe integrals are
    ///   used wherever possible as the compiler will remove the overhead
    ///   when it is not needed, so they are almost zero cost. In this case
    ///   however, the debug ring implements the debugging logic that the
    ///   safe integral relies on, which means that it cannot use safe
    ///   integrals in it's implementation. This is, however, still compliant
    ///   as fixed types are used and overflow has been checked and verified
    ///   to never occur.
    ///

    /// <!-- description -->
    ///   @brief Outputs a character to the serial port.
    ///
    /// <!-- inputs/outputs -->
    ///   @param c the character to output
    ///
    constexpr void
    debug_ring_write(bsl::char_type const c) noexcept
    {
        // NOLINTNEXTLINE(bsl-non-safe-integral-types-are-forbidden)
        bsl::uintmx mut_epos{g_pmut_mut_debug_ring->epos};
        // NOLINTNEXTLINE(bsl-non-safe-integral-types-are-forbidden)
        bsl::uintmx mut_spos{g_pmut_mut_debug_ring->spos};

        // NOLINTNEXTLINE(bsl-types-fixed-width-ints-arithmetic-check)
        if (!(g_pmut_mut_debug_ring->buf.size() > mut_epos)) {
            mut_epos = {};
        }
        else {
            bsl::touch();
        }

        *g_pmut_mut_debug_ring->buf.at_if(mut_epos) = c;
        ++mut_epos;

        // NOLINTNEXTLINE(bsl-types-fixed-width-ints-arithmetic-check)
        if (!(g_pmut_mut_debug_ring->buf.size() > mut_epos)) {
            mut_epos = {};
        }
        else {
            bsl::touch();
        }

        if (mut_epos == mut_spos) {
            ++mut_spos;

            // NOLINTNEXTLINE(bsl-types-fixed-width-ints-arithmetic-check)
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
