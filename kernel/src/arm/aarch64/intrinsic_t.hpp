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

#ifndef INTRINSIC_HPP
#define INTRINSIC_HPP

#include <bsl/cstdint.hpp>
#include <bsl/debug.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/exit_code.hpp>
#include <bsl/is_constant_evaluated.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/touch.hpp>

namespace mk
{
    /// <!-- description -->
    ///   @brief Provides raw access to intrinsics. Instead of using global
    ///     functions, the intrinsics class provides a means for the rest of
    ///     the kernel to mock the intrinsics when needed during unit testing.
    ///
    class intrinsic_t final
    {
    public:
        /// <!-- description -->
        ///   @brief Returns the value of tp (TLS pointer)
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of tp (TLS pointer)
        ///
        [[nodiscard]] static constexpr auto
        tp() noexcept -> bsl::safe_u64
        {
            if (bsl::is_constant_evaluated()) {
                return {};
            }

            return {};
        }

        /// <!-- description -->
        ///   @brief Sets the value of tp (TLS pointer)
        ///
        /// <!-- inputs/outputs -->
        ///   @param val the value to set tp (TLS pointer) to
        ///
        static constexpr void
        set_tp(bsl::safe_u64 const &val) noexcept
        {
            if (bsl::is_constant_evaluated()) {
                return;
            }

            if (bsl::unlikely(!val)) {
                bsl::error() << "invalid val "    // --
                             << bsl::hex(val)     // --
                             << bsl::endl         // --
                             << bsl::here();      // --

                return;
            }

            bsl::touch();
        }
    };
}

#endif
