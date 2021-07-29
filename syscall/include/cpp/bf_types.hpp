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

#ifndef BF_TYPES_HPP
#define BF_TYPES_HPP

#include <bsl/safe_integral.hpp>

namespace syscall
{
    // -------------------------------------------------------------------------
    // Scalar Types
    // -------------------------------------------------------------------------

    /// @brief Defines the type used for returning status from a function
    using bf_status_t = bsl::safe_uint64;

    // -------------------------------------------------------------------------
    // Bootstrap Callback Handler Type
    // -------------------------------------------------------------------------

    /// @brief Defines the signature of the bootstrap callback handler
    // Entry points cannot use safe integral types
    // NOLINTNEXTLINE(bsl-non-safe-integral-types-are-forbidden)
    using bf_callback_handler_bootstrap_t = void (*)(bsl::safe_uint16::value_type);

    // -------------------------------------------------------------------------
    // VMExit Callback Handler Type
    // -------------------------------------------------------------------------

    /// @brief Defines the signature of the VM exit callback handler
    // Entry points cannot use safe integral types
    using bf_callback_handler_vmexit_t =
        // NOLINTNEXTLINE(bsl-non-safe-integral-types-are-forbidden)
        void (*)(bsl::safe_uint16::value_type, bsl::safe_uint64::value_type);

    // -------------------------------------------------------------------------
    // Fast Fail Callback Handler Type
    // -------------------------------------------------------------------------

    /// @brief Defines the signature of the fast fail callback handler
    // Entry points cannot use safe integral types
    using bf_callback_handler_fail_t =
        // NOLINTNEXTLINE(bsl-non-safe-integral-types-are-forbidden)
        void (*)(bsl::safe_uint16::value_type, bf_status_t::value_type);
}

#endif
