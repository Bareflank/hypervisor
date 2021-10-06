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

#ifndef MOCKS_SERIAL_WRITE_HPP
#define MOCKS_SERIAL_WRITE_HPP

#include <bsl/cstdint.hpp>
#include <bsl/cstr_type.hpp>
#include <bsl/discard.hpp>

namespace mk
{
    /// <!-- description -->
    ///   @brief Outputs a string to the serial port.
    ///
    /// <!-- inputs/outputs -->
    ///   @param str the string to output
    ///   @param len the total number of bytes to output
    ///
    constexpr void
    serial_write(bsl::cstr_type const str, bsl::uintmx const len) noexcept
    {
        bsl::discard(str);
        bsl::discard(len);
    }
}

#endif
