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
///
/// @file cstdint.hpp
///

#ifndef BSL_CSTDINT_HPP
#define BSL_CSTDINT_HPP

#include <stdint.h>    // NOLINT

namespace bsl
{
    /// @brief defines an 8bit signed integer
    using int8 = ::int8_t;
    /// @brief defines an 16bit signed integer
    using int16 = ::int16_t;
    /// @brief defines an 32bit signed integer
    using int32 = ::int32_t;
    /// @brief defines an 64bit signed integer
    using int64 = ::int64_t;

    /// @brief defines an 8bit unsigned integer
    using uint8 = ::uint8_t;
    /// @brief defines an 16bit unsigned integer
    using uint16 = ::uint16_t;
    /// @brief defines an 32bit unsigned integer
    using uint32 = ::uint32_t;
    /// @brief defines an 64bit unsigned integer
    using uint64 = ::uint64_t;

    /// @brief defines at least an 8bit signed integer
    using int_least8 = ::int_least8_t;
    /// @brief defines at least an 16bit signed integer
    using int_least16 = ::int_least16_t;
    /// @brief defines at least an 32bit signed integer
    using int_least32 = ::int_least32_t;
    /// @brief defines at least an 64bit signed integer
    using int_least64 = ::int_least64_t;

    /// @brief defines at least an 8bit unsigned integer
    using uint_least8 = ::uint_least8_t;
    /// @brief defines at least an 16bit unsigned integer
    using uint_least16 = ::uint_least16_t;
    /// @brief defines at least an 32bit unsigned integer
    using uint_least32 = ::uint_least32_t;
    /// @brief defines at least an 64bit unsigned integer
    using uint_least64 = ::uint_least64_t;

    /// @brief defines at least an 8bit signed integer with optimizations
    using int_fast8 = ::int_fast8_t;
    /// @brief defines at least an 16bit signed integer with optimizations
    using int_fast16 = ::int_fast16_t;
    /// @brief defines at least an 32bit signed integer with optimizations
    using int_fast32 = ::int_fast32_t;
    /// @brief defines at least an 64bit signed integer with optimizations
    using int_fast64 = ::int_fast64_t;

    /// @brief defines at least an 8bit unsigned integer with optimizations
    using uint_fast8 = ::uint_fast8_t;
    /// @brief defines at least an 16bit unsigned integer with optimizations
    using uint_fast16 = ::uint_fast16_t;
    /// @brief defines at least an 32bit unsigned integer with optimizations
    using uint_fast32 = ::uint_fast32_t;
    /// @brief defines at least an 64bit unsigned integer with optimizations
    using uint_fast64 = ::uint_fast64_t;

    /// @brief defines a signed integer the size of a void *
    using intptr = ::intptr_t;
    /// @brief defines a unsigned integer the size of a void *
    using uintptr = ::uintptr_t;

    /// @brief defines a signed integer with the maximum possible size
    using intmax = ::intmax_t;
    /// @brief defines a unsigned integer with the maximum possible size
    using uintmax = ::uintmax_t;
}

#endif
