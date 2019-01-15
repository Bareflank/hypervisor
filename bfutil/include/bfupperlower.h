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

///
/// @file bfupperlower.h
///

#ifndef BFUPPERLOWER_H
#define BFUPPERLOWER_H

#include <bftypes.h>
#include <type_traits>

namespace bfn
{

/// Lower
///
/// @param val the pointer to mask
/// @return the lower 12 bits of val
///
template <
    typename T,
    typename = std::enable_if<std::is_integral<T>::value>
    >
auto
lower(T val) noexcept
{
    return static_cast<T>(static_cast<uintptr_t>(val) & (0xFFFULL));
}

/// Lower
///
/// @param val the pointer to mask
/// @return the lower 12 bits of val
///
template<class T>
auto
lower(T *val) noexcept
{
    return reinterpret_cast<T *>(reinterpret_cast<uintptr_t>(val) & (0xFFFULL));
}

/// Lower
///
/// @param val the pointer to mask
/// @param from the number of bits to mask
/// @return the lower "from" bits of val
///
template <
    typename T,
    typename = std::enable_if<std::is_integral<T>::value>
    >
auto
lower(T val, uintptr_t from) noexcept
{
    return static_cast<T>(static_cast<uintptr_t>(val) & ((0x1ULL << from) - 1));
}

/// Lower
///
/// @param val the pointer to mask
/// @param from the number of bits to mask
/// @return the lower "from" bits of val
///
template<class T>
auto
lower(T *val, uintptr_t from) noexcept
{
    return reinterpret_cast<T *>(reinterpret_cast<uintptr_t>(val) & ((0x1ULL << from) - 1));
}

/// Upper
///
/// @param val the pointer to mask
/// @return the upper 12 bits of val
///
template <
    typename T,
    typename = std::enable_if<std::is_integral<T>::value>
    >
auto
upper(T val) noexcept
{
    return static_cast<T>(static_cast<uintptr_t>(val) & ~(0xFFFULL));
}

/// Upper
///
/// @param val the pointer to mask
/// @return the upper 12 bits of val
///
template<class T>
auto
upper(T *val) noexcept
{
    return reinterpret_cast<T *>(reinterpret_cast<uintptr_t>(val) & ~(0xFFFULL));
}

/// Upper
///
/// @param val the pointer to mask
/// @param from the number of bits to mask
/// @return the upper "from" bits of val
///
template <
    typename T,
    typename = std::enable_if<std::is_integral<T>::value>
    >
auto
upper(T val, uintptr_t from) noexcept
{
    return static_cast<T>(static_cast<uintptr_t>(val) & ~((0x1ULL << from) - 1));
}

/// Upper
///
/// @param val the pointer to mask
/// @param from the number of bits to mask
/// @return the upper "from" bits of val
///
template<class T>
auto
upper(T *val, uintptr_t from) noexcept
{
    return reinterpret_cast<T *>(reinterpret_cast<uintptr_t>(val) & ~((0x1ULL << from) - 1));
}

}

#endif
