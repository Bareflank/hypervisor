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
/// @file bfbitmanip.h
///

#ifndef BFBITMANIP_H
#define BFBITMANIP_H

#include <bfgsl.h>

#include <bitset>
#include <type_traits>

/// Set Bit
///
/// Sets a bit given the bit position and an integer.
///
/// @expects
/// @ensures
///
/// @param t integer whose bit is to be set
/// @param b bit position
/// @return t with bit set at position b
///
template <
    typename T,
    typename B,
    typename = std::enable_if<std::is_integral<T>::value>,
    typename = std::enable_if<std::is_integral<B>::value>
    >
constexpr auto
set_bit(T t, B b) noexcept
{
    return t | (0x1ULL << b);
}

/// Set Bit
///
/// Sets a bit given the bit position and an integer.
///
/// @expects
/// @ensures
///
/// @param view view whose bit is to be set
/// @param b bit position
/// @return t with bit set at position b
///
template <
    typename T,
    typename B,
    typename = std::enable_if<std::is_pointer<T>::value>,
    typename = std::enable_if<std::is_integral<B>::value>
    >
constexpr auto
set_bit(gsl::span<T> &view, B b)
{
    auto byte_view = gsl::as_writeable_bytes(view);
    byte_view.at(b >> 3) |= gsl::narrow_cast<gsl::byte>((1 << (b & 7)));
}

/// Clear Bit
///
/// Clears a bit given the bit position and an integer.
///
/// @expects
/// @ensures
///
/// @param t integer whose bit is to be cleared
/// @param b bit position
/// @return t with bit cleared at position b
///
template <
    typename T,
    typename B,
    typename = std::enable_if<std::is_integral<T>::value>,
    typename = std::enable_if<std::is_integral<B>::value>
    >
constexpr auto
clear_bit(T t, B b) noexcept
{
    return t & ~(0x1ULL << b);
}

/// Clear Bit
///
/// Clears a bit given the bit position and an integer.
///
/// @expects
/// @ensures
///
/// @param view view whose bit is to be cleared
/// @param b bit position
/// @return t with bit cleared at position b
///
template <
    typename T,
    typename B,
    typename = std::enable_if<std::is_pointer<T>::value>,
    typename = std::enable_if<std::is_integral<B>::value>
    >
constexpr auto
clear_bit(gsl::span<T> &view, B b)
{
    auto byte_view = gsl::as_writeable_bytes(view);
    byte_view.at(b >> 3) &= gsl::narrow_cast<gsl::byte>(~(1 << (b & 7)));
}

/// Get Bit
///
/// @expects
/// @ensures
///
/// @param t integer whose bit is to be gotten
/// @param b bit position
/// @return value of bit b for integer t
///
template <
    typename T,
    typename B,
    typename = std::enable_if<std::is_integral<T>::value>,
    typename = std::enable_if<std::is_integral<B>::value>
    >
constexpr auto
get_bit(T t, B b) noexcept
{
    return (t & (0x1ULL << b)) >> b;
}

/// Get Bit
///
/// @expects
/// @ensures
///
/// @param view view whose bit is to be gotten
/// @param b bit position
/// @return value of bit b for integer t
///
template <
    typename T,
    typename B,
    typename = std::enable_if<std::is_pointer<T>::value>,
    typename = std::enable_if<std::is_integral<B>::value>
    >
constexpr auto
get_bit(const gsl::span<T> &view, B b)
{
    auto byte_view = gsl::as_writeable_bytes(view);
    return byte_view.at(b >> 3) & gsl::narrow_cast<gsl::byte>((1 << (b & 7)));
}

/// Is Bit Set
///
/// @expects
/// @ensures
///
/// @param t integer whose bit is to be tested
/// @param b bit position
/// @return true if bit b in t is set, false otherwise
///
template <
    typename T,
    typename B,
    typename = std::enable_if<std::is_integral<T>::value>,
    typename = std::enable_if<std::is_integral<B>::value>
    >
constexpr auto
is_bit_set(T t, B b) noexcept
{
    return static_cast<uint64_t>(get_bit(t, b)) != static_cast<uint64_t>(0);
}

/// Is Bit Cleared
///
/// @expects
/// @ensures
///
/// @param t integer whose bit is to be tested
/// @param b bit position
/// @return true if bit b in t is cleared, false otherwise
///
template <
    typename T,
    typename B,
    typename = std::enable_if<std::is_integral<T>::value>,
    typename = std::enable_if<std::is_integral<B>::value>
    >
constexpr auto
is_bit_cleared(T t, B b) noexcept
{
    return static_cast<uint64_t>(get_bit(t, b)) == static_cast<uint64_t>(0);
}

/// Number of Bits Set
///
/// @expects
/// @ensures
///
/// @param t integer whose bit is to be tested
/// @return the number of bits set in t
///
template <
    typename T,
    typename = std::enable_if<std::is_integral<T>::value>
    >
auto
num_bits_set(T t) noexcept
{
    std::bitset<64> b{t};
    return b.count();
}

/// Get Bits
///
/// @expects
/// @ensures
///
/// @param t integer whose bits are to be gotten
/// @param m the bit mask
/// @return t & m
///
template <
    typename T,
    typename M,
    typename = std::enable_if<std::is_integral<T>::value>,
    typename = std::enable_if<std::is_integral<M>::value>
    >
constexpr auto
get_bits(T t, M m) noexcept
{
    return t & m;
}

/// Set Bits
///
/// @expects
/// @ensures
///
/// @param t integer whose bits are to be set
/// @param m the bit mask
/// @param v the bits to set
/// @return t with bits set to v masked by m
///
template <
    typename T,
    typename M,
    typename V,
    typename = std::enable_if<std::is_integral<T>::value>,
    typename = std::enable_if<std::is_integral<M>::value>,
    typename = std::enable_if<std::is_integral<V>::value>
    >
constexpr auto
set_bits(T t, M m, V v) noexcept
{
    return (t & ~m) | (v & m);
}

#endif
