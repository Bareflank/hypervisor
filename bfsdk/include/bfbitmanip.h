//
// Bareflank Hypervisor
//
// Copyright (C) 2015 Assured Information Security, Inc.
// Author: Rian Quinn        <quinnr@ainfosec.com>
// Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULLAR PURPOSE. See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

///
/// @file bfbitmanip.h
///

#ifndef BFBITMANIP_H
#define BFBITMANIP_H

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
auto
set_bit(T t, B b) noexcept
{
    return t | (0x1ULL << b);
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
auto
clear_bit(T t, B b) noexcept
{
    return t & ~(0x1ULL << b);
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
auto
get_bit(T t, B b) noexcept
{
    return (t & (0x1ULL << b)) >> b;
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
auto
is_bit_set(T t, B b) noexcept
{
    return get_bit(t, b) != 0;
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
auto
is_bit_cleared(T t, B b) noexcept
{
    return get_bit(t, b) == 0;
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
auto
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
auto
set_bits(T t, M m, V v) noexcept
{
    return (t & ~m) | (v & m);
}

#endif
