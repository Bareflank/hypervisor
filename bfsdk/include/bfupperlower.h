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
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

///
/// @file bfupperlower.h
///

#ifndef BFUPPERLOWER_H
#define BFUPPERLOWER_H

#include <bftypes.h>

namespace bfn
{

/// Lower
///
/// @param val the pointer to mask
/// @return the lower 12 bits of val
///
template <
    typename T,
    typename = std::enable_if_t<std::is_integral<T>::value>
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
    typename = std::enable_if_t<std::is_integral<T>::value>
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
    typename = std::enable_if_t<std::is_integral<T>::value>
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
    typename = std::enable_if_t<std::is_integral<T>::value>
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
