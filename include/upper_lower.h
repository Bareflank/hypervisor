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

#ifndef UPPER_LOWER_H
#define UPPER_LOWER_H

#include <stdint.h>

namespace bfn
{

/// Lower
///
/// @param ptr the pointer to mask
/// @return the lower 12 bits of ptr
///
template <class T>
auto lower(T ptr) noexcept
{ return reinterpret_cast<uintptr_t>(ptr) & (0xFFFUL); }

/// Lower
///
/// @param ptr the pointer to mask
/// @param from the number of bits to mask
/// @return the lower "from" bits of ptr
///
template <class T>
auto lower(T ptr, uintptr_t from) noexcept
{ return reinterpret_cast<uintptr_t>(ptr) & ((0x1UL << from) - 1); }

/// Upper
///
/// @param ptr the pointer to mask
/// @return the upper 12 bits of ptr
///
template <class T>
auto upper(T ptr) noexcept
{ return reinterpret_cast<uintptr_t>(ptr) & ~(0xFFFUL); }

/// Upper
///
/// @param ptr the pointer to mask
/// @param from the number of bits to mask
/// @return the upper "from" bits of ptr
///
template <class T>
auto upper(T ptr, uintptr_t from) noexcept
{ return reinterpret_cast<uintptr_t>(ptr) & ~((0x1UL << from) - 1); }

}

#endif
