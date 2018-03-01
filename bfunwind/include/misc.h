//
// Bareflank Unwind Library
// Copyright (C) 2015 Assured Information Security, Inc.
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

#ifndef MISC_H
#define MISC_H

#include <abort.h>
#include <stdint.h>

inline uint64_t bfabs(int64_t value)
{ return value >= 0 ? static_cast<uint64_t>(value) : static_cast<uint64_t>(-value); }

inline uint64_t
add_offset(uint64_t value, int64_t offset)
{
    auto abs_offset = bfabs(offset);

    if (offset >= 0) {
        return value + abs_offset;
    }

    if (value >= abs_offset) {
        return value - abs_offset;
    }

    ABORT("attempted add an offset that would result in overflow");
    return 0;
}

#endif
