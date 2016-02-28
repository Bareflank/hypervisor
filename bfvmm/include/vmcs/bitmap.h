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

#ifndef BITMAP__H
#define BITMAP__H

#include <stdint.h>
#include <memory>

class bitmap
{
public:
    /// Constructor
    /// @param num_bits size of the bitmap in bits
    ///
    bitmap(uint32_t num_bits);

    /// Destructor
    ///
    virtual ~bitmap() {}

    /// address
    /// @return the virtual address of the beginning
    ///         of the bitmap
    ///
    uint8_t *address();

    /// set_bit
    /// @param n nth bit to set in the bitmap
    ///
    void set_bit(uint32_t n);

    /// reset_bit
    /// @param n nth bit to clear in the bitmap
    ///
    void clear_bit(uint32_t n);

    /// bit
    /// @param n nth bit's status to return
    /// @return true if the bit is set, false otherwise
    ///
    bool bit(uint32_t n);

private:
    std::unique_ptr<uint8_t[]> m_bitmap;
    uint32_t m_length;
};

#endif // BITMAP__H
