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

#ifndef BITMAP_H
#define BITMAP_H

#include <stdint.h>
#include <memory>

class bitmap
{
public:

    /// Constructor
    ///
    /// @param num_bits size of the bitmap in bits
    ///
    bitmap(uint32_t num_bits);

    /// Destructor
    ///
    virtual ~bitmap() {}

    /// Virtual Address
    ///
    /// @return the virtual address of the beginning of the bitmap
    ///
    uint64_t virt_addr() const noexcept
    { return m_virt_addr; }

    /// Physical Address
    ///
    /// @return the virtual address of the beginning of the bitmap
    ///
    uint64_t phys_addr() const noexcept
    { return m_phys_addr; }

    /// Set Bit
    ///
    /// @param n nth bit to set in the bitmap
    ///
    void set_bit(uint32_t n) noexcept;

    /// Reset Bit
    ///
    /// @param n nth bit to clear in the bitmap
    ///
    void clear_bit(uint32_t n) noexcept;

    /// Get Bit
    ///
    /// @param n nth bit's status to return
    /// @return true if the bit is set, false otherwise
    ///
    bool bit(uint32_t n) const noexcept;

private:
    uint32_t m_length;
    uint64_t m_virt_addr;
    uint64_t m_phys_addr;
    std::unique_ptr<uint8_t[]> m_bitmap;
};

#endif
