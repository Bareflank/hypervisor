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

#include <vmcs/bitmap.h>
#include <memory_manager/memory_manager.h>

bitmap::bitmap(uint32_t num_bits)
{
    m_length = num_bits >> 3;

    if (num_bits & 7)
        m_length++;

    m_bitmap = std::make_unique<uint8_t[]>(m_length);

    m_virt_addr = (uint64_t)m_bitmap.get();
    m_phys_addr = (uint64_t)g_mm->virt_to_phys(m_bitmap.get());
}

void bitmap::set_bit(uint32_t n) noexcept
{
    if ((n >> 3) > m_length)
        return;

    m_bitmap.get()[n >> 3] |= (1 << (n & 7));
}

void bitmap::clear_bit(uint32_t n) noexcept
{
    if ((n >> 3) > m_length)
        return;

    m_bitmap.get()[n >> 3] &= ~(1 << (n & 7));
}

bool bitmap::bit(uint32_t n) const noexcept
{
    if ((n >> 3) > m_length)
        return false;

    if (m_bitmap.get()[n >> 3] & (1 << (n & 7)))
        return true;

    return false;
}
