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

#include <debug.h>

#include <exception.h>
#include <intrinsics/gdt_x64.h>

gdt_x64::gdt_x64(uint16_t size) :
    m_size(0)
{
    if (size == 0)
        return;

    auto addr = new uint64_t[size]();

    m_gdt_reg.base = (uint64_t)addr;
    m_gdt_reg.limit = (uint16_t)(size << 3);

    m_size = size;
    m_gdt = std::shared_ptr<uint64_t>(addr);
}

gdt_x64::gdt_x64(const std::shared_ptr<intrinsics_x64> &intrinsics) :
    m_size(0)
{
    if (!intrinsics)
        return;

    intrinsics->read_gdt(&m_gdt_reg);

    m_size = m_gdt_reg.limit >> 3;
    m_gdt = std::shared_ptr<uint64_t>((uint64_t *)m_gdt_reg.base, [](uint64_t *) {});
}

uint64_t
gdt_x64::base() const
{
    return m_gdt_reg.base;
}

uint16_t
gdt_x64::limit() const
{
    return m_gdt_reg.limit;
}

void
gdt_x64::set_base(uint16_t index, uint64_t addr)
{
    if (index == 0)
        return;

    uint64_t sd1 = 0;
    uint64_t sd2 = 0;

    if (index >= m_size)
        throw std::invalid_argument("index out of range");

    sd1 = m_gdt.get()[index];
    if (index + 1 < m_size) sd2 = m_gdt.get()[index + 1];

    sd1 = (sd1 & 0x00FFFF000000FFFF);
    sd2 = (sd2 & 0xFFFFFFFF00000000);

    // The segment base description can be found in the intel's software
    // developer's manual, volume 3, chapter 3.4.5 as well as volume 3,
    // chapter 24.4.1.
    //
    // Note that in 64bit mode, system descriptors are 16 bytes long
    // instread of the traditional 8 bytes. A system descriptor has the
    // system flag set to 0. Most of the time, this is going to be the
    // TSS descriptor. Even though Intel Tasks don't exist in 64 bit mode,
    // the TSS descriptor is still used, and thus, TR must still be loaded.
    //
    // ------------------------------------------------------------------
    // |                       Base 63-32                               |
    // ------------------------------------------------------------------
    // |   Base 31-24   |                              |   Base 23-16   |
    // ------------------------------------------------------------------
    // |          Base 15-00         |                                  |
    // ------------------------------------------------------------------
    //

    uint64_t base_15_00 = ((addr & 0x000000000000FFFF) << 16);
    uint64_t base_23_16 = ((addr & 0x0000000000FF0000) << 16);
    uint64_t base_31_24 = ((addr & 0x00000000FF000000) << 32);
    uint64_t base_63_32 = ((addr & 0xFFFFFFFF00000000) >> 32);

    if ((sd1 & 0x100000000000) == 0)
    {
        if (index + 1 >= m_size)
            throw std::invalid_argument("index does not point to a valid TSS");

        m_gdt.get()[index + 0] = sd1 | base_31_24 | base_23_16 | base_15_00;
        m_gdt.get()[index + 1] = sd2 | base_63_32;
    }
    else
    {
        m_gdt.get()[index + 0] = sd1 | base_31_24 | base_23_16 | base_15_00;
    }
}

uint64_t
gdt_x64::base(uint16_t index) const
{
    if (index == 0)
        return 0;

    uint64_t sd1 = 0;
    uint64_t sd2 = 0;

    if (index >= m_size)
        throw std::invalid_argument("index out of range");

    sd1 = m_gdt.get()[index];
    if (index + 1 < m_size) sd2 = m_gdt.get()[index + 1];

    // The segment base description can be found in the intel's software
    // developer's manual, volume 3, chapter 3.4.5 as well as volume 3,
    // chapter 24.4.1.
    //
    // Note that in 64bit mode, system descriptors are 16 bytes long
    // instread of the traditional 8 bytes. A system descriptor has the
    // system flag set to 0. Most of the time, this is going to be the
    // TSS descriptor. Even though Intel Tasks don't exist in 64 bit mode,
    // the TSS descriptor is still used, and thus, TR must still be loaded.
    //
    // ------------------------------------------------------------------
    // |                       Base 63-32                               |
    // ------------------------------------------------------------------
    // |   Base 31-24   |                              |   Base 23-16   |
    // ------------------------------------------------------------------
    // |          Base 15-00         |                                  |
    // ------------------------------------------------------------------
    //

    uint64_t base_15_00 = ((sd1 & 0x00000000FFFF0000) >> 16);
    uint64_t base_23_16 = ((sd1 & 0x000000FF00000000) >> 16);
    uint64_t base_31_24 = ((sd1 & 0xFF00000000000000) >> 32);
    uint64_t base_63_32 = ((sd2 & 0x00000000FFFFFFFF) << 32);

    if ((sd1 & 0x100000000000) == 0)
    {
        if (index + 1 >= m_size)
            throw std::invalid_argument("index does not point to a valid TSS");

        return base_63_32 | base_31_24 | base_23_16 | base_15_00;
    }
    else
    {
        return base_31_24 | base_23_16 | base_15_00;
    }
}

void
gdt_x64::set_limit(uint16_t index, uint64_t limit)
{
    if (index == 0)
        return;

    if (index >= m_size)
        throw std::invalid_argument("index out of range");

    uint64_t sd1 = (m_gdt.get()[index] & 0xFFF0FFFFFFFF0000);

    // The segment limit description can be found in the intel's software
    // developer's manual, volume 3, chapter 3.4.5 as well as volume 3,
    // chapter 24.4.1.
    //
    // ------------------------------------------------------------------
    // |               | Limit 19-16 |                                  |
    // ------------------------------------------------------------------
    // |                             |            Limit 15-00           |
    // ------------------------------------------------------------------

    if ((sd1 & 0x80000000000000) != 0)
        limit = (limit >> 12);

    uint64_t limit_15_00 = ((limit & 0x000000000000FFFF) << 0);
    uint64_t limit_19_16 = ((limit & 0x00000000000F0000) << 32);

    m_gdt.get()[index] = sd1 | limit_19_16 | limit_15_00;
}

uint64_t
gdt_x64::limit(uint16_t index) const
{
    if (index == 0)
        return 0;

    if (index >= m_size)
        throw std::invalid_argument("index out of range");

    uint64_t sd1 = m_gdt.get()[index];

    // The segment limit description can be found in the intel's software
    // developer's manual, volume 3, chapter 3.4.5 as well as volume 3,
    // chapter 24.4.1.
    //
    // ------------------------------------------------------------------
    // |               | Limit 19-16 |                                  |
    // ------------------------------------------------------------------
    // |                             |            Limit 15-00           |
    // ------------------------------------------------------------------

    if ((sd1 & 0x80000000000000) != 0)
    {
        uint64_t limit_15_00 = ((sd1 & 0x000000000000FFFF) >> 0);
        uint64_t limit_19_16 = ((sd1 & 0x000F000000000000) >> 32);

        return ((limit_19_16 | limit_15_00) << 12) | 0x0000000000000FFF;
    }
    else
    {
        uint64_t limit_15_00 = ((sd1 & 0x000000000000FFFF) >> 0);
        uint64_t limit_19_16 = ((sd1 & 0x000F000000000000) >> 32);

        return limit_19_16 | limit_15_00;
    }
}

void
gdt_x64::set_access_rights(uint16_t index, uint64_t access_rights)
{
    if (index == 0)
        return;

    if (index >= m_size)
        throw std::invalid_argument("index out of range");

    uint64_t sd1 = (m_gdt.get()[index] & 0xFF0F00FFFFFFFFFF);

    // The segment access description can be found in the intel's software
    // developer's manual, volume 3, chapter 3.4.5 as well as volume 3,
    // chapter 24.4.1.
    //
    // ------------------------------------------------------------------
    // |           | A 15-12 |       |  Access 07-00   |                |
    // ------------------------------------------------------------------
    // |                             |                                  |
    // ------------------------------------------------------------------
    //

    uint64_t access_rights_07_00 = ((access_rights & 0x00000000000000FF) << 40);
    uint64_t access_rights_15_12 = ((access_rights & 0x000000000000F000) << 40);

    m_gdt.get()[index] = sd1 | access_rights_15_12 | access_rights_07_00;
}

uint64_t
gdt_x64::access_rights(uint16_t index) const
{
    // Note that unlike the other functions, when the selector is for the
    // null segment, we need to return the following. This tells the system
    // that this is a unusable segment.
    //

    if (index == 0)
        return 0x10000;

    if (index >= m_size)
        throw std::invalid_argument("index out of range");

    uint64_t sd1 = m_gdt.get()[index];

    // The segment access description can be found in the intel's software
    // developer's manual, volume 3, chapter 3.4.5 as well as volume 3,
    // chapter 24.4.1.
    //
    // ------------------------------------------------------------------
    // |           | A 15-12 |       |  Access 07-00   |                |
    // ------------------------------------------------------------------
    // |                             |                                  |
    // ------------------------------------------------------------------
    //

    uint64_t access_rights_07_00 = ((sd1 & 0x0000FF0000000000) >> 40);
    uint64_t access_rights_15_12 = ((sd1 & 0x00F0000000000000) >> 40);

    return access_rights_15_12 | access_rights_07_00;
}
