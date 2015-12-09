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

#include <memory_manager/page.h>

page::page() :
    m_phys(0),
    m_virt(0),
    m_size(0),
    m_allocated(false)
{
}

page::page(void *phys, void *virt, uint64_t size) :
    m_phys(phys),
    m_virt(virt),
    m_size(size),
    m_allocated(false)
{
}

page::~page()
{
}

bool page::is_valid() const
{
    return (m_phys != 0) &&
           (m_virt != 0) &&
           (m_size != 0);
}

bool page::is_allocated() const
{
    return m_allocated;
}

void page::allocate()
{
    m_allocated = true;
}

void page::free()
{
    m_allocated = false;
}

void *page::phys_addr() const
{
    return m_phys;
}

void *page::virt_addr() const
{
    return m_virt;
}

uint64_t page::size() const
{
    return m_size;
}

page::page(const page &other)
{
    *this = other;
}

void page::operator=(const page &other)
{
    m_phys = other.m_phys;
    m_virt = other.m_virt;
    m_size = other.m_size;
    m_allocated = other.m_allocated;
}

bool page::operator==(const page &other)
{
    return m_phys == other.m_phys &&
           m_virt == other.m_virt &&
           m_size == other.m_size;
}

bool page::operator!=(const page &other)
{
    return !(*this == other);
}
