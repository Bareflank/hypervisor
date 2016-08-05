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
#include <intrinsics/idt_x64.h>

idt_x64::idt_x64(uint16_t size)
{
    auto addr = new uint64_t[size << 1]();

    m_idt_reg.base = reinterpret_cast<uint64_t>(addr);
    m_idt_reg.limit = static_cast<uint16_t>((size << 4) - 1);

    m_size = size << 1;
    m_idt = std::shared_ptr<uint64_t>(addr);
}

idt_x64::idt_x64(const std::shared_ptr<intrinsics_x64> &intrinsics)
{
    if (!intrinsics)
        return;

    intrinsics->read_idt(&m_idt_reg);

    m_size = (m_idt_reg.limit + 1) >> 3;
    m_idt = std::shared_ptr<uint64_t>(reinterpret_cast<uint64_t *>(m_idt_reg.base), [](uint64_t *) {});
}

uint64_t
idt_x64::base() const
{
    return m_idt_reg.base;
}

uint16_t
idt_x64::limit() const
{
    return m_idt_reg.limit;
}
