//
// Bareflank Hypervisor
// Copyright (C) 2018 Assured Information Security, Inc.
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

#include <debug/serial/serial_ns16550a.h>

namespace bfvmm
{

uint8_t
serial_ns16550a::inb(uint16_t addr) const noexcept
{
    return x64::portio::inb(static_cast<uint16_t>(addr + m_addr));
}

void
serial_ns16550a::outb(uint16_t addr, uint8_t data) const noexcept
{
    x64::portio::outb(static_cast<uint16_t>(addr + m_addr), data);
}

}
