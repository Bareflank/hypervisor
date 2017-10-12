//
// Bareflank Hypervisor
// Copyright (C) 2017 Assured Information Security, Inc.
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

#ifndef PORTIO_AARCH64_H
#define PORTIO_AARCH64_H

namespace intrinsics
{
namespace portio
{

    using port_addr_type = uintptr_t;
    using port_8bit_type = uint8_t;
    using port_16bit_type = uint16_t;
    using port_32bit_type = uint32_t;
    using port_64bit_type = uint64_t;
    using integer_pointer = uintptr_t;
    using size_type = size_t;

    template<typename T> inline T in(port_addr_type port) noexcept
    { return *reinterpret_cast<T volatile *>(port); }

    template<typename T> inline void out(port_addr_type port, T data) noexcept
    { *reinterpret_cast<T volatile *>(port) = data; }

    inline auto inb(port_addr_type port) noexcept
    { return in<port_8bit_type>(port); }

    inline auto inw(port_addr_type port) noexcept
    { return in<port_16bit_type>(port); }

    inline auto ind(port_addr_type port) noexcept
    { return in<port_32bit_type>(port); }

    inline auto inq(port_addr_type port) noexcept
    { return in<port_64bit_type>(port); }

    inline void outb(port_addr_type port, uint8_t data) noexcept
    { return out(port, data); }

    inline void outw(port_addr_type port, uint16_t data) noexcept
    { return out(port, data); }

    inline void outd(port_addr_type port, uint32_t data) noexcept
    { return out(port, data); }

    inline void outq(port_addr_type port, uint64_t data) noexcept
    { return out(port, data); }
}
}

#endif
