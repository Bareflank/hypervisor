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

#ifndef PORTIO_X64_H
#define PORTIO_X64_H

#include <gsl/gsl>

extern "C" uint8_t __inb(uint16_t port) noexcept;
extern "C" uint16_t __inw(uint16_t port) noexcept;

extern "C" void __outb(uint16_t port, uint8_t val) noexcept;
extern "C" void __outw(uint16_t port, uint16_t val) noexcept;

// *INDENT-OFF*

namespace x64
{
namespace portio
{
    using port_addr_type = uint16_t;
    using port_8bit_type = uint8_t;
    using port_16bit_type = uint16_t;

    template<class P, class = typename std::enable_if<std::is_integral<P>::value>::type>
    auto inb(P port) noexcept { return __inb(gsl::narrow_cast<port_addr_type>(port)); }

    template<class P, class = typename std::enable_if<std::is_integral<P>::value>::type>
    auto inw(P port) noexcept { return __inw(gsl::narrow_cast<port_addr_type>(port)); }

    template<class P, class T,
             class = typename std::enable_if<std::is_integral<P>::value>::type,
             class = typename std::enable_if<std::is_integral<T>::value>::type>
    void outb(P port, T val) noexcept { __outb(gsl::narrow_cast<port_addr_type>(port), gsl::narrow_cast<port_8bit_type>(val)); }

    template<class P, class T,
             class = typename std::enable_if<std::is_integral<P>::value>::type,
             class = typename std::enable_if<std::is_integral<T>::value>::type>
    void outw(P port, T val) noexcept { __outw(gsl::narrow_cast<port_addr_type>(port), gsl::narrow_cast<port_16bit_type>(val)); }
}
}

// *INDENT-ON*

#endif
