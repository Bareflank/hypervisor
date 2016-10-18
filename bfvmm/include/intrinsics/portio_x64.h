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
    template<class P> auto inb(P port) noexcept
    { return __inb(gsl::narrow_cast<uint16_t>(port)); }

    template<class P> auto inw(P port) noexcept
    { return __inw(gsl::narrow_cast<uint16_t>(port)); }

    template<class P, class T> void outb(P port, T val) noexcept
    { __outb(gsl::narrow_cast<uint16_t>(port), gsl::narrow_cast<uint8_t>(val)); }

    template<class P, class T> void outw(P port, T val) noexcept
    { __outw(gsl::narrow_cast<uint16_t>(port), gsl::narrow_cast<uint16_t>(val)); }
}
}

// *INDENT-ON*

#endif
