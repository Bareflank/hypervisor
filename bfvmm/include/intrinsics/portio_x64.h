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
extern "C" uint32_t __ind(uint16_t port) noexcept;

extern "C" void __insb(uint16_t port, uint64_t m8) noexcept;
extern "C" void __insw(uint16_t port, uint64_t m16) noexcept;
extern "C" void __insd(uint16_t port, uint64_t m32) noexcept;

extern "C" void __insbrep(uint16_t port, uint64_t m8, uint32_t count) noexcept;
extern "C" void __inswrep(uint16_t port, uint64_t m16, uint32_t count) noexcept;
extern "C" void __insdrep(uint16_t port, uint64_t m32, uint32_t count) noexcept;

extern "C" void __outb(uint16_t port, uint8_t val) noexcept;
extern "C" void __outw(uint16_t port, uint16_t val) noexcept;
extern "C" void __outd(uint16_t port, uint32_t val) noexcept;

extern "C" void __outsb(uint16_t port, uint64_t m8) noexcept;
extern "C" void __outsw(uint16_t port, uint64_t m16) noexcept;
extern "C" void __outsd(uint16_t port, uint64_t m32) noexcept;

extern "C" void __outsbrep(uint16_t port, uint64_t m8, uint32_t count) noexcept;
extern "C" void __outswrep(uint16_t port, uint64_t m16, uint32_t count) noexcept;
extern "C" void __outsdrep(uint16_t port, uint64_t m32, uint32_t count) noexcept;

// *INDENT-OFF*

namespace x64
{
namespace portio
{
    using port_addr_type = uint16_t;
    using port_8bit_type = uint8_t;
    using port_16bit_type = uint16_t;
    using port_32bit_type = uint32_t;
    using integer_pointer = uintptr_t;
    using size_type = uint32_t;

    template<class P, class = typename std::enable_if<std::is_integral<P>::value>::type>
    auto inb(P port) noexcept { return __inb(gsl::narrow_cast<port_addr_type>(port)); }

    template<class P, class = typename std::enable_if<std::is_integral<P>::value>::type>
    auto inw(P port) noexcept { return __inw(gsl::narrow_cast<port_addr_type>(port)); }

    template<class P, class = typename std::enable_if<std::is_integral<P>::value>::type>
    auto ind(P port) noexcept { return __ind(gsl::narrow_cast<port_addr_type>(port)); }

    template<class P, class = typename std::enable_if<std::is_integral<P>::value>::type>
    auto insb(P port, integer_pointer m8) noexcept { return __insb(gsl::narrow_cast<port_addr_type>(port), m8); }

    template<class P, class = typename std::enable_if<std::is_integral<P>::value>::type>
    auto insw(P port, integer_pointer m16) noexcept { return __insw(gsl::narrow_cast<port_addr_type>(port), m16); }

    template<class P, class = typename std::enable_if<std::is_integral<P>::value>::type>
    auto insd(P port, integer_pointer m32) noexcept { return __insd(gsl::narrow_cast<port_addr_type>(port), m32); }

    template<class P, class = typename std::enable_if<std::is_integral<P>::value>::type>
    auto insb(P port, void *m8) noexcept { return __insb(gsl::narrow_cast<port_addr_type>(port), reinterpret_cast<integer_pointer>(m8)); }

    template<class P, class = typename std::enable_if<std::is_integral<P>::value>::type>
    auto insw(P port, void *m16) noexcept { return __insw(gsl::narrow_cast<port_addr_type>(port), reinterpret_cast<integer_pointer>(m16)); }

    template<class P, class = typename std::enable_if<std::is_integral<P>::value>::type>
    auto insd(P port, void *m32) noexcept { return __insd(gsl::narrow_cast<port_addr_type>(port), reinterpret_cast<integer_pointer>(m32)); }

    template<class P, class = typename std::enable_if<std::is_integral<P>::value>::type>
    auto insbrep(P port, integer_pointer m8, size_type count) noexcept { return __insbrep(gsl::narrow_cast<port_addr_type>(port), m8, count); }

    template<class P, class = typename std::enable_if<std::is_integral<P>::value>::type>
    auto inswrep(P port, integer_pointer m16, size_type count) noexcept { return __inswrep(gsl::narrow_cast<port_addr_type>(port), m16, count); }

    template<class P, class = typename std::enable_if<std::is_integral<P>::value>::type>
    auto insdrep(P port, integer_pointer m32, size_type count) noexcept { return __insdrep(gsl::narrow_cast<port_addr_type>(port), m32, count); }

    template<class P, class = typename std::enable_if<std::is_integral<P>::value>::type>
    auto insbrep(P port, void *m8, size_type count) noexcept { return __insbrep(gsl::narrow_cast<port_addr_type>(port), reinterpret_cast<integer_pointer>(m8), count); }

    template<class P, class = typename std::enable_if<std::is_integral<P>::value>::type>
    auto inswrep(P port, void *m16, size_type count) noexcept { return __inswrep(gsl::narrow_cast<port_addr_type>(port), reinterpret_cast<integer_pointer>(m16), count); }

    template<class P, class = typename std::enable_if<std::is_integral<P>::value>::type>
    auto insdrep(P port, void *m32, size_type count) noexcept { return __insdrep(gsl::narrow_cast<port_addr_type>(port), reinterpret_cast<integer_pointer>(m32), count); }

    template<class P, class T,
             class = typename std::enable_if<std::is_integral<P>::value>::type,
             class = typename std::enable_if<std::is_integral<T>::value>::type>
    void outb(P port, T val) noexcept { __outb(gsl::narrow_cast<port_addr_type>(port), gsl::narrow_cast<port_8bit_type>(val)); }

    template<class P, class T,
             class = typename std::enable_if<std::is_integral<P>::value>::type,
             class = typename std::enable_if<std::is_integral<T>::value>::type>
    void outw(P port, T val) noexcept { __outw(gsl::narrow_cast<port_addr_type>(port), gsl::narrow_cast<port_16bit_type>(val)); }

    template<class P, class T,
             class = typename std::enable_if<std::is_integral<P>::value>::type,
             class = typename std::enable_if<std::is_integral<T>::value>::type>
    void outd(P port, T val) noexcept { __outd(gsl::narrow_cast<port_addr_type>(port), gsl::narrow_cast<port_32bit_type>(val)); }

    template<class P, class = typename std::enable_if<std::is_integral<P>::value>::type>
    void outsb(P port, integer_pointer m8) noexcept { __outsb(gsl::narrow_cast<port_addr_type>(port), m8); }

    template<class P, class = typename std::enable_if<std::is_integral<P>::value>::type>
    void outsw(P port, integer_pointer m16) noexcept { __outsw(gsl::narrow_cast<port_addr_type>(port), m16); }

    template<class P, class = typename std::enable_if<std::is_integral<P>::value>::type>
    void outsd(P port, integer_pointer m32) noexcept { __outsd(gsl::narrow_cast<port_addr_type>(port), m32); }

    template<class P, class = typename std::enable_if<std::is_integral<P>::value>::type>
    void outsb(P port, void *m8) noexcept { __outsb(gsl::narrow_cast<port_addr_type>(port), reinterpret_cast<integer_pointer>(m8)); }

    template<class P, class = typename std::enable_if<std::is_integral<P>::value>::type>
    void outsw(P port, void *m16) noexcept { __outsw(gsl::narrow_cast<port_addr_type>(port), reinterpret_cast<integer_pointer>(m16)); }

    template<class P, class = typename std::enable_if<std::is_integral<P>::value>::type>
    void outsd(P port, void *m32) noexcept { __outsd(gsl::narrow_cast<port_addr_type>(port), reinterpret_cast<integer_pointer>(m32)); }

    template<class P, class = typename std::enable_if<std::is_integral<P>::value>::type>
    void outsbrep(P port, integer_pointer m8, size_type count) noexcept { __outsbrep(gsl::narrow_cast<port_addr_type>(port), m8, count); }

    template<class P, class = typename std::enable_if<std::is_integral<P>::value>::type>
    void outswrep(P port, integer_pointer m16, size_type count) noexcept { __outswrep(gsl::narrow_cast<port_addr_type>(port), m16, count); }

    template<class P, class = typename std::enable_if<std::is_integral<P>::value>::type>
    void outsdrep(P port, integer_pointer m32, size_type count) noexcept { __outsdrep(gsl::narrow_cast<port_addr_type>(port), m32, count); }

    template<class P, class = typename std::enable_if<std::is_integral<P>::value>::type>
    void outsbrep(P port, void *m8, size_type count) noexcept { __outsbrep(gsl::narrow_cast<port_addr_type>(port), reinterpret_cast<integer_pointer>(m8), count); }

    template<class P, class = typename std::enable_if<std::is_integral<P>::value>::type>
    void outswrep(P port, void *m16, size_type count) noexcept { __outswrep(gsl::narrow_cast<port_addr_type>(port), reinterpret_cast<integer_pointer>(m16), count); }

    template<class P, class = typename std::enable_if<std::is_integral<P>::value>::type>
    void outsdrep(P port, void *m32, size_type count) noexcept { __outsdrep(gsl::narrow_cast<port_addr_type>(port), reinterpret_cast<integer_pointer>(m32), count); }
}
}

// *INDENT-ON*

#endif
