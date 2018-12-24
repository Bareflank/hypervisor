//
// Copyright (C) 2019 Assured Information Security, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#ifndef PORTIO_X64_H
#define PORTIO_X64_H

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

extern "C" uint8_t _inb(uint16_t port) noexcept;
extern "C" uint16_t _inw(uint16_t port) noexcept;
extern "C" uint32_t _ind(uint16_t port) noexcept;

extern "C" void _insb(uint16_t port, uint64_t m8) noexcept;
extern "C" void _insw(uint16_t port, uint64_t m16) noexcept;
extern "C" void _insd(uint16_t port, uint64_t m32) noexcept;

extern "C" void _insbrep(uint16_t port, uint64_t m8, uint32_t count) noexcept;
extern "C" void _inswrep(uint16_t port, uint64_t m16, uint32_t count) noexcept;
extern "C" void _insdrep(uint16_t port, uint64_t m32, uint32_t count) noexcept;

extern "C" void _outb(uint16_t port, uint8_t val) noexcept;
extern "C" void _outw(uint16_t port, uint16_t val) noexcept;
extern "C" void _outd(uint16_t port, uint32_t val) noexcept;

extern "C" void _outsb(uint16_t port, uint64_t m8) noexcept;
extern "C" void _outsw(uint16_t port, uint64_t m16) noexcept;
extern "C" void _outsd(uint16_t port, uint64_t m32) noexcept;

extern "C" void _outsbrep(uint16_t port, uint64_t m8, uint32_t count) noexcept;
extern "C" void _outswrep(uint16_t port, uint64_t m16, uint32_t count) noexcept;
extern "C" void _outsdrep(uint16_t port, uint64_t m32, uint32_t count) noexcept;

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

    inline auto inb(port_addr_type port) noexcept
    { return _inb(port); }

    inline auto inw(port_addr_type port) noexcept
    { return _inw(port); }

    inline auto ind(port_addr_type port) noexcept
    { return _ind(port); }

    inline auto insb(port_addr_type port, integer_pointer m8) noexcept
    { return _insb(port, m8); }

    inline auto insw(port_addr_type port, integer_pointer m16) noexcept
    { return _insw(port, m16); }

    inline auto insd(port_addr_type port, integer_pointer m32) noexcept
    { return _insd(port, m32); }

    inline auto insb(port_addr_type port, void *m8) noexcept
    { return _insb(port, reinterpret_cast<integer_pointer>(m8)); }

    inline auto insw(port_addr_type port, void *m16) noexcept
    { return _insw(port, reinterpret_cast<integer_pointer>(m16)); }

    inline auto insd(port_addr_type port, void *m32) noexcept
    { return _insd(port, reinterpret_cast<integer_pointer>(m32)); }

    inline auto insbrep(port_addr_type port, integer_pointer m8, size_type count) noexcept
    { return _insbrep(port, m8, count); }

    inline auto inswrep(port_addr_type port, integer_pointer m16, size_type count) noexcept
    { return _inswrep(port, m16, count); }

    inline auto insdrep(port_addr_type port, integer_pointer m32, size_type count) noexcept
    { return _insdrep(port, m32, count); }

    inline auto insbrep(port_addr_type port, void *m8, size_type count) noexcept
    { return _insbrep(port, reinterpret_cast<integer_pointer>(m8), count); }

    inline auto inswrep(port_addr_type port, void *m16, size_type count) noexcept
    { return _inswrep(port, reinterpret_cast<integer_pointer>(m16), count); }

    inline auto insdrep(port_addr_type port, void *m32, size_type count) noexcept
    { return _insdrep(port, reinterpret_cast<integer_pointer>(m32), count); }

    inline void outb(port_addr_type port, port_8bit_type val) noexcept
    { _outb(port, val); }

    inline void outw(port_addr_type port, port_16bit_type val) noexcept
    { _outw(port, val); }

    inline void outd(port_addr_type port, port_32bit_type val) noexcept
    { _outd(port, val); }

    inline void outsb(port_addr_type port, integer_pointer m8) noexcept
    { _outsb(port, m8); }

    inline void outsw(port_addr_type port, integer_pointer m16) noexcept
    { _outsw(port, m16); }

    inline void outsd(port_addr_type port, integer_pointer m32) noexcept
    { _outsd(port, m32); }

    inline void outsb(port_addr_type port, void *m8) noexcept
    { _outsb(port, reinterpret_cast<integer_pointer>(m8)); }

    inline void outsw(port_addr_type port, void *m16) noexcept
    { _outsw(port, reinterpret_cast<integer_pointer>(m16)); }

    inline void outsd(port_addr_type port, void *m32) noexcept
    { _outsd(port, reinterpret_cast<integer_pointer>(m32)); }

    inline void outsbrep(port_addr_type port, integer_pointer m8, size_type count) noexcept
    { _outsbrep(port, m8, count); }

    inline void outswrep(port_addr_type port, integer_pointer m16, size_type count) noexcept
    { _outswrep(port, m16, count); }

    inline void outsdrep(port_addr_type port, integer_pointer m32, size_type count) noexcept
    { _outsdrep(port, m32, count); }

    inline void outsbrep(port_addr_type port, void *m8, size_type count) noexcept
    { _outsbrep(port, reinterpret_cast<integer_pointer>(m8), count); }

    inline void outswrep(port_addr_type port, void *m16, size_type count) noexcept
    { _outswrep(port, reinterpret_cast<integer_pointer>(m16), count); }

    inline void outsdrep(port_addr_type port, void *m32, size_type count) noexcept
    { _outsdrep(port, reinterpret_cast<integer_pointer>(m32), count); }
}
}

// *INDENT-ON*

#endif
