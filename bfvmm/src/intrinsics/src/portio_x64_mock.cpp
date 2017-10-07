//
// Bareflank Hypervisor
// Copyright (C) 2015 Assured Information Security, Inc.
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

#include <bfgsl.h>
#include <bfdebug.h>

#include <intrinsics/x86/common/portio_x64.h>

extern "C" uint8_t
_inb(uint16_t port) noexcept
{
    std::cerr << __BFFUNC__ << " called with: " << '\n';
    std::cerr << "    - port: " << view_as_pointer(port) << '\n';
    return 0;
}

extern "C" uint16_t
_inw(uint16_t port) noexcept
{
    std::cerr << __BFFUNC__ << " called with: " << '\n';
    std::cerr << "    - port: " << view_as_pointer(port) << '\n';
    return 0;
}

extern "C" uint32_t
_ind(uint16_t port) noexcept
{
    std::cerr << __BFFUNC__ << " called with: " << '\n';
    std::cerr << "    - port: " << view_as_pointer(port) << '\n';
    return 0;
}

extern "C" void
_insb(uint16_t port, uint64_t m8) noexcept
{
    std::cerr << __BFFUNC__ << " called with: " << '\n';
    std::cerr << "    - port: " << view_as_pointer(port) << '\n';
    std::cerr << "    - m8: " << view_as_pointer(m8) << '\n';
}

extern "C" void
_insw(uint16_t port, uint64_t m16) noexcept
{
    std::cerr << __BFFUNC__ << " called with: " << '\n';
    std::cerr << "    - port: " << view_as_pointer(port) << '\n';
    std::cerr << "    - m16: " << view_as_pointer(m16) << '\n';
}

extern "C" void
_insd(uint16_t port, uint64_t m32) noexcept
{
    std::cerr << __BFFUNC__ << " called with: " << '\n';
    std::cerr << "    - port: " << view_as_pointer(port) << '\n';
    std::cerr << "    - m32: " << view_as_pointer(m32) << '\n';
}

extern "C" void
_insbrep(uint16_t port, uint64_t m8, uint32_t count) noexcept
{
    std::cerr << __BFFUNC__ << " called with: " << '\n';
    std::cerr << "    - port: " << view_as_pointer(port) << '\n';
    std::cerr << "    - m8: " << view_as_pointer(m8) << '\n';
    std::cerr << "    - count: " << view_as_pointer(count) << '\n';
}

extern "C" void
_inswrep(uint16_t port, uint64_t m16, uint32_t count) noexcept
{
    std::cerr << __BFFUNC__ << " called with: " << '\n';
    std::cerr << "    - port: " << view_as_pointer(port) << '\n';
    std::cerr << "    - m16: " << view_as_pointer(m16) << '\n';
    std::cerr << "    - count: " << view_as_pointer(count) << '\n';
}

extern "C" void
_insdrep(uint16_t port, uint64_t m32, uint32_t count) noexcept
{
    std::cerr << __BFFUNC__ << " called with: " << '\n';
    std::cerr << "    - port: " << view_as_pointer(port) << '\n';
    std::cerr << "    - m32: " << view_as_pointer(m32) << '\n';
    std::cerr << "    - count: " << view_as_pointer(count) << '\n';
}

extern "C" void
_outb(uint16_t port, uint8_t val) noexcept
{
    std::cerr << __BFFUNC__ << " called with: " << '\n';
    std::cerr << "    - port: " << view_as_pointer(port) << '\n';
    std::cerr << "    - val: " << view_as_pointer(val) << '\n';
}

extern "C" void
_outw(uint16_t port, uint16_t val) noexcept
{
    std::cerr << __BFFUNC__ << " called with: " << '\n';
    std::cerr << "    - port: " << view_as_pointer(port) << '\n';
    std::cerr << "    - val: " << view_as_pointer(val) << '\n';
}

extern "C" void
_outd(uint16_t port, uint32_t val) noexcept
{
    std::cerr << __BFFUNC__ << " called with: " << '\n';
    std::cerr << "    - port: " << view_as_pointer(port) << '\n';
    std::cerr << "    - val: " << view_as_pointer(val) << '\n';
}

extern "C" void
_outsb(uint16_t port, uint64_t m8) noexcept
{
    std::cerr << __BFFUNC__ << " called with: " << '\n';
    std::cerr << "    - port: " << view_as_pointer(port) << '\n';
    std::cerr << "    - m8: " << view_as_pointer(m8) << '\n';
}

extern "C" void
_outsw(uint16_t port, uint64_t m16) noexcept
{
    std::cerr << __BFFUNC__ << " called with: " << '\n';
    std::cerr << "    - port: " << view_as_pointer(port) << '\n';
    std::cerr << "    - m16: " << view_as_pointer(m16) << '\n';
}

extern "C" void
_outsd(uint16_t port, uint64_t m32) noexcept
{
    std::cerr << __BFFUNC__ << " called with: " << '\n';
    std::cerr << "    - port: " << view_as_pointer(port) << '\n';
    std::cerr << "    - m32: " << view_as_pointer(m32) << '\n';
}

extern "C" void
_outsbrep(uint16_t port, uint64_t m8, uint32_t count) noexcept
{
    std::cerr << __BFFUNC__ << " called with: " << '\n';
    std::cerr << "    - port: " << view_as_pointer(port) << '\n';
    std::cerr << "    - m8: " << view_as_pointer(m8) << '\n';
    std::cerr << "    - count: " << view_as_pointer(count) << '\n';
}

extern "C" void
_outswrep(uint16_t port, uint64_t m16, uint32_t count) noexcept
{
    std::cerr << __BFFUNC__ << " called with: " << '\n';
    std::cerr << "    - port: " << view_as_pointer(port) << '\n';
    std::cerr << "    - m16: " << view_as_pointer(m16) << '\n';
    std::cerr << "    - count: " << view_as_pointer(count) << '\n';
}

extern "C" void
_outsdrep(uint16_t port, uint64_t m32, uint32_t count) noexcept
{
    std::cerr << __BFFUNC__ << " called with: " << '\n';
    std::cerr << "    - port: " << view_as_pointer(port) << '\n';
    std::cerr << "    - m32: " << view_as_pointer(m32) << '\n';
    std::cerr << "    - count: " << view_as_pointer(count) << '\n';
}
