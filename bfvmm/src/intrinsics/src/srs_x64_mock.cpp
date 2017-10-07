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

#include <intrinsics/x86/common/srs_x64.h>

extern "C" uint16_t
_read_es(void) noexcept
{
    std::cerr << __BFFUNC__ << " called" << '\n';
    return 0;
}

extern "C" void
_write_es(uint16_t val) noexcept
{
    std::cerr << __BFFUNC__ << " called with: " << view_as_pointer(val) << '\n';
}

extern "C" uint16_t
_read_cs(void) noexcept
{
    std::cerr << __BFFUNC__ << " called" << '\n';
    return 0;
}

extern "C" void
_write_cs(uint16_t val) noexcept
{
    std::cerr << __BFFUNC__ << " called with: " << view_as_pointer(val) << '\n';
}

extern "C" uint16_t
_read_ss(void) noexcept
{
    std::cerr << __BFFUNC__ << " called" << '\n';
    return 0;
}

extern "C" void
_write_ss(uint16_t val) noexcept
{
    std::cerr << __BFFUNC__ << " called with: " << view_as_pointer(val) << '\n';
}

extern "C" uint16_t
_read_ds(void) noexcept
{
    std::cerr << __BFFUNC__ << " called" << '\n';
    return 0;
}

extern "C" void
_write_ds(uint16_t val) noexcept
{
    std::cerr << __BFFUNC__ << " called with: " << view_as_pointer(val) << '\n';
}

extern "C" uint16_t
_read_fs(void) noexcept
{
    std::cerr << __BFFUNC__ << " called" << '\n';
    return 0;
}

extern "C" void
_write_fs(uint16_t val) noexcept
{
    std::cerr << __BFFUNC__ << " called with: " << view_as_pointer(val) << '\n';
}

extern "C" uint16_t
_read_gs(void) noexcept
{
    std::cerr << __BFFUNC__ << " called" << '\n';
    return 0;
}

extern "C" void
_write_gs(uint16_t val) noexcept
{
    std::cerr << __BFFUNC__ << " called with: " << view_as_pointer(val) << '\n';
}

extern "C" uint16_t
_read_ldtr(void) noexcept
{
    std::cerr << __BFFUNC__ << " called" << '\n';
    return 0;
}

extern "C" void
_write_ldtr(uint16_t val) noexcept
{
    std::cerr << __BFFUNC__ << " called with: " << view_as_pointer(val) << '\n';
}

extern "C" uint16_t
_read_tr(void) noexcept
{
    std::cerr << __BFFUNC__ << " called" << '\n';
    return 0;
}

extern "C" void
_write_tr(uint16_t val) noexcept
{
    std::cerr << __BFFUNC__ << " called with: " << view_as_pointer(val) << '\n';
}
