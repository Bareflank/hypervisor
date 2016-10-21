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

#include <gsl/gsl>
#include <debug.h>

extern "C" uint16_t
__attribute__((weak)) __read_es(void) noexcept
{
    std::cerr << __FUNC__ << " called" << '\n';
    abort();
}

extern "C" void
__attribute__((weak)) __write_es(uint16_t val) noexcept
{
    std::cerr << __FUNC__ << " called with: " << view_as_pointer(val) << '\n';
    abort();
}

extern "C" uint16_t
__attribute__((weak)) __read_cs(void) noexcept
{
    std::cerr << __FUNC__ << " called" << '\n';
    abort();
}

extern "C" void
__attribute__((weak)) __write_cs(uint16_t val) noexcept
{
    std::cerr << __FUNC__ << " called with: " << view_as_pointer(val) << '\n';
    abort();
}

extern "C" uint16_t
__attribute__((weak)) __read_ss(void) noexcept
{
    std::cerr << __FUNC__ << " called" << '\n';
    abort();
}

extern "C" void
__attribute__((weak)) __write_ss(uint16_t val) noexcept
{
    std::cerr << __FUNC__ << " called with: " << view_as_pointer(val) << '\n';
    abort();
}

extern "C" uint16_t
__attribute__((weak)) __read_ds(void) noexcept
{
    std::cerr << __FUNC__ << " called" << '\n';
    abort();
}

extern "C" void
__attribute__((weak)) __write_ds(uint16_t val) noexcept
{
    std::cerr << __FUNC__ << " called with: " << view_as_pointer(val) << '\n';
    abort();
}

extern "C" uint16_t
__attribute__((weak)) __read_fs(void) noexcept
{
    std::cerr << __FUNC__ << " called" << '\n';
    abort();
}

extern "C" void
__attribute__((weak)) __write_fs(uint16_t val) noexcept
{
    std::cerr << __FUNC__ << " called with: " << view_as_pointer(val) << '\n';
    abort();
}

extern "C" uint16_t
__attribute__((weak)) __read_gs(void) noexcept
{
    std::cerr << __FUNC__ << " called" << '\n';
    abort();
}

extern "C" void
__attribute__((weak)) __write_gs(uint16_t val) noexcept
{
    std::cerr << __FUNC__ << " called with: " << view_as_pointer(val) << '\n';
    abort();
}

extern "C" uint16_t
__attribute__((weak)) __read_ldtr(void) noexcept
{
    std::cerr << __FUNC__ << " called" << '\n';
    abort();
}

extern "C" void
__attribute__((weak)) __write_ldtr(uint16_t val) noexcept
{
    std::cerr << __FUNC__ << " called with: " << view_as_pointer(val) << '\n';
    abort();
}

extern "C" uint16_t
__attribute__((weak)) __read_tr(void) noexcept
{
    std::cerr << __FUNC__ << " called" << '\n';
    abort();
}

extern "C" void
__attribute__((weak)) __write_tr(uint16_t val) noexcept
{
    std::cerr << __FUNC__ << " called with: " << view_as_pointer(val) << '\n';
    abort();
}
