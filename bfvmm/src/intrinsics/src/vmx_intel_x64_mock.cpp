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

extern "C" bool
__attribute__((weak)) __vmxon(void *ptr)
{
    (void) ptr;

    bferror << static_cast<const char *>(__PRETTY_FUNCTION__) << " called" << bfendl;
    abort();
}

extern "C" bool
__attribute__((weak)) __vmxoff(void) noexcept
{
    bferror << static_cast<const char *>(__PRETTY_FUNCTION__) << " called" << bfendl;
    abort();
}

extern "C" bool
__attribute__((weak)) __vmclear(void *ptr) noexcept
{
    (void) ptr;

    bferror << static_cast<const char *>(__PRETTY_FUNCTION__) << " called" << bfendl;
    abort();
}

extern "C" bool
__attribute__((weak)) __vmptrld(void *ptr) noexcept
{
    (void) ptr;

    bferror << static_cast<const char *>(__PRETTY_FUNCTION__) << " called" << bfendl;
    abort();
}

extern "C" bool
__attribute__((weak)) __vmptrst(void *ptr) noexcept
{
    (void) ptr;

    bferror << static_cast<const char *>(__PRETTY_FUNCTION__) << " called" << bfendl;
    abort();
}

extern "C" bool
__attribute__((weak)) __vmwrite(uint64_t field, uint64_t value) noexcept
{
    bferror << static_cast<const char *>(__PRETTY_FUNCTION__) << " called with: " << bfendl;
    bferror << "    - field: " << view_as_pointer(field) << '\n';
    bferror << "    - value: " << view_as_pointer(value) << '\n';
    abort();
}

extern "C" bool
__attribute__((weak)) __vmread(uint64_t field, uint64_t *value) noexcept
{
    (void) value;

    bferror << static_cast<const char *>(__PRETTY_FUNCTION__) << " called with: " << bfendl;
    bferror << "    - field: " << view_as_pointer(field) << '\n';
    abort();
}

extern "C" bool
__attribute__((weak)) __vmlaunch(void) noexcept
{
    bferror << static_cast<const char *>(__PRETTY_FUNCTION__) << " called" << bfendl;
    abort();
}
