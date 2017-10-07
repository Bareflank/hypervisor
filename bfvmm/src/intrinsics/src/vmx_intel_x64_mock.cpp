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

#include <intrinsics/x86/intel_x64.h>

extern "C" bool
_vmxon(void *ptr) noexcept
{
    (void) ptr;

    std::cerr << __BFFUNC__ << " called" << '\n';
    return true;
}

extern "C" bool
_vmxoff(void) noexcept
{
    std::cerr << __BFFUNC__ << " called" << '\n';
    return true;
}

extern "C" bool
_vmclear(void *ptr) noexcept
{
    (void) ptr;

    std::cerr << __BFFUNC__ << " called" << '\n';
    return true;
}

extern "C" bool
_vmptrld(void *ptr) noexcept
{
    (void) ptr;

    std::cerr << __BFFUNC__ << " called" << '\n';
    return true;
}

extern "C" bool
_vmptrst(void *ptr) noexcept
{
    (void) ptr;

    std::cerr << __BFFUNC__ << " called" << '\n';
    return true;
}

extern "C" bool
_vmread(uint64_t field, uint64_t *value) noexcept
{
    *value = 10;

    std::cerr << __BFFUNC__ << " called with: " << '\n';
    std::cerr << "    - field: " << view_as_pointer(field) << '\n';
    return true;
}

extern "C" bool
_vmwrite(uint64_t field, uint64_t value) noexcept
{
    std::cerr << __BFFUNC__ << " called with: " << '\n';
    std::cerr << "    - field: " << view_as_pointer(field) << '\n';
    std::cerr << "    - value: " << view_as_pointer(value) << '\n';
    return true;
}

extern "C" bool
_vmlaunch_demote(void) noexcept
{
    std::cerr << __BFFUNC__ << " called" << '\n';
    return true;
}

extern "C" bool
_invept(uint64_t type, void *ptr) noexcept
{
    (void) type;
    (void) ptr;

    std::cerr << __BFFUNC__ << " called" << '\n';
    return true;
}

extern "C" bool
_invvpid(uint64_t type, void *ptr) noexcept
{
    (void) type;
    (void) ptr;

    std::cerr << __BFFUNC__ << " called" << '\n';
    return true;
}
