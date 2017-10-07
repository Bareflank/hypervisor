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

#undef GSL_THROW_ON_CONTRACT_VIOLATION
#define GSL_TERMINATE_ON_CONTRACT_VIOLATION

#include <bfgsl.h>
#include <bfdebug.h>
#include <bftypes.h>

#include <intrinsics/x86/common/cpuid_x64.h>

extern "C" uint32_t
_cpuid_eax(uint32_t val) noexcept
{
    std::cerr << __BFFUNC__ << " called with: " << view_as_pointer(val) << '\n';
    return 0;
}

extern "C" uint32_t
_cpuid_ebx(uint32_t val) noexcept
{
    std::cerr << __BFFUNC__ << " called with: " << view_as_pointer(val) << '\n';
    return 0;
}

extern "C" uint32_t
_cpuid_ecx(uint32_t val) noexcept
{
    std::cerr << __BFFUNC__ << " called with: " << view_as_pointer(val) << '\n';
    return 0;
}

extern "C" uint32_t
_cpuid_edx(uint32_t val) noexcept
{
    std::cerr << __BFFUNC__ << " called with: " << view_as_pointer(val) << '\n';
    return 0;
}

extern "C" uint32_t
_cpuid_subeax(uint32_t val, uint32_t sub) noexcept
{
    bfignored(val);
    bfignored(sub);

    std::cerr << __BFFUNC__ << " called" << '\n';
    return 0;
}

extern "C" uint32_t
_cpuid_subebx(uint32_t val, uint32_t sub) noexcept
{
    bfignored(val);
    bfignored(sub);

    std::cerr << __BFFUNC__ << " called" << '\n';
    return 0;
}

extern "C" uint32_t
_cpuid_subecx(uint32_t val, uint32_t sub) noexcept
{
    bfignored(val);
    bfignored(sub);

    std::cerr << __BFFUNC__ << " called" << '\n';
    return 0;
}

extern "C" uint32_t
_cpuid_subedx(uint32_t val, uint32_t sub) noexcept
{
    bfignored(val);
    bfignored(sub);

    std::cerr << __BFFUNC__ << " called" << '\n';
    return 0;
}

extern "C" void
_cpuid(void *eax, void *ebx, void *ecx, void *edx) noexcept
{
    bfignored(eax);
    bfignored(ebx);
    bfignored(ecx);
    bfignored(edx);

    std::cerr << __BFFUNC__ << " called" << '\n';
}
