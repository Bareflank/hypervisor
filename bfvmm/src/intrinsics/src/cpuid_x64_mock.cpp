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

#undef GSL_THROW_ON_CONTRACT_VIOLATION
#define GSL_TERMINATE_ON_CONTRACT_VIOLATION

#include <gsl/gsl>
#include <debug.h>

extern "C" uint32_t
__attribute__((weak)) __cpuid_eax(uint32_t val) noexcept
{
    std::cerr << __FUNC__ << " called with: " << view_as_pointer(val) << '\n';
    abort();
}

extern "C" uint32_t
__attribute__((weak)) __cpuid_ebx(uint32_t val) noexcept
{
    std::cerr << __FUNC__ << " called with: " << view_as_pointer(val) << '\n';
    abort();
}

extern "C" uint32_t
__attribute__((weak)) __cpuid_ecx(uint32_t val) noexcept
{
    std::cerr << __FUNC__ << " called with: " << view_as_pointer(val) << '\n';
    abort();
}

extern "C" uint32_t
__attribute__((weak)) __cpuid_edx(uint32_t val) noexcept
{
    std::cerr << __FUNC__ << " called with: " << view_as_pointer(val) << '\n';
    abort();
}

extern "C" void
__attribute__((weak)) __cpuid(uint64_t *rax, uint64_t *rbx, uint64_t *rcx, uint64_t *rdx) noexcept
{
    expects(rax);
    expects(rbx);
    expects(rcx);
    expects(rdx);

    std::cerr << __FUNC__ << " called with: " << '\n';
    std::cerr << "    - rax: " << view_as_pointer(*rax) << '\n';
    std::cerr << "    - rbx: " << view_as_pointer(*rbx) << '\n';
    std::cerr << "    - rcx: " << view_as_pointer(*rcx) << '\n';
    std::cerr << "    - rdx: " << view_as_pointer(*rdx) << '\n';
    abort();
}
