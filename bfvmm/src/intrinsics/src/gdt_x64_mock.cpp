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

#include <intrinsics/gdt_x64.h>

extern "C" void
__attribute__((weak)) __read_gdt(gdt_reg_x64_t *gdt_reg) noexcept
{
    std::cerr << __FUNC__ << " called with: " << '\n';
    std::cerr << "    - gdt_reg: " << gdt_reg << '\n';
    abort();
}

extern "C" void
__attribute__((weak)) __write_gdt(gdt_reg_x64_t *gdt_reg) noexcept
{
    std::cerr << __FUNC__ << " called with: " << '\n';
    std::cerr << "    - gdt_reg: " << gdt_reg << '\n';
    abort();
}
