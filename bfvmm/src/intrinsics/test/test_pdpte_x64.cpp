//
// Bareflank Hypervisor
//
// Copyright (C) 2015 Assured Information Security, Inc.
// Author: Rian Quinn        <quinnr@ainfosec.com>
// Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
// Author: Connor Davis      <davisc@ainfosec.com>
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

#include <test.h>
#include <intrinsics/cpuid_x64.h>
#include <intrinsics/pdpte_x64.h>

using namespace x64;

void
intrinsics_ut::test_pdpte_x64_reserved_mask()
{
    g_eax_cpuid[cpuid::addr_size::addr] = 48U;
    this->expect_true(pdpte::reserved::mask() == 0xFFFF0000000001E6ULL);
}

void
intrinsics_ut::test_pdpte_x64_page_directory_addr_mask()
{
    g_eax_cpuid[cpuid::addr_size::addr] = 48;
    this->expect_true(pdpte::page_directory_addr::mask() == 0x0000FFFFFFFFF000ULL);
}
