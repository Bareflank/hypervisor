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

#include <test.h>
#include <intrinsics/rdtsc_x64.h>

using namespace x64;

read_tsc::value_type g_read_tsc = 0;
read_tscp::value_type g_read_tscp = 0;

extern "C" uint64_t
__read_tsc(void) noexcept
{ return g_read_tsc; }

extern "C" uint64_t
__read_tscp(void) noexcept
{ return g_read_tscp; }

void
intrinsics_ut::test_rdtsc_x64()
{
    g_read_tsc = 10U;
    this->expect_true(read_tsc::get() == 10U);
}

void
intrinsics_ut::test_rdtscp_x64()
{
    g_read_tscp = 10U;
    this->expect_true(read_tscp::get() == 10U);
}
