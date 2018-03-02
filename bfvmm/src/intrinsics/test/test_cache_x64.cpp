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
#include <intrinsics/cache_x64.h>

using namespace x64;

extern "C" void
__invd(void) noexcept
{ }

extern "C" void
__wbinvd(void) noexcept
{ }

extern "C" void
__clflush(void *addr) noexcept
{ (void) addr; }

void
intrinsics_ut::test_cache_x64_invd()
{
    this->expect_no_exception([&] { cache::invd(); });
}

void
intrinsics_ut::test_cache_x64_wbinvd()
{
    this->expect_no_exception([&] { cache::wbinvd(); });
}

void
intrinsics_ut::test_cache_x64_clflush()
{
    this->expect_no_exception([&] { cache::clflush(0x10); });
    this->expect_no_exception([&] { cache::clflush(this); });
}
