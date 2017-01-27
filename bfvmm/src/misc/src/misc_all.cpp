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

#include <stddef.h>
#include <stdint.h>

#include <constants.h>
#include <eh_frame_list.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-result"

uintptr_t __stack_chk_guard = 0x595e9fbd94fda766;

auto g_eh_frame_list_num = 0ULL;
eh_frame_t g_eh_frame_list[MAX_NUM_MODULES] = {};

extern "C" struct eh_frame_t *
get_eh_frame_list() noexcept
{ return g_eh_frame_list; }

extern "C" int64_t
register_eh_frame(void *addr, uint64_t size) noexcept
{
    if (addr == nullptr || size == 0)
        return REGISTER_EH_FRAME_SUCCESS;

    if (g_eh_frame_list_num >= MAX_NUM_MODULES)
        return REGISTER_EH_FRAME_FAILURE;

    g_eh_frame_list[g_eh_frame_list_num].addr = addr;
    g_eh_frame_list[g_eh_frame_list_num].size = size;
    g_eh_frame_list_num++;

    return REGISTER_EH_FRAME_SUCCESS;
}

extern "C" int
___xpg_strerror_r(int errnum, char *buf, size_t buflen)
{
    (void) errnum;

    __builtin_memset(buf, 0, buflen);
    return 0;
}

extern "C" int
__fpclassifyd(double)
{ return 0; }

extern "C" double
ldexp(double x, int exp)
{ return __builtin_ldexp(x, exp); }

extern "C" float
nanf(const char *tagp)
{ return __builtin_nanf(tagp); }

extern "C" void
_start(void) noexcept
{ }

void *__dso_handle = 0;

#pragma GCC diagnostic pop
