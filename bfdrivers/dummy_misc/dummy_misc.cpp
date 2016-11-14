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
#include <error_codes.h>

int64_t
return_success()
{ return SUCCESS; }

void *
operator new(size_t size)
{
    (void) size;

    static int mem = 0;
    return &mem;
}

void
operator delete(void *ptr) throw()
{
    (void) ptr;
}

extern "C" int64_t
sym_that_returns_failure(int64_t val)
{
    (void) val;

    return -1;
}

extern "C" int64_t
sym_that_returns_success(int64_t val)
{
    (void) val;

    return 0;
}

extern "C" int64_t
register_eh_frame(void *addr, uint64_t size)
{
    (void) addr;
    (void) size;

    return REGISTER_EH_FRAME_SUCCESS;
}

extern "C" void
__cxa_end_catch(void)
{  }

extern "C" void
__cxa_begin_catch(void)
{  }

extern "C" void
__gxx_personality_v0(void)
{  }

extern "C" int
atexit(void (*function)(void))
{
    (void) function;
    return 0;
}

extern "C" int64_t
local_init(struct section_info_t *info)
{
    (void) info;
    return 0;
}

extern "C" int64_t
local_fini(struct section_info_t *info)
{
    (void) info;
    return 0;
}
