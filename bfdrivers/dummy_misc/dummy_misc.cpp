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

#include <stdint.h>

int g_misc = 0;

class test
{
public:
    test()
    { g_misc = 10; }

    virtual ~test()
    { g_misc = 20; }
};

test g_test;

void
operator delete(void *ptr)
{
    (void) ptr;
}

extern "C" int64_t
sym_that_returns_failure(int64_t)
{
    return -1;
}

extern "C" int64_t
sym_that_returns_success(int64_t)
{
    return 0;
}

extern "C" int64_t
get_misc(void)
{
    return g_misc;
}

extern "C" void
register_eh_frame(void *addr, uint64_t size)
{
    (void) addr;
    (void) size;
}

