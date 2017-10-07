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

///
/// @file bfbuffer.h
///
///

#ifdef WIN64

#include <windows.h>

inline int
set_affinity(uint64_t core)
{
    if (SetProcessAffinityMask(GetCurrentProcess(), 1ULL << core) == 0) {
        return -1;
    }

    return 0;
}

#else

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <sched.h>

inline int
set_affinity(uint64_t core)
{
    cpu_set_t  mask;

    CPU_ZERO(&mask);
    CPU_SET(core, &mask);

    if (sched_setaffinity(0, sizeof(mask), &mask) != 0) {
        return -1;
    }

    return 0;
}

#endif
