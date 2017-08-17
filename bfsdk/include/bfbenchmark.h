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
// MERCHANTABILITY or FITNESS FOR A PARTICULLAR PURPOSE. See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

#ifndef BFBENCHMARK_H
#define BFBENCHMARK_H

#if defined(__clang__) || defined(__GNUC__)
#pragma GCC system_header
#endif

#include <chrono>
#include <cstdlib>

#include <bfdebug.h>

template<typename T>
uint64_t benchmark(T func)
{
    auto s = std::chrono::high_resolution_clock::now();
    func();
    auto e = std::chrono::high_resolution_clock::now();

    return static_cast<uint64_t>((e - s).count());
}

size_t g_page_allocs = 0;
size_t g_nonpage_allocs = 0;

static void *
custom_new(std::size_t size)
{
    if ((size & 0xFFF) == 0) {
        g_page_allocs += size;
    }
    else {
        g_nonpage_allocs += size;
    }

    return malloc(size);
}

static void
custom_delete(void *ptr, std::size_t size)
{
    bfignored(size);
    free(ptr);
}

void *
operator new[](std::size_t size)
{ return custom_new(size); }

void *
operator new (std::size_t size)
{ return custom_new(size); }

void
operator delete (void *ptr, std::size_t size) throw()
{ custom_delete(ptr, size); }

void
operator delete (void *ptr) throw()
{ custom_delete(ptr, 0); }

void
operator delete[](void *ptr, std::size_t size) throw()
{ custom_delete(ptr, size); }

void
operator delete[](void *ptr) throw()
{ custom_delete(ptr, 0); }

#endif

inline void
print_memory_stats()
{
    auto page_allocs = g_page_allocs;
    auto nonpage_allocs = g_nonpage_allocs;

    bfdebug_nhex(0, "bytes allocated", page_allocs + nonpage_allocs);
    bfdebug_subnhex(0, "page aligned bytes allocated", page_allocs);
    bfdebug_subnhex(0, "non-page aligned bytes allocated", nonpage_allocs);
}

inline void
clear_memory_stats()
{
    g_page_allocs = 0;
    g_nonpage_allocs = 0;
}
