//
// Copyright (C) 2019 Assured Information Security, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

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

inline void *
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

inline void
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

void *
operator new (std::size_t count, const std::nothrow_t &) noexcept
{ return custom_new(count); }

void *
operator new[](std::size_t count, const std::nothrow_t &) noexcept
{ return custom_new(count); }

void
operator delete (void *ptr, std::size_t size) throw()
{ custom_delete(ptr, size); }

void
operator delete (void *ptr) throw()
{ operator delete (ptr, static_cast<std::size_t>(0)); }

void
operator delete[](void *ptr, std::size_t size) throw()
{ custom_delete(ptr, size); }

void
operator delete[](void *ptr) throw()
{ operator delete[](ptr, static_cast<std::size_t>(0)); }

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

#endif
