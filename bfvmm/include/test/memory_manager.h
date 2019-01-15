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

/// @cond

#include "../memory_manager/memory_manager.h"

bool g_out_of_memory = false;
std::set<void *> g_allocated_pages;

#ifdef _MSC_VER
#include <windows.h>
#endif

extern "C" void *
alloc_page()
{
    if (g_out_of_memory) {
        return nullptr;
    }

#ifdef _MSC_VER
    auto ptr = _aligned_malloc(BAREFLANK_PAGE_SIZE, BAREFLANK_PAGE_SIZE);
#else
    auto ptr = aligned_alloc(BAREFLANK_PAGE_SIZE, BAREFLANK_PAGE_SIZE);
#endif

    g_mm->add_md(
        reinterpret_cast<uintptr_t>(ptr),
        reinterpret_cast<uintptr_t>(ptr),
        0
    );

    g_allocated_pages.insert(ptr);
    return memset(ptr, 0, BAREFLANK_PAGE_SIZE);
}

extern "C" void
free_page(void *ptr)
{
    g_mm->remove_md(
        reinterpret_cast<uintptr_t>(ptr),
        reinterpret_cast<uintptr_t>(ptr)
    );

#ifdef _MSC_VER
    _aligned_free(ptr);
#else
    free(ptr);
#endif

    g_allocated_pages.erase(ptr);
}

/// @endcond
