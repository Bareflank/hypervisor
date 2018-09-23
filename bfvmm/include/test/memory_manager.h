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
