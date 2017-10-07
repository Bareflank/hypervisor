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

#ifndef BFNEWDELETE_H
#define BFNEWDELETE_H

#if defined(__clang__) || defined(__GNUC__)
#pragma GCC system_header
#endif

#include <cstdlib>
#include <exception>

#include <bfconstants.h>

size_t g_new_throws_bad_alloc = 0;

#ifdef _WIN32
#include <malloc.h>
#define aligned_alloc _aligned_malloc
#endif

inline void *
custom_new(std::size_t size)
{
    if (size == g_new_throws_bad_alloc || size == 0xFFFFFFFFFFFFFFFF) {
        throw std::bad_alloc();
    }

    if ((size & (MAX_PAGE_SIZE - 1)) == 0) {
        return aligned_alloc(0x1000, size);
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

#endif
