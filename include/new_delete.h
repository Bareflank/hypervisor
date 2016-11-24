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

#ifndef NEW_DELETE_H
#define NEW_DELETE_H

#pragma GCC system_header

// Note:
//
// This file provides a generic replacement for new / delete for unit testing
// so that things like bad_alloc and aligned memory can be unit tested. This
// file can only be included once in a unit test, and it should be included
// as a system header to prevent scanners from getting upset that we are using
// malloc / free which is exactly what the standard libraries are doing.

#include <stdlib.h>
#include <stddef.h>
#include <exception>

size_t g_new_throws_bad_alloc = 0;

static void *
malloc_aligned(std::size_t size)
{
    int ret = 0;
    void *ptr = nullptr;

    ret = posix_memalign(&ptr, MAX_PAGE_SIZE, size);
    (void) ret;

    return ptr;
}

static void *
custom_new(std::size_t size)
{
    if (size == g_new_throws_bad_alloc || size == 0xFFFFFFFFFFFFFFFF)
        throw std::bad_alloc();

    if ((size & (MAX_PAGE_SIZE - 1)) == 0)
        return malloc_aligned(size);

    return malloc(size);
}

static void
custom_delete(void *ptr)
{ free(ptr); }

void *
operator new[](std::size_t size)
{ return custom_new(size); }

void *
operator new(std::size_t size)
{ return custom_new(size); }

void
operator delete(void *ptr, std::size_t /* size */) throw()
{ custom_delete(ptr); }

void
operator delete(void *ptr) throw()
{ custom_delete(ptr); }

void
operator delete[](void *ptr) throw()
{ custom_delete(ptr); }

void
operator delete[](void *ptr, std::size_t /* size */) throw()
{ custom_delete(ptr); }

#endif
