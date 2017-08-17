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

#include <bfgsl.h>
#include <bftypes.h>
#include <bfexports.h>
#include <bfsupport.h>

#include <cstring>
#include <stdexcept>

#include <dummy_libs.h>

derived1 g_derived1;
derived2 g_derived2;

int
main(int argc, char *argv[])
{
    if (argc != 2) {
        return -1;
    }

    try {
        throw std::runtime_error("test exceptions");
    }
    catch (std::exception &)
    { }

    return g_derived1.foo(gsl::narrow_cast<int>(atoi(argv[0]))) +
           g_derived2.foo(gsl::narrow_cast<int>(atoi(argv[1])));
}

extern "C" int64_t
bfmain(uintptr_t request, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3)
{
    bfignored(arg3);

    if (request < BF_REQUEST_END) {
        return 0;
    }

    try {
        throw std::runtime_error("test exceptions");
    }
    catch (std::exception &)
    { }

    return g_derived1.foo(gsl::narrow_cast<int>(arg1)) +
           g_derived2.foo(gsl::narrow_cast<int>(arg2));
}

// -----------------------------------------------------------------------------
// Missing C Functions
// -----------------------------------------------------------------------------

int g_cursor = 0;
char g_memory[0x10000] = {};

extern "C" EXPORT_SYM int
write(int file, const void *buffer, size_t count)
{
    bfignored(file);
    bfignored(buffer);
    bfignored(count);

    return 0;
}

extern "C" EXPORT_SYM void *
_malloc_r(struct _reent *ent, size_t size)
{
    bfignored(ent);

    auto *addr = &g_memory[g_cursor];
    g_cursor += size;

    return addr;
}

extern "C" EXPORT_SYM void
_free_r(struct _reent *ent, void *ptr)
{
    bfignored(ent);
    bfignored(ptr);
}

extern "C" EXPORT_SYM void *
_calloc_r(struct _reent *ent, size_t nmemb, size_t size)
{
    bfignored(ent);

    if (auto ptr = malloc(nmemb * size)) {
        return memset(ptr, 0, nmemb * size);
    }

    return nullptr;
}

extern "C" EXPORT_SYM void *
_realloc_r(struct _reent *ent, void *ptr, size_t size)
{
    bfignored(ent);
    bfignored(ptr);
    bfignored(size);

    return nullptr;
}
