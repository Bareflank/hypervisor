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

// TIDY_EXCLUSION=-cppcoreguidelines-pro*
//
// Reason:
//     Although written in C++, this code needs to implement C specific logic
//     that by its very definition will not adhere to the core guidelines
//     similar to libc which is needed by all C++ implementations.
//

#ifndef REQUEST_INIT_FAILS
#define REQUEST_INIT_RETURN ENTRY_SUCCESS
#else
#define REQUEST_INIT_RETURN ENTRY_ERROR_UNKNOWN
#endif

#ifndef REQUEST_FINI_FAILS
#define REQUEST_FINI_RETURN ENTRY_SUCCESS
#else
#define REQUEST_FINI_RETURN ENTRY_ERROR_UNKNOWN
#endif

#ifndef REQUEST_ADD_MDL_FAILS
#define REQUEST_ADD_MDL_RETURN ENTRY_SUCCESS
#else
#define REQUEST_ADD_MDL_RETURN ENTRY_ERROR_UNKNOWN
#endif

#ifndef REQUEST_GET_DRR_FAILS
#define REQUEST_GET_DRR_RETURN ENTRY_SUCCESS
#else
#define REQUEST_GET_DRR_RETURN ENTRY_ERROR_UNKNOWN
#endif

#ifndef REQUEST_SET_RSDP_FAILS
#define REQUEST_SET_RSDP_RETURN ENTRY_SUCCESS
#else
#define REQUEST_SET_RSDP_RETURN ENTRY_ERROR_UNKNOWN
#endif

#ifndef REQUEST_VMM_INIT_FAILS
#define REQUEST_VMM_INIT_RETURN ENTRY_SUCCESS
#else
#define REQUEST_VMM_INIT_RETURN ENTRY_ERROR_UNKNOWN
#endif

#ifndef REQUEST_VMM_FINI_FAILS
#define REQUEST_VMM_FINI_RETURN ENTRY_SUCCESS
#else
#define REQUEST_VMM_FINI_RETURN ENTRY_ERROR_UNKNOWN
#endif

#include <bfgsl.h>
#include <bftypes.h>
#include <bfexports.h>
#include <bfsupport.h>

#include <cstdlib>
#include <cstring>
#include <stdexcept>

#include <dummy_libs.h>

derived1 g_derived1;
derived2 g_derived2;

EXPORT_SYM int global_var = 0;

int
main(int argc, char *argv[])
{
    if (argc != 2) {
        return -1;
    }

    try {
        throw std::runtime_error("test exceptions");
    }
    catch (std::exception &) {
        auto view = gsl::make_span(argv, argc);

        return g_derived1.foo(gsl::narrow_cast<int>(strtol(view[0], nullptr, 10))) +
               g_derived2.foo(gsl::narrow_cast<int>(strtol(view[1], nullptr, 10)));
    }

    return 0;
}

extern "C" int64_t
bfmain(uintptr_t request, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3)
{
    bfignored(arg1);
    bfignored(arg2);
    bfignored(arg3);

    switch (request) {
        case BF_REQUEST_INIT:
            return REQUEST_INIT_RETURN;

        case BF_REQUEST_FINI:
            return REQUEST_FINI_RETURN;

        case BF_REQUEST_ADD_MDL:
            return REQUEST_ADD_MDL_RETURN;

        case BF_REQUEST_GET_DRR:
            return REQUEST_GET_DRR_RETURN;

        case BF_REQUEST_VMM_INIT:
            return REQUEST_VMM_INIT_RETURN;

        case BF_REQUEST_VMM_FINI:
            return REQUEST_VMM_FINI_RETURN;

        case BF_REQUEST_SET_RSDP:
            return REQUEST_SET_RSDP_RETURN;

        default:
            break;
    }

    return ENTRY_ERROR_UNKNOWN;
}

// -----------------------------------------------------------------------------
// Missing C Functions
// -----------------------------------------------------------------------------

int g_cursor = 0;
char g_memory[0x100000] = {};

extern "C" EXPORT_SYM int
write(int file, const void *buffer, size_t count)
{
    bfignored(file);
    bfignored(buffer);
    bfignored(count);

    return 0;
}

extern "C" EXPORT_SYM uint64_t
unsafe_write_cstr(const char *cstr, size_t len)
{
    bfignored(cstr);
    bfignored(len);

    return 0;
}

extern "C" EXPORT_SYM void *
_malloc_r(struct _reent *ent, size_t size)
{
    bfignored(ent);

    auto addr = &gsl::at(g_memory, g_cursor);
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

    if (auto ptr = _malloc_r(nullptr, nmemb * size)) {
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

extern "C" EXPORT_SYM uint64_t *
thread_context_tlsptr(void)
{
    static uint64_t s_tls[0x1000] = {};
    return s_tls;
}

extern "C" EXPORT_SYM uint64_t
thread_context_cpuid(void)
{
    return 0;
}
