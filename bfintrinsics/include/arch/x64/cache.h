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

#ifndef CACHE_X64_H
#define CACHE_X64_H

#include <cstdint>

// -----------------------------------------------------------------------------
// Exports
// -----------------------------------------------------------------------------

#include <bfexports.h>

#ifndef STATIC_INTRINSICS
#ifdef SHARED_INTRINSICS
#define EXPORT_INTRINSICS EXPORT_SYM
#else
#define EXPORT_INTRINSICS IMPORT_SYM
#endif
#else
#define EXPORT_INTRINSICS
#endif

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

extern "C" void _invd(void) noexcept;
extern "C" void _wbinvd(void) noexcept;
extern "C" void _clflush(void *addr) noexcept;

// *INDENT-OFF*

namespace x64
{
namespace cache
{

using pointer = void *;
using integer_pointer = uintptr_t;

inline void invd() noexcept
{ _invd(); }

inline void wbinvd() noexcept
{ _wbinvd(); }

inline void clflush(integer_pointer addr) noexcept
{ _clflush(reinterpret_cast<pointer>(addr)); }

inline void clflush(pointer addr) noexcept
{ _clflush(addr); }

}
}

// *INDENT-ON*

#endif
