//
// Bareflank Hypervisor
// Copyright (C) 2018 Assured Information Security, Inc.
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

#ifndef BIT_INTEL_X64_H
#define BIT_INTEL_X64_H

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

extern "C" uint64_t _bsf(uint64_t value) noexcept;
extern "C" uint64_t _bsr(uint64_t value) noexcept;
extern "C" uint64_t _popcnt(uint64_t value) noexcept;

// *INDENT-OFF*

namespace intel_x64
{
namespace bit
{
    inline uint64_t bsf(uint64_t value) noexcept
    { return _bsf(value); }

    inline uint64_t bsr(uint64_t value) noexcept
    { return _bsr(value); }

    inline uint64_t popcnt(uint64_t value) noexcept
    { return _popcnt(value); }
}
}
// *INDENT-ON*

#endif
