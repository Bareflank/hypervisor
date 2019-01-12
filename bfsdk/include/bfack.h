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

#ifndef BFACK_H
#define BFACK_H

#include <bftypes.h>

#ifdef __cplusplus
#define NOEXCEPT noexcept
#else
#define NOEXCEPT
#endif

#ifdef __cplusplus
extern "C" {
#endif

uint32_t _cpuid_eax(uint32_t val) NOEXCEPT;

#ifdef __cplusplus
}
#endif

/// Ack
///
/// Note:
///
/// Use this function instead of calling CPUID manually as the CPUID leaves
/// are always subject to change, as nested virtualization might require
/// mods to this approach.
///
/// @return returns 1 if Bareflank is running, 0 otherwise.
///
static inline int
bfack(void) NOEXCEPT
{ return _cpuid_eax(0x4BF00000) == 0x4BF00001 ? 1 : 0; }

#endif
