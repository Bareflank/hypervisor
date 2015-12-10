/*
 * Bareflank Hypervisor
 *
 * Copyright (C) 2015 Assured Information Security, Inc.
 * Author: Rian Quinn        <quinnr@ainfosec.com>
 * Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef INTRINSICS_INTEL_X64_H
#define INTRINSICS_INTEL_X64_H

#include <stdint.h>
#include <intrinsics/intrinsics_x64.h>

// =============================================================================
// Intrinsics
// =============================================================================

#ifdef __cplusplus
extern "C" {
#endif

uint64_t __vmxon(void *vmxon_region);
uint64_t __vmxoff(void);

// =============================================================================
// C++ Wrapper
// =============================================================================

#ifdef __cplusplus
}
#endif

class intrinsics_intel_x64 : public intrinsics_x64
{
public:

    bool vmxon(void *vmxon_region)
    { __vmxon(vmxon_region); }

    bool vmxoff()
    { __vmxoff(); }
};

#endif
