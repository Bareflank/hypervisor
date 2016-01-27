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

#ifndef ENTRY_INTERFACE_H
#define ENTRY_INTERFACE_H

#ifndef KERNEL
#include <stdint.h>
#else
#include <types.h>
#endif

#pragma pack(push, 1)

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Entry Error Codes
 */
#define ENTRY_SUCCESS 0
#define ENTRY_ERROR_VMM_INIT_FAILED -10LL
#define ENTRY_ERROR_VMM_START_FAILED -20LL
#define ENTRY_ERROR_VMM_STOP_FAILED -30LL

/**
 * Entry Point
 *
 * This typedef defines what an entry point is. All functions that are to
 * be called using the ELF loader should conform to this prototype.
 *
 * @param arg the argument you wish to pass to the entry point
 * @return the return value of the entry point
 */
typedef int64_t(*entry_point_t)(int64_t);

#ifdef __cplusplus
}
#endif

#pragma pack(pop)

#endif
