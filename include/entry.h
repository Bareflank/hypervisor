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

#include <memory.h>
#include <constants.h>

#pragma pack(push, 1)

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Entry Error Codes
 */
#define ENTRY_SUCCESS 0
#define ENTRY_ERROR_VMM_INIT_FAILED -10
#define ENTRY_ERROR_VMM_START_FAILED -20
#define ENTRY_ERROR_VMM_STOP_FAILED -30

/**
 * Entry Point
 *
 * This typedef defines what an entry point is. All functions that are to
 * be called using the ELF loader should conform to this prototype.
 *
 * @param arg the argument you wish to pass to the entry point
 * @return the return value of the entry point
 */
typedef int(*entry_point_t)(int);

/**
 * Init VMM
 *
 * This is the prototype for the function that should be called by the driver
 * entry to init the VMM.
 *
 * @param arg currently unused (set to 0)
 * @return VMM_SUCCESS on success, negative error code on failure
 */
int
init_vmm(int arg);

/**
 * Start VMM
 *
 * This is the prototype for the function that should be called by the driver
 * entry to start the VMM.
 *
 * @param arg currently unused (set to 0)
 * @return VMM_SUCCESS on success, negative error code on failure
 */
int
start_vmm(int arg);

/**
 * Stop VMM
 *
 * This is the prototype for the function that should be called by the driver
 * entry to stop the VMM.
 *
 * @param arg currently unused (set to 0)
 * @return VMM_SUCCESS on success, negative error code on failure
 */
int
stop_vmm(int arg);

#ifdef __cplusplus
}
#endif

#pragma pack(pop)

#endif
