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

#ifndef COMMON_H
#define COMMON_H

#include <types.h>

/* ========================================================================== */
/* Macros                                                                     */
/* ========================================================================== */

#define BF_SUCCESS 0
#define BF_ERROR_REACHED_MAX_MODULES -5000
#define BF_ERROR_NO_MODULES_ADDED -5001
#define BF_ERROR_VMM_ALREADY_STARTED -5002
#define BF_ERROR_FAILED_TO_START_VMM -5003
#define BF_ERROR_FAILED_TO_STOP_VMM -5004

#define MAX_NUM_MODULES 100

/* ========================================================================== */
/* Common Functions                                                           */
/* ========================================================================== */

/**
 * Add Module
 *
 * Add's a module into memory to be executed once start_vmm is run. This
 * function uses the platform functions to allocate memory for the executable.
 * The file that is provided should not be removed until after stop_vmm is
 * run. Removing the file from memory could cause a crash, as the start_vmm
 * function uses the file that is being added to search for symbols that are
 * needed, as well as the stop_vmm function. Once stop_vmm is run, it's safe
 * to remove the files. Also, this function cannot be run if the vmm has
 * already been started.
 *
 * @param file the file to add to memory
 * @param fsize the size of the file in bytes
 * @return BF_SUCCESS on success, negative error code on failure
 */
int32_t
add_module(char *file, int32_t fsize);

/**
 * Clear Modules
 *
 * This function is executed by stop_vmm and does not need to be run manually.
 * Instead, the user should execute stop_vmm. This function removed the modules
 * that were added to memory, and then resets internal variables so that new
 * modules can be added, and the vmm can be started again.
 */
void
clear_modules(void);

/**
 * Start VMM
 *
 * This function starts the vmm (assuming that the modules that were
 * loaded are actually a vmm). The user should run add_module prior to running
 * this function for all of the modules that are needed. If symbols are
 * missing, this function will error out. If the vmm has already been started,
 * this function will also error out. Finally, the vmm must have
 * "_Z9start_vmmi" in one of the modules for the vmm to successfully start.
 *
 * @return BF_SUCCESS on success, negative error code on failure
 */
int32_t
start_vmm(void);

/**
 * Stop VMM
 *
 * This function stops the vmm (assuming that the modules that were
 * loaded are actually a vmm). The user should run start_vmm prior to running
 * this function. If the vmm has not already been started,
 * this function will also error out. Finally, the vmm must have
 * "_Z8stop_vmmi" in one of the modules for the vmm to successfully stop.
 *
 * @return BF_SUCCESS on success, negative error code on failure
 */
int32_t
stop_vmm(void);

#endif
