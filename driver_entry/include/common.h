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

#define MAX_NUM_MODULES 100

/* ========================================================================== */
/* Common Functions                                                           */
/* ========================================================================== */

int32_t
add_module(char *file, int32_t fsize);

void
clear_modules(void);

int32_t
start_vmm(void);

int32_t
stop_vmm(void);

#endif
