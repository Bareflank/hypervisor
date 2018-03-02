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

#include <types.h>
#include <error_codes.h>

#pragma pack(push, 1)

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Execute Entry Point
 *
 * This typedef defines the function that is used to execute other entry
 * points. Note that there are several types of entry points. For example,
 * add_mdl, get_drr, start_vmm and stop_vmm are all entry points
 * and they have different parameter types. As a result, this function has
 * to be written generically to support all of them
 *
 * @expects stack != 0
 * @expects func != nullptr
 * @ensures none
 *
 * @param stack the stack to use when executing the entry point
 * @param func the entry point to call
 * @param arg1 the first argument to the entry point
 * @param arg2 the second argument to the entry point
 * @return the return value of the entry point
 *
 */
typedef int64_t(*execute_entry_t)(uint64_t stack, void *func, uint64_t arg1, uint64_t arg2);


#ifdef __cplusplus
}
#endif

#pragma pack(pop)

#endif
