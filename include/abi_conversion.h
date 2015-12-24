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

#ifndef ABI_CONVERSION_H
#define ABI_CONVERSION_H

#include <entry.h>

/**
 * Microsoft 64bit ABI to System V 64bit ABI
 *
 * With the switch to 64bit, there are really only two different types of
 * ABIs that can be used. MS x64 and System V 64bit ABI. Since the cross
 * compiled code is compiled using System V, the code that is compiled using
 * MS x64 that needs to call into the cross-compiled code needs a means to
 * swich from one calling convention to another. This function executes an
 * entry point, while performing this conversion.
 *
 * @param entry_point the entry point you wish to execute
 * @param arg the argument you wish to pass to the entry point
 * @return the return value of the entry point
 */
typedef void *(*exec_ms64tosv64_t)(void *entry_point, int);

#endif
