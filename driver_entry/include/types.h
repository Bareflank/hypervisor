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

#ifndef TYPES_H
#define TYPES_H

/* ========================================================================== */
/* Userspace                                                                  */
/* ========================================================================== */

#ifndef KERNEL
#include <stdint.h>
#endif

/* ========================================================================== */
/* Linux Types                                                                */
/* ========================================================================== */

#ifdef KERNEL
#ifdef __linux__
#include <linux/types.h>
#define PRId64 "lld"
#define BFIO _IO
#define BFIOR _IOR
#define BFIOW _IOW
#endif
#endif

/* ========================================================================== */
/* Windows Types                                                              */
/* ========================================================================== */

#ifdef KERNEL
#ifdef _WIN32
#endif
#endif

/* ========================================================================== */
/* OSX Types                                                                  */
/* ========================================================================== */

#ifdef KERNEL
#ifdef __APPLE__
#define BFIOW(x,y,z) (y)
#define BFIO(x,y) (y)
#define BFIOR(x,y,z) (y)
#endif
#endif

#endif
