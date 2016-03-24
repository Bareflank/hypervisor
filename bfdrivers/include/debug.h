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

#ifndef DEBUG_H
#define DEBUG_H

#include <driver_entry_interface.h>

#ifndef KERNEL
#include <stdio.h>
#define INFO(...)
#define DEBUG(...) printf(__VA_ARGS__)
#define ALERT(...) printf(__VA_ARGS__)
#endif

/* ========================================================================== */
/* Linux Debugging                                                            */
/* ========================================================================== */

#ifdef KERNEL
#ifdef __linux__
#include <linux/module.h>
#define INFO(...) printk(KERN_INFO __VA_ARGS__)
#define DEBUG(...) printk(KERN_INFO "[" BAREFLANK_NAME "]: " __VA_ARGS__)
#define ALERT(...) printk(KERN_ALERT "[" BAREFLANK_NAME " ERROR]: " __VA_ARGS__)
#endif
#endif

/* ========================================================================== */
/* Windows Debugging                                                          */
/* ========================================================================== */

#ifdef KERNEL
#ifdef _WIN32
#endif
#endif

/* ========================================================================== */
/* OSX Debugging                                                              */
/* ========================================================================== */

#ifdef KERNEL
#ifdef __APPLE__
#endif
#endif

#endif
