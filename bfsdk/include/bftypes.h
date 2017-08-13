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

#ifndef BFTYPES_H
#define BFTYPES_H

/* -------------------------------------------------------------------------- */
/* Helper Macros                                                              */
/* -------------------------------------------------------------------------- */

#ifdef __cplusplus
#define bfscast(a, b) (static_cast<a>(b))
#else
#define bfscast(a, b) ((a)(b))
#endif

#ifdef __cplusplus
#define bfrcast(a, b) (reinterpret_cast<a>(b))
#else
#define bfrcast(a, b) ((a)(b))
#endif

#ifdef __cplusplus
#define bfadd(a, b, c) (reinterpret_cast<a>(reinterpret_cast<uintptr_t>(b) + (c)))
#else
#define bfadd(a, b, c) ((a)((char *)(b) + (c)))
#endif

#ifdef __cplusplus
#define bfcadd(a, b, c) (reinterpret_cast<a>(reinterpret_cast<uintptr_t>(b) + (c)))
#else
#define bfcadd(a, b, c) ((a)((const char *)(b) + (c)))
#endif

#define bfignored(a) (void)a

/* -------------------------------------------------------------------------- */
/* Stringify                                                                  */
/* -------------------------------------------------------------------------- */

#define bfstringify(a) __bfstringify(a)
#define __bfstringify(a) #a

/* -------------------------------------------------------------------------- */
/* NULL                                                                       */
/* -------------------------------------------------------------------------- */

#if !defined(__cplusplus) && !defined(nullptr)
#define nullptr 0
#endif

/* -------------------------------------------------------------------------- */
/* Testing                                                                    */
/* -------------------------------------------------------------------------- */

#ifdef ENABLE_UNITTESTING
#define VIRTUAL virtual
#else
#define VIRTUAL
#endif

/* -------------------------------------------------------------------------- */
/* Userspace                                                                  */
/* -------------------------------------------------------------------------- */

#if !defined(KERNEL) && !defined(_WIN32)
#if defined(__cplusplus) && __has_include("cstdint")
#include <cstdint>
#else
#include <stdint.h>
#endif
#endif

/* -------------------------------------------------------------------------- */
/* Linux Types                                                                */
/* -------------------------------------------------------------------------- */

#if defined(KERNEL) && defined(__linux__)
#include <linux/types.h>
#define PRId64 "lld"
#endif

/* -------------------------------------------------------------------------- */
/* Windows Types                                                              */
/* -------------------------------------------------------------------------- */

#if defined(_WIN32)
#include <basetsd.h>
typedef INT8 int8_t;
typedef INT16 int16_t;
typedef INT32 int32_t;
typedef INT64 int64_t;
typedef UINT8 uint8_t;
typedef UINT16 uint16_t;
typedef UINT32 uint32_t;
typedef UINT64 uint64_t;
typedef UINT_PTR uintptr_t;
typedef INT_PTR intptr_t;
#define PRId64 "lld"
#endif

#endif
