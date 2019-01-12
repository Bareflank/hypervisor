/*
 * Copyright (C) 2019 Assured Information Security, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
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
/* Debug                                                                      */
/* -------------------------------------------------------------------------- */

#ifdef NDEBUG
#define ndebug 1
#else
#define ndebug 0
#endif

/* -------------------------------------------------------------------------- */
/* Testing                                                                    */
/* -------------------------------------------------------------------------- */

#ifdef ENABLE_BUILD_TEST
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

/* -------------------------------------------------------------------------- */
/* EFI Types                                                                  */
/* -------------------------------------------------------------------------- */

#if defined(KERNEL) && defined(EFI)
#include "efi.h"
#include "efilib.h"
#define PRId64 "lld"
#endif

#endif
