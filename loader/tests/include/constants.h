/* SPDX-License-Identifier: SPDX-License-Identifier: GPL-2.0 OR MIT */

/**
 * @copyright
 * Copyright (C) 2020 Assured Information Security, Inc.
 *
 * @copyright
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * @copyright
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * @copyright
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef CONSTANTS_H
#define CONSTANTS_H

#include <types.h>

#define HYPERVISOR_PAGE_SIZE ((uint64_t)0x1000)
#define HYPERVISOR_PAGE_SHIFT ((uint64_t)12)
#define HYPERVISOR_SERIAL_PORT 0x03F8
#define HYPERVISOR_DEBUG_RING_SIZE ((uint64_t)10)
#define HYPERVISOR_VMEXIT_LOG_SIZE ((uint64_t)2)
#define HYPERVISOR_MAX_ELF_FILE_SIZE ((uint64_t)0x800000)
#define HYPERVISOR_MAX_SEGMENTS ((uint64_t)3)
#define HYPERVISOR_MAX_EXTENSIONS ((uint64_t)2)
#define HYPERVISOR_MAX_PPS ((uint64_t)2)
#define HYPERVISOR_MAX_VMS ((uint64_t)2)
#define HYPERVISOR_MAX_VPS ((uint64_t)2)
#define HYPERVISOR_MAX_VSS ((uint64_t)2)
#define HYPERVISOR_MAX_HUGE_ALLOCS ((uint64_t)2)
#define HYPERVISOR_MK_DIRECT_MAP_ADDR ((uint64_t)0x0000400000000000)
#define HYPERVISOR_MK_DIRECT_MAP_SIZE ((uint64_t)0x0000200000000000)
#define HYPERVISOR_MK_STACK_ADDR ((uint64_t)0x0000008000000000)
#define HYPERVISOR_MK_STACK_SIZE ((uint64_t)0x1000)
#define HYPERVISOR_MK_CODE_ADDR ((uint64_t)0x0000028000000000)
#define HYPERVISOR_MK_CODE_SIZE ((uint64_t)0x800000)
#define HYPERVISOR_MK_PAGE_POOL_ADDR ((uint64_t)0x0000400000000000)
#define HYPERVISOR_MK_PAGE_POOL_SIZE ((uint64_t)0x8000000)
#define HYPERVISOR_MK_HUGE_POOL_ADDR ((uint64_t)0x0000400000000000)
#define HYPERVISOR_MK_HUGE_POOL_SIZE ((uint64_t)0x20000)
#define HYPERVISOR_EXT_DIRECT_MAP_ADDR ((uint64_t)0x0000600000000000)
#define HYPERVISOR_EXT_DIRECT_MAP_SIZE ((uint64_t)0x0000200000000000)
#define HYPERVISOR_EXT_STACK_ADDR ((uint64_t)0x0000308000000000)
#define HYPERVISOR_EXT_STACK_SIZE ((uint64_t)0x1000)
#define HYPERVISOR_EXT_FAIL_STACK_ADDR ((uint64_t)0x0000318000000000)
#define HYPERVISOR_EXT_FAIL_STACK_SIZE ((uint64_t)0x8000)
#define HYPERVISOR_EXT_CODE_ADDR ((uint64_t)0x0000328000000000)
#define HYPERVISOR_EXT_CODE_SIZE ((uint64_t)0x800000)
#define HYPERVISOR_EXT_TLS_ADDR ((uint64_t)0x0000338000000000)
#define HYPERVISOR_EXT_TLS_SIZE ((uint64_t)0x2000)
#define HYPERVISOR_EXT_PAGE_POOL_ADDR ((uint64_t)0x0000200000000000)
#define HYPERVISOR_EXT_PAGE_POOL_SIZE ((uint64_t)0x8000000)
#define HYPERVISOR_EXT_HUGE_POOL_ADDR ((uint64_t)0x0000200000000000)
#define HYPERVISOR_EXT_HUGE_POOL_SIZE ((uint64_t)0x20000)

#endif
