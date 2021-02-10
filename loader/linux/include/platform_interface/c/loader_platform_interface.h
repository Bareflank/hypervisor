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

#ifndef LOADER_PLATFORM_INTERFACE_H
#define LOADER_PLATFORM_INTERFACE_H

#include <dump_vmm_args_t.h>
#include <linux/ioctl.h>
#include <start_vmm_args_t.h>
#include <stop_vmm_args_t.h>

/* clang-format off */

/** @brief defines the name of the loader */
#define LOADER_NAME "bareflank_loader"
/** @brief defines the /dev name of the loader */
#define LOADER_DEVICE_NAME "/dev/bareflank_loader"

/** @brief defines IOCTL for starting a VM */
#define LOADER_START_VMM _IOW(0U, LOADER_START_VMM_CMD, struct start_vmm_args_t *)
/** @brief defines IOCTL for stopping a VM */
#define LOADER_STOP_VMM _IOW(0U, LOADER_STOP_VMM_CMD, struct stop_vmm_args_t *)
/** @brief defines IOCTL for dumping a VMs debug ring */
#define LOADER_DUMP_VMM _IOWR(0U, LOADER_DUMP_VMM_CMD, struct dump_vmm_args_t *)

#endif
