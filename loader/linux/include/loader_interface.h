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

#ifndef LOADER_INTERFACE_H
#define LOADER_INTERFACE_H

#include "../../include/loader_interface_common.h"

#define BAREFLANK_LOADER_NAME "bareflank_loader"
#define BAREFLANK_LOADER_DEVICE_NAME "/dev/" BAREFLANK_LOADER_NAME

#include <linux/ioctl.h>

#define BAREFLANK_LOADER_MAGIC_NUMBER 0x42

#define BAREFLANK_LOADER_IOCTL_START_VMM_CMD 0xBF01U
#define BAREFLANK_LOADER_IOCTL_STOP_VMM_CMD 0xBF02U
#define BAREFLANK_LOADER_IOCTL_DUMP_VMM_CMD 0xBF03U

#define BAREFLANK_LOADER_START_VMM                                                                 \
    _IO(BAREFLANK_LOADER_MAGIC_NUMBER, BAREFLANK_LOADER_IOCTL_START_VMM_CMD)    // NOLINT
#define BAREFLANK_LOADER_STOP_VMM                                                                  \
    _IO(BAREFLANK_LOADER_MAGIC_NUMBER, BAREFLANK_LOADER_IOCTL_STOP_VMM_CMD)    // NOLINT
#define BAREFLANK_LOADER_DUMP_VMM                                                                  \
    _IO(BAREFLANK_LOADER_MAGIC_NUMBER, BAREFLANK_LOADER_IOCTL_DUMP_VMM_CMD)    // NOLINT

#endif
