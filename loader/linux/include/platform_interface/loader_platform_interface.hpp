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

#include <asm/ioctl.h>
#include <dump_vmm_args_t.hpp>
#include <start_vmm_args_t.hpp>
#include <stop_vmm_args_t.hpp>

#include <bsl/safe_integral.hpp>
#include <bsl/string_view.hpp>

namespace loader
{
    /// @brief defines the name of the loader
    constexpr bsl::string_view NAME{"bareflank_loader"};
    /// @brief defines the /dev name of the loader
    constexpr bsl::string_view DEVICE_NAME{"/dev/bareflank_loader"};

    /// @brief defines IOCTL for starting a VM
    constexpr bsl::safe_umx START_VMM{static_cast<bsl::uintmx>(
        _IOW(0U, START_VMM_CMD.get(), start_vmm_args_t *))};
    /// @brief defines IOCTL for stopping a VM
    constexpr bsl::safe_umx STOP_VMM{static_cast<bsl::uintmx>(
        _IOW(0U, STOP_VMM_CMD.get(), stop_vmm_args_t *))};
    /// @brief defines IOCTL for dumping a VMs debug ring
    constexpr bsl::safe_umx DUMP_VMM{static_cast<bsl::uintmx>(
        _IOWR(0U, DUMP_VMM_CMD.get(), dump_vmm_args_t *))};
}

#endif
