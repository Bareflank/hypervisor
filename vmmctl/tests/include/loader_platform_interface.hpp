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

#ifndef LOADER_PLATFORM_INTERFACE_HPP
#define LOADER_PLATFORM_INTERFACE_HPP

#include <bsl/convert.hpp>
#include <bsl/string_view.hpp>

namespace loader
{
    /// @brief defines the name of the loader
    constexpr bsl::string_view NAME{"bareflank_loader"};
    /// @brief defines the /dev name of the loader
    constexpr bsl::string_view DEVICE_NAME{"/dev/bareflank_loader"};

    /// @brief defines IOCTL for starting a VM
    constexpr auto START_VMM{0x1_umx};
    /// @brief defines IOCTL for stopping a VM
    constexpr auto STOP_VMM{0x2_umx};
    /// @brief defines IOCTL for dumping a VMs debug ring
    constexpr auto DUMP_VMM{0x3_umx};
}

#endif
