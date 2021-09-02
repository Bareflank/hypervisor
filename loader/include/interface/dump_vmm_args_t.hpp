/// @copyright
/// Copyright (C) 2020 Assured Information Security, Inc.
///
/// @copyright
/// Permission is hereby granted, free of charge, to any person obtaining a copy
/// of this software and associated documentation files (the "Software"), to deal
/// in the Software without restriction, including without limitation the rights
/// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
/// copies of the Software, and to permit persons to whom the Software is
/// furnished to do so, subject to the following conditions:
///
/// @copyright
/// The above copyright notice and this permission notice shall be included in
/// all copies or substantial portions of the Software.
///
/// @copyright
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
/// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
/// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
/// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
/// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
/// SOFTWARE.

#ifndef DUMP_VMM_ARGS_T_HPP
#define DUMP_VMM_ARGS_T_HPP

#include <debug_ring_t.hpp>

#include <bsl/convert.hpp>
#include <bsl/cstdint.hpp>
#include <bsl/safe_integral.hpp>

#pragma pack(push, 1)

namespace loader
{
    /// @brief defines the IOCTL index for dumping a VMs debug ring
    constexpr auto DUMP_VMM_CMD{0xBF03_u32};

    /// @struct loader::dump_vmm_args_t
    ///
    /// <!-- description -->
    ///   @brief Defines the information that a userspace application needs to
    ///     provide to dump the VMM.
    ///
    struct dump_vmm_args_t final
    {
        /// @brief set to loader::version
        bsl::uint64 ver;

        /// @brief stores the contents of the debug ring upon request
        debug_ring_t debug_ring;
    };
}

#pragma pack(pop)

#endif
