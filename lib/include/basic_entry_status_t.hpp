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

#ifndef BASIC_ENTRY_STATUS_T_HPP
#define BASIC_ENTRY_STATUS_T_HPP

#include <bsl/convert.hpp>
#include <bsl/safe_integral.hpp>

namespace lib
{
    /// <!-- description -->
    ///   @brief Defines the status of a page table entry
    ///
    enum class basic_entry_status_t : bsl::uint8
    {
        /// @brief defines the not-present state for a page table entry
        not_present = (0_u8).get(),
        /// @brief defines the present state for a page table entry
        present = (1_u8).get(),
        /// @brief defines the reserved state for a page table entry
        reserved = (2_u8).get()
    };
}

#endif
