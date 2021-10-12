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

#ifndef GLOBAL_DESCRIPTOR_TABLE_REGISTER_T_HPP
#define GLOBAL_DESCRIPTOR_TABLE_REGISTER_T_HPP

#include <bsl/cstdint.hpp>

#pragma pack(push, 1)

namespace loader
{
    /// <!-- description -->
    ///   @brief Defines the structure of the global descriptor table register
    ///     as defined by Intel and AMD
    ///
    struct global_descriptor_table_register_t final
    {
        /// @brief stores the size of the gdt in bytes (minus 1)
        bsl::uint16 limit;
        /// @brief stores a pointer to the gdt
        bsl::uint64 base;
    };
}

#pragma pack(pop)

#endif
