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

#ifndef INVVPID_DESCRIPTOR_T
#define INVVPID_DESCRIPTOR_T

#include <bsl/cstdint.hpp>

#pragma pack(push, 1)

namespace mk
{
    /// <!-- description -->
    ///   @brief Stores information needed to execute invvpid
    ///
    struct invvpid_descriptor_t final
    {
        /// @brief stores the vpid to invalidate
        bsl::uint16 vpid;
        /// @brief reserved
        bsl::uint16 reserved1;
        /// @brief reserved
        bsl::uint16 reserved2;
        /// @brief reserved
        bsl::uint16 reserved3;
        /// @brief stores the address to invalidate
        bsl::uintmx addr;
    };
}

#pragma pack(pop)

#endif
