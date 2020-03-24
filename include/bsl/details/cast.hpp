/// @copyright
/// Copyright (C) 2019 Assured Information Security, Inc.
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

#ifndef BSL_DETAILS_CAST_HPP
#define BSL_DETAILS_CAST_HPP

namespace bsl
{
    namespace details
    {
        /// <!-- description -->
        ///   @brief Equivalent to a static_cast from a void *
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam T the type to convert the ptr to
        ///   @param ptr the pointer to convert
        ///   @return static_cast<T *>(ptr);
        ///
        template<typename T>
        constexpr T const *
        cast(void const *const ptr) noexcept
        {
            return static_cast<T const *>(ptr);
        }
    }
}

#endif
