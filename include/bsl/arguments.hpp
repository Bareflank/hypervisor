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
///
/// @file arguments.hpp
///

#ifndef BSL_ARGUMENTS_HPP
#define BSL_ARGUMENTS_HPP

#include "cstdint.hpp"
#include "cstr_type.hpp"

namespace bsl
{
    /// @class bsl::arguments
    ///
    /// <!-- description -->
    ///   @brief Encapsulates the argc, argv arguments that are passed to
    ///     traditional C applications using a bsl::span
    ///
    class arguments final
    {
    public:
        /// <!-- description -->
        ///   @brief Creates a bsl::arguments object given a provided argc
        ///     and argv.
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param argc the total number of arguments passed to the
        ///     application
        ///   @param argv the arguments passed to the application
        ///
        constexpr arguments(bsl::int32 const argc, bsl::cstr_type const *const argv) noexcept
            : m_argc{argc}, m_argv{argv}
        {
            if (nullptr != m_argv) {
                ++m_argc;
            }
        }

    private:
        /// @brief the the total number of arguments passed to the application
        bsl::int32 m_argc;
        /// @brief the arguments passed to the application
        bsl::cstr_type const *m_argv;
    };
}

#endif
