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
///
/// @file type_identity.hpp
///

#ifndef BSL_TYPE_IDENTITY_HPP
#define BSL_TYPE_IDENTITY_HPP

namespace bsl
{
    /// @class bsl::type_identity
    ///
    /// <!-- description -->
    ///   @brief Provides the member typedef "type" that names T
    ///     (i.e., the identity transformation).
    ///
    /// <!-- template parameters -->
    ///   @tparam T the type that defines the member typedef "type"
    ///
    template<typename T>
    struct type_identity final
    {
        /// @brief the member typedef "type" being provided
        using type = T;
    };

    /// @brief a helper that reduces the verbosity of bsl::type_identity
    template<typename T>
    using type_identity_t = typename type_identity<T>::type;
}

#endif
