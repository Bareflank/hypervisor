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
/// @file add_pointer.hpp
///

#ifndef BSL_ADD_POINTER_HPP
#define BSL_ADD_POINTER_HPP

#include "type_identity.hpp"

namespace bsl
{
    /// @class bsl::add_pointer
    ///
    /// <!-- description -->
    ///   @brief Provides the member typedef type which is the same as T,
    ///     except that a topmost pointer is added.
    ///   @include example_add_pointer_overview.hpp
    ///
    /// <!-- template parameters -->
    ///   @tparam T the type to add an pointer to
    ///
    template<typename T>
    class add_pointer final : public type_identity<T *>
    {};

    /// @brief a helper that reduces the verbosity of bsl::add_pointer
    template<typename T>
    using add_pointer_t = typename add_pointer<T>::type;

    /// @cond doxygen off

    template<typename T>
    class add_pointer<T &> final : public type_identity<T *>
    {};

    template<typename T>
    class add_pointer<T &&> final : public type_identity<T *>
    {};

    /// @endcond doxygen on
}

#endif
