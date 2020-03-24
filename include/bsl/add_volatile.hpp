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
/// @file add_volatile.hpp
///

#ifndef BSL_ADD_VOLATILE_HPP
#define BSL_ADD_VOLATILE_HPP

#include "type_identity.hpp"

namespace bsl
{
    /// @class bsl::add_volatile
    ///
    /// <!-- description -->
    ///   @brief Provides the member typedef type which is the same as T,
    ///     except that a topmost volatile qualifier is added.
    ///
    /// <!-- notes -->
    ///   @note "volatile" is not supported by the BSL as it is not compliant
    ///     with AUTOSAR. We only provide this for completeness and will
    ///     produce a compile-time error if these APIs are used. Also note
    ///     that C++ in general is deprectating the use of volatile.
    ///
    /// <!-- template parameters -->
    ///   @tparam T the type to add a volatile qualifier to
    ///
    template<typename T>
    class add_volatile final : public type_identity<T volatile>
    {
        static_assert(sizeof(T) != sizeof(T), "volatile not supported");
    };

    /// @brief a helper that reduces the verbosity of bsl::add_volatile
    template<typename T>
    using add_volatile_t = typename add_volatile<T>::type;

    /// @cond doxygen off

    template<typename T>
    class add_volatile<T volatile> final : public type_identity<T volatile>
    {
        static_assert(sizeof(T) != sizeof(T), "volatile not supported");
    };

    /// @endcond doxygen on
}

#endif
