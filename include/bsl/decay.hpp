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
/// @file decay.hpp
///

#ifndef BSL_DECAY_HPP
#define BSL_DECAY_HPP

#include "add_pointer.hpp"
#include "conditional.hpp"
#include "is_array.hpp"
#include "is_function.hpp"
#include "remove_cv.hpp"
#include "remove_extent.hpp"
#include "remove_reference.hpp"
#include "type_identity.hpp"

namespace bsl
{
    /// @class bsl::decay
    ///
    /// <!-- description -->
    ///   @brief Applies lvalue-to-rvalue, array-to-pointer, and
    ///     function-to-pointer implicit conversions to the type T,
    ///     removes const-qualifiers, and defines the resulting type as the
    ///     member typedef type. Note that this does not remove volatile as
    ///     the BSL does not support the use of volatile.
    ///   @include example_decay_overview.hpp
    ///
    /// <!-- template parameters -->
    ///   @tparam T the type to decay
    ///
    template<typename T>
    class decay final :
        public type_identity<conditional_t<
            is_array<remove_reference_t<T>>::value,
            remove_extent_t<remove_reference_t<T>> *,
            conditional_t<
                is_function<remove_reference_t<T>>::value,
                add_pointer_t<remove_reference_t<T>>,
                remove_cv_t<remove_reference_t<T>>>>>
    {};

    /// @brief a helper that reduces the verbosity of bsl::add_const
    template<typename T>
    using decay_t = typename decay<T>::type;
}

#endif
