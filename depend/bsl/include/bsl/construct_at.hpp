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

#ifndef BSL_CONSTRUCT_AT_HPP
#define BSL_CONSTRUCT_AT_HPP

#include "declval.hpp"
#include "new.hpp"
#include "forward.hpp"

namespace bsl
{
    /// <!-- description -->
    ///   @brief Used to construct T at a specific location in memory using
    ///     a placement-new. The difference is, this function takes a void *
    ///     and returns a T *. This should be used instead of using the
    ///     placement new operator directly as it encapsulates issues with
    ///     PRQA.
    ///   @include example_construct_at_overview.hpp
    ///
    ///   SUPPRESSION: PRQA 5217 - false positive
    ///   - We suppress this because A18-5-2 states that non-placement
    ///     new and delete expressions are not allowed. This is a false
    ///     positive because this uses a placement new, which is allowed.
    ///
    ///   SUPPRESSION: PRQA 3058 - false positive
    ///   - We suppress this because M8-4-4 states that function pointers
    ///     should be preceeded by an &. In some cases, even if it is, this
    ///     rule still triggers (some sort of bug with PRQA)
    ///
    ///   SUPPRESSION: PRQA 2706 - false positive
    ///   - We suppress this because 18-5-5 states that all allocated memory
    ///     shall be deallocated. This is a placement new, which is not
    ///     allocating memory.
    ///
    ///   SUPPRESSION: PRQA 4327 - false positive
    ///   - We suppress this because A0-1-4 states that all function parameters
    ///     should be used. PRQA thinks that "args" is not being used, which
    ///     is not true as "args" is passed to the placement new operator
    ///     which is then used to determine which constructor to use. Even if
    ///     the resulting constructor was not using a parameter, that
    ///     constructor would fail this test, not this function. Something is
    ///     buggy with this test.
    ///
    /// <!-- contracts -->
    ///   @pre none
    ///   @post none
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of object to initialize
    ///   @tparam ARGS the types of args to initialize T with
    ///   @param ptr a pointer to the object to initialize
    ///   @param args the args to initialize T with
    ///
    /// <!-- exceptions -->
    ///   @throw throws if T throws during construction
    ///
    template<typename T, typename... ARGS>
    constexpr void
    construct_at(void *const ptr, ARGS &&... args)    // PRQA S 4327
        noexcept(noexcept(new (ptr) T{bsl::declval<ARGS>()...}))
    {
        bsl::discard(new (ptr) T{bsl::forward<ARGS>(args)...});    // PRQA S 1-10000 // NOLINT
    }
}

#endif
