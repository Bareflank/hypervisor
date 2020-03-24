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
/// @file new.hpp
///

#ifndef BSL_NEW_HPP
#define BSL_NEW_HPP

#include "cstdint.hpp"
#include "discard.hpp"

/// <!-- description -->
///   @brief This function implements the placement new operator. Note that
///     this function is passed a count and pointer, both of which are ignored.
///
///   SUPPRESSION: PRQA 2000 - false positive
///   - We suppress this because M7-3-1 states that functions should not be
///     defined in the global namespace. This is a false positive because
///     C++ requires that the placement new function is defind in the global
///     namespace.
///
///   SUPPRESSION: PRQA 2000 - false positive
///   - We suppress this because M0-1-10 states that functions should be used
///     if they are defined. This function is used by bsl::result and others,
///     but PRQA is not able to detect this.
///
/// <!-- contracts -->
///   @pre none
///   @post none
///
/// <!-- inputs/outputs -->
///   @param count ignored
///   @param ptr the ptr to return
///   @return returns ptr
///
constexpr void *
operator new(bsl::uintmax count, void *const ptr) noexcept    // PRQA S 2000, 1503
{
    bsl::discard(count);
    return ptr;
}

#endif
