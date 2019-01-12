//
// Copyright (C) 2019 Assured Information Security, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

///
/// @file bfstd.h
///

#ifndef BFSTD_H
#define BFSTD_H

#if defined(__clang__) || defined(__GNUC__)
#pragma GCC system_header
#endif

#include <stdio.h>
#include <stdlib.h>

// Note:
//
// This file exists for code that cannot include libc++
//

namespace std
{
/// Remove Reference
///
/// Returns T regardless of lvalue / rvalue type
///
template<class T> struct remove_reference {
    typedef T type;     ///< Type T
};

/// Remove Reference
///
/// Returns T regardless of lvalue / rvalue type
///
template<class T> struct remove_reference<T &> {
    typedef T type;     ///< Type T
};

/// Remove Reference
///
/// Returns T regardless of lvalue / rvalue type
///
template<class T> struct remove_reference < T && > {
    typedef T type;     ///< Type T
};

/// Forward
///
/// Preserves lvalue / rvalue reference
///
/// @param t the object to be forwarded
/// @return static_cast<T&&>(t)
///
template<class T>
constexpr T &&
forward(typename std::remove_reference<T>::type &t) noexcept
{
    return static_cast < T && >(t);
}

/// Forward
///
/// Preserves lvalue / rvalue reference
///
/// @param t the object to be forwarded
/// @return static_cast<T&&>(t)
///
template<class T>
constexpr T &&
forward(typename std::remove_reference<T>::type &&t) noexcept
{
    return static_cast < T && >(t);
}

/// Move
///
/// Produces a rvalue reference
///
/// @param t the object to be moved
/// @return static_cast<typename std::remove_reference<T>::type&&>(t)
///
template<class T>
constexpr typename std::remove_reference<T>::type &&
move(T &&t) noexcept
{
    return static_cast < typename std::remove_reference<T>::type && >(t);
}

/// Terminate
///
/// A C++ wrapper around C's abort().
///
[[noreturn]] inline void
terminate() noexcept
{
    printf("FATAL ERROR: std::terminate() called!!!\n");
    abort();
}
}

#endif
