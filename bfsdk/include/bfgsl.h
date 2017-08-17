//
// Bareflank Hypervisor
//
// Copyright (C) 2015 Assured Information Security, Inc.
// Author: Rian Quinn        <quinnr@ainfosec.com>
// Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

///
/// @file bfgsl.h
///

#ifndef BFGSL_H
#define BFGSL_H

#if defined(__clang__) || defined(__GNUC__)
#pragma GCC system_header
#endif

/// @cond

#define concat1(a,b) a ## b
#define concat2(a,b) concat1(a,b)
#define ___ concat2(dont_care, __COUNTER__)

/// @endcond

#ifndef NEED_GSL_LITE
#include <gsl/gsl>
#else

#include <bfstd.h>

/// @cond

#if defined(__clang__) || defined(__GNUC__)
#define gsl_likely(x) __builtin_expect(!!(x), 1)
#define gsl_unlikely(x) __builtin_expect(!!(x), 0)
#else
#define gsl_likely(x) (x)
#define gsl_unlikely(x) (x)
#endif

#define expects(cond)                                                                              \
    if (gsl_unlikely(!(cond))) {                                                                   \
        std::terminate();                                                                          \
    }
#define ensures(cond)                                                                              \
    if (gsl_unlikely(!(cond))) {                                                                   \
        std::terminate();                                                                          \
    }

/// @endcond

namespace gsl
{

/// Narrow Cast
///
/// A rename of static_cast to indicate a narrow (e.g. 64bit to 32bit)
///
/// @param u the value to narrow
/// @return static_cast<T>(u)
///
template<class T, class U>
inline constexpr T
narrow_cast(U &&u) noexcept
{
    return static_cast<T>(std::forward<U>(u));
}

/// At
///
/// Returns a reference to an element in an array given an index. Unlike
/// the [] operator, if the indexis out-of-bounds, an exception is thrown,
/// or std::terminate() is called.
///
/// @param arr the array
/// @param index the index of the element to retrieve.
/// @return a reference to
///
template<class T, size_t N, class I>
constexpr T &
at(T(&arr)[N], I index)
{
    expects(index >= 0 && index < narrow_cast<I>(N));
    return arr[static_cast<size_t>(index)];
}

/// At
///
/// Returns a reference to an element in an array given an index. Unlike
/// the [] operator, if the indexis out-of-bounds, an exception is thrown,
/// or std::terminate() is called.
///
/// @param arr the array
/// @param index the index of the element to retrieve.
/// @return a reference to
///
template<class T, size_t N, class I>
const constexpr T &
at(const T(&arr)[N], I index)
{
    expects(index >= 0 && index < narrow_cast<I>(N));
    return arr[static_cast<size_t>(index)];
}

/// At
///
/// Returns a reference to an element in an array given an index. Unlike
/// the [] operator, if the indexis out-of-bounds, an exception is thrown,
/// or std::terminate() is called.
///
/// @param arr the array
/// @param N the size of the array
/// @param index the index of the element to retrieve.
/// @return a reference to
///
template<class T, class I>
constexpr T &
at(T *arr, size_t N, I index)
{
    expects(index >= 0 && index < narrow_cast<I>(N));
    return arr[static_cast<size_t>(index)];
}

/// At
///
/// Returns a reference to an element in an array given an index. Unlike
/// the [] operator, if the indexis out-of-bounds, an exception is thrown,
/// or std::terminate() is called.
///
/// @param arr the array
/// @param N the size of the array
/// @param index the index of the element to retrieve.
/// @return a reference to
///
template<class T, class I>
const constexpr T &
at(const T *arr, size_t N, I index)
{
    expects(index >= 0 && index < narrow_cast<I>(N));
    return arr[static_cast<size_t>(index)];
}

}

#endif
#endif
