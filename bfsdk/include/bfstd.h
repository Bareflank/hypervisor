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
