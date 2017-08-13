// -*- C++ -*-
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
/// @file bfvector.h
///

#ifndef BFVECTOR
#define BFVECTOR

#include <vector>
#include <bfgsl.h>

namespace bfn
{

/// Find
///
/// Get the iterator from the provided vector, given an index.
///
/// @expects index >= 0
/// @expects index < v.size()
/// @ensures ret != v.end()
///
/// @param v std::vector to get iterator from
/// @param index the iterator to locate
/// @return returns the iterator at pos == index, or throws gsl::fail_fast
///
template <
    typename T,
    typename A
    >
auto
find(std::vector<T, A> &v, const std::ptrdiff_t index)
{
    // [[ensures ret: ret != v.end()]]
    expects(index >= 0 && index < gsl::narrow_cast<std::ptrdiff_t>(v.size()));

    return v.begin() + index;
}

/// Find (const)
///
/// Get the iterator from the provided vector, given an index.
///
/// @expects index >= 0
/// @expects index < v.size()
/// @ensures ret != v.end()
///
/// @param v std::vector to get iterator from
/// @param index the iterator to locate
/// @return returns the iterator at pos == index, or throws gsl::fail_fast
///
template <
    typename T,
    typename A
    >
auto
cfind(const std::vector<T, A> &v, const std::ptrdiff_t index)
{
    // [[ensures ret: ret != v.end()]]
    expects(index >= 0 && index < gsl::narrow_cast<std::ptrdiff_t>(v.size()));

    return v.cbegin() + index;
}

/// Remove
///
/// Removes an element from the provided vector. This function uses
/// std::vector::erase, and thus, all iterators are invalidated after this
/// function call is made.
///
/// @expects index >= 0
/// @expects index < v.size()
/// @ensures
///
/// @param v std::vector to get iterator from
/// @param index the iterator to locate
///
template <
    typename T,
    typename A,
    typename I,
    typename = std::enable_if<std::is_integral<I>::value>
    >
void
remove(std::vector<T, A> &v, const I index)
{
    v.erase(cfind(v, index));
}

/// Take
///
/// Takes an element from the provided vector. This function uses
/// std::vector::erase, and thus, all iterators are invalidated after this
/// function call is made.
///
/// @expects index >= 0
/// @expects index < v.size()
/// @ensures
///
/// @param v std::vector to get iterator from
/// @param index the iterator to locate
/// @return returns the element that was removed
///
template <
    typename T,
    typename A,
    typename I,
    typename = std::enable_if<std::is_integral<I>::value>
    >
auto
take(std::vector<T, A> &v, const I index)
{
    const auto iter = cfind(v, index);
    auto val = *iter;

    v.erase(iter);

    return val;
}

}

#endif
