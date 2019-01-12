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
