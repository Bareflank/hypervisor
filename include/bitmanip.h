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

#ifndef BITMANIP_H
#define BITMANIP_H

#include <type_traits>

template<class T, class B,
         class = typename std::enable_if<std::is_integral<T>::value>::type,
         class = typename std::enable_if<std::is_integral<B>::value>::type>
auto set_bit(T t, B b) noexcept
{ return t | (0x1UL << b); }

template<class T, class B,
         class = typename std::enable_if<std::is_integral<T>::value>::type,
         class = typename std::enable_if<std::is_integral<B>::value>::type>
auto clear_bit(T t, B b) noexcept
{ return t & ~(0x1UL << b); }

template<class T, class B,
         class = typename std::enable_if<std::is_integral<T>::value>::type,
         class = typename std::enable_if<std::is_integral<B>::value>::type>
auto get_bit(T t, B b) noexcept
{ return (t & (0x1UL << b)) >> b; }

template<class T, class B,
         class = typename std::enable_if<std::is_integral<T>::value>::type,
         class = typename std::enable_if<std::is_integral<B>::value>::type>
auto is_bit_set(T t, B b) noexcept
{ return get_bit(t, b) != 0; }

template<class T, class B,
         class = typename std::enable_if<std::is_integral<T>::value>::type,
         class = typename std::enable_if<std::is_integral<B>::value>::type>
auto is_bit_cleared(T t, B b) noexcept
{ return get_bit(t, b) == 0; }

template<class T,
         class = typename std::enable_if<std::is_integral<T>::value>::type>
auto num_bits_set(T t) noexcept
{ return __builtin_popcountll(t); }

template<class T, class M,
         class = typename std::enable_if<std::is_integral<T>::value>::type,
         class = typename std::enable_if<std::is_integral<M>::value>::type>
auto get_bits(T t, M m) noexcept
{ return t & m; }

template<class T, class M, class V,
         class = typename std::enable_if<std::is_integral<T>::value>::type,
         class = typename std::enable_if<std::is_integral<M>::value>::type,
         class = typename std::enable_if<std::is_integral<V>::value>::type>
auto set_bits(T t, M m, V v) noexcept
{ return (t & ~m) | (v & m); }

#endif
