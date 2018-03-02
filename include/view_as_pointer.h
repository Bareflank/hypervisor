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

#ifndef VIEW_AS_POINTER
#define VIEW_AS_POINTER

#include <type_traits>

// There are basically two different ways to print an integer as a pointer
// (i.e. 0xXXXXXXXXXXXXXXXX).
//
// - You can use the hex / dec stream modifiers, and set the fill and
//   width. This is a lot of code, and the stream modifiers are stateful,
//   so to use them, you must first save off the current modifiers, and
//   then restore them after use.
//
// - Or, you could simply cast the integer as a pointer. This goes
//   against the C++ Core Guidelines, but since the pointer is never
//   dereferenced, it should not be an issue.
//

template<class T,
         class = typename std::enable_if<
             std::is_integral<T>::value
             or
             std::is_pointer<T>::value
             >::type
         >
const void *view_as_pointer(const T val)
{ return reinterpret_cast<const void *>(val); }

#endif
