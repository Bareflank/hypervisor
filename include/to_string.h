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

#ifndef BFN_TO_STRING
#define BFN_TO_STRING

#include <sstream>
#include <iomanip>

namespace bfn
{
template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
std::string to_string(T val, int base)
{
    std::stringstream stream;

    if (base == 8) stream << "0";
    if (base == 16) stream << "0x";
    stream << std::setbase(base) << std::uppercase << val;

    return stream.str();
}
}

#endif
