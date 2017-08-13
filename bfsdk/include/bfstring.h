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
/// @file bfstring.h
///

#ifndef BFSTRING_H
#define BFSTRING_H

#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <type_traits>

/// std::string literal
///
/// @param str string to convert to std::string
/// @param len len of str
/// @return std::string(str, len)
///
inline auto operator""_s(const char *str, std::size_t len)
{
    return std::string(str, len);
}

namespace bfn
{

/// Convert to String (with base)
///
/// Same thing as std::to_string, but adds the ability to state the base for
/// conversion.
///
/// @expects none
/// @ensures none
///
/// @param val the value to convert
/// @param base the base for conversion.
/// @return string version of val converted to the provided base
///
template <
    typename T,
    typename = std::enable_if<std::is_integral<T>::value>
    >
std::string
to_string(const T val, const int base)
{
    // TODO:
    //
    // C++17 has a new set of functions that called to_chars which gets rid
    // of the allocation. We should use this in the VMM when compiled with
    // our cross compiler. When not compiled with our cross compiler, we
    // should use this code to emulate it so that we do not need C++17 on all
    // systems. This optimization would reduce the debugging code to just
    // page allocations as needed which is ideal
    //

    std::stringstream stream;

    switch (base) {
        case 8:
            stream << "0";
            break;

        case 16:
            stream << "0x";
            stream << std::setfill('0') << std::setw(16);
            break;

        default:
            break;
    };

    stream << std::setbase(base) << std::uppercase << val;
    return stream.str();
}

/// Split String
///
/// Splits a string into a string vector based on a provided
/// delimiter
///
/// @expects none
/// @ensures none
///
/// @param ss the stringstream to split
/// @param delimiter the delimiter to split the string with
/// @return std::vector<std::string> version of str, split using delimiter
///
inline std::vector<std::string>
split(const std::string &str, char delimiter)
{
    std::istringstream ss{str};
    std::vector<std::string> result;

    while (!ss.eof()) {
        std::string field;
        std::getline(ss, field, delimiter);

        result.push_back(field);
    }

    return result;
}

/// Split String
///
/// Splits a string into a string vector based on a provided
/// delimiter
///
/// @expects none
/// @ensures none
///
/// @param str the string to split
/// @param delimiter the delimiter to split the string with
/// @return std::vector<std::string> version of str, split using delimiter
///
inline std::vector<std::string>
split(const char *str, char delimiter)
{
    if (str == nullptr) {
        return {};
    }

    return split(std::string(str), delimiter);
}

}

#endif
