//
// Bareflank Hypervisor
// Copyright (C) 2015 Assured Information Security, Inc.
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

#include <inttypes.h>

#include <vector>
#include <string>
#include <sstream>

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

/// Digits
///
/// Returns the number of digits in a number given the number and its
/// base. This can be used to figure out the size of the character
/// arracy that is needed to store a given number.
///
/// @expects none
/// @ensures none
///
/// @param val the value to convert to digits
/// @param base the base for conversion
/// @return the total number of digits in val given base
///
inline int
digits(std::size_t val, const int base = 10)
{
    std::array<char, 32> buf;
    std::size_t digits = 0;

    switch (base) {
        case 16: {
            return snprintf(buf.data(), buf.size(), "%" PRIx64, val);
        }

        default: {
            return snprintf(buf.data(), buf.size(), "%" PRIu64, val);
        }
    }
}

/// Convert to String (with base)
///
/// Same thing as std::to_string, but adds the ability to state the base for
/// conversion.
///
/// @expects none
/// @ensures none
///
/// @param str the string to add the converted integer to
/// @param val the value to convert
/// @param base the base for conversion.
/// @param pad if padding should be used
/// @return the total number of digits of val given base
///
inline int
to_string(std::string &str, std::size_t val, const int base = 10, bool pad = true)
{
    std::array<char, 32> buf;
    std::size_t len, digits = 0;

    switch (base) {
        case 16: {
            len = snprintf(buf.data(), buf.size(), "%" PRIx64, val);
            digits = len + 2;

            str += "0x";
            if (pad) {
                for (auto i = 0; i < 16 - len; i++) {
                    str += '0';
                }
                digits += 16 - len;
            }

            break;
        }

        default: {
            len = snprintf(buf.data(), buf.size(), "%" PRIu64, val);
            digits = len;
            break;
        }
    }

    str += std::string_view(buf.data(), len);
    return digits;
}

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
/// @param pad if padding should be used
/// @return string version of val converted to the provided base
///
inline std::string
to_string(std::size_t val, const int base = 10, bool pad = false)
{
    std::string str;
    to_string(str, val, base, pad);

    return str;
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
