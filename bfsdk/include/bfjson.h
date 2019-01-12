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
/// @file bfjson.h
///

#ifndef BFJSON_H
#define BFJSON_H

#include <bfgsl.h>

#include <nlohmann/json.hpp>
using json = nlohmann::json;                ///< Simply namespace

/// JSON Hex or Dec
///
/// Converts a JSON object's field to T. The field name can either be "<field>"
/// or "<field>_hex". If "_hex" is added to the field name, the value is
/// interpreted as a hex string, other wise it's interpreted as a dec number.
///
/// @expects none
/// @ensures none
///
/// @param obj the json object
/// @param field the field name
/// @return returns the converted number or throws
///
template <
    typename T,
    typename J,
    typename = std::enable_if<std::is_integral<T>::value>
    >
auto
json_hex_or_dec(const J &obj, const std::string &field)
{
    auto val_hex = obj.value(field + "_hex", json(nullptr));

    if (val_hex.is_string()) {
        return gsl::narrow_cast<T>(std::stoull(val_hex.template get<std::string>(), 0, 16));
    }

    auto val_dec = obj.at(field);

    if (val_dec.is_number()) {
        return gsl::narrow_cast<T>(val_dec.template get<T>());
    }

    throw std::runtime_error("json is neither a hex or dec");
}

/// JSON Hex or Dec Array
///
/// Converts a JSON object's field to [T]. The field name can either be
/// "<field>" or "<field>_hex". If "_hex" is added to the field name, each value
/// is interpreted as a hex string, other wise they are interpreted as a dec
/// number.
///
/// @expects none
/// @ensures none
///
/// @param obj the json object
/// @param field the field name
/// @return returns std::vector with the converted numbers or throws
///
template <
    typename T,
    typename J,
    typename = std::enable_if<std::is_integral<T>::value>
    >
auto
json_hex_or_dec_array(const J &obj, const std::string &field)
{
    std::vector<T> result;
    auto array_hex = obj.value(field + "_hex", json(nullptr));

    if (array_hex.is_array()) {
        for (auto val : array_hex) {
            result.push_back(gsl::narrow_cast<T>(std::stoull(val.template get<std::string>(), 0, 16)));
        }

        return result;
    }

    auto array_dec = obj.at(field);

    if (array_dec.is_array()) {
        for (auto val : array_dec) {
            result.push_back(gsl::narrow_cast<T>(val.template get<T>()));
        }

        return result;
    }

    throw std::runtime_error("json is neither a hex or dec");
}

#endif
