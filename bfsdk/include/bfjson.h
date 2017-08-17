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
// MERCHANTABILITY or FITNESS FOR A PARTICULLAR PURPOSE. See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

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
