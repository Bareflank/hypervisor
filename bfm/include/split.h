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

#ifndef SPLIT_H
#define SPLIT_H

#include <vector>
#include <string>
#include <sstream>

/// Split String
///
/// C++ does not provide a split string function for std::string. The
/// following function provides a split function given a single character
/// delimiter.
///
/// @param str the string to split
/// @param delimiter the character to search for the seperates the str
/// @return str, broken up into a vector or strings, delimited by the
///         provided delimiter
std::vector<std::string> split(const std::string &str, char delimiter);

#endif
