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

#ifndef FILE_H
#define FILE_H

#include <string>
#include <fstream>

/// File
///
/// This class is responsible for working with a file. Specifically, this
/// class wraps calls to ifstream and fstream to simplify their interface
/// as well as provide an implementation for the rest of the Bareflank
/// Manager, such that testing is eaiser.
class file
{
public:

    /// File Constructor
    ///
    /// Creates a file class that can be used to working with files.
    file() noexcept = default;

    /// File Destructor
    ///
    virtual ~file() = default;

    /// Read
    ///
    /// Reads the entire contents of a file, and returns the result in
    /// a c++ standard string.
    ///
    /// @param filename the filename to read.
    /// @return the contents of filename
    ///
    /// @throws invalid_filename_error thrown if the filename does not exist
    ///     or is not readable
    ///
    virtual std::string read(const std::string &filename) const;
};

#endif
