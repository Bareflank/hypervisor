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

#include <fstream>
#include <file_base.h>

/// File
///
/// This class is responsible for working with a file. Specifically, this
/// class wraps calls to ifstream and fstream to simplify their interface
/// as well as provide an implementation for the rest of the Bareflank
/// Manager, such that testing is eaiser.
class file : public file_base
{
public:

    /// File Constructor
    ///
    /// Creates a file class that can be used to working with files.
    file();

    /// File Destructor
    ///
    ~file();

    /// Exists
    ///
    /// Returns true if the file provides exists on the filesystem.
    ///
    /// @param filename the filename to check for existence.
    /// @return true if filename exists
    ///
    bool exists(const std::string &filename) const override;

    /// Read
    ///
    /// Reads the entire contents of a file, and returns the result in
    /// a c++ standard string. If the file does not exist, an empty
    /// string is returned.
    ///
    /// @param filename the filename to read.
    /// @return the contents of filename, or an empty string if filename
    ///         does not exists.
    std::string read(const std::string &filename) const override;
};

#endif
