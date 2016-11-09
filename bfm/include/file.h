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
#include <vector>

/// File
///
/// This class is responsible for working with a file. Specifically, this
/// class wraps calls to ifstream and fstream to simplify their interface
/// as well as provide an implementation for the rest of the Bareflank
/// Manager, such that testing is easier.
///
class file
{
public:

    using text_data = std::string;
    using binary_data = std::vector<char>;
    using filename_type = std::string;

    /// File Constructor
    ///
    /// @expects none
    /// @ensures none
    ///
    /// Creates a file class that can be used to working with files.
    ///
    file() noexcept = default;

    /// File Destructor
    ///
    /// @expects none
    /// @ensures none
    ///
    virtual ~file() = default;

    /// Read
    ///
    /// Reads the entire contents of a file, in text form
    ///
    /// @expects filename.empty() == false
    /// @ensures none
    ///
    /// @param filename name of the file to read.
    /// @return the contents of filename
    ///
    virtual text_data read_text(const filename_type &filename) const;

    /// Read
    ///
    /// Reads the entire contents of a file, in binary form
    ///
    /// @expects filename.empty() == false
    /// @ensures none
    ///
    /// @param filename name of the file to read.
    /// @return the contents of filename
    ///
    virtual binary_data read_binary(const filename_type &filename) const;

    /// Write
    ///
    /// Writes text data to the file provided
    ///
    /// @expects filename.empty() == false
    /// @expects data.empty() == false
    /// @ensures none
    ///
    /// @param filename name of the file to write to.
    /// @param data data to write
    ///
    virtual void write_text(const filename_type &filename, const text_data &data) const;

    /// Write
    ///
    /// Writes binary data to the file provided
    ///
    /// @expects filename.empty() == false
    /// @expects data.empty() == false
    /// @ensures none
    ///
    /// @param filename name of the file to write to.
    /// @param data data to write
    ///
    virtual void write_binary(const filename_type &filename, const binary_data &data) const;
};

#endif
