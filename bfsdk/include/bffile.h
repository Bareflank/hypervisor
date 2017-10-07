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
/// @file bffile.h
///

#ifndef BFFILE_H
#define BFFILE_H

#include <cstdlib>

#include <string>
#include <vector>
#include <fstream>

#include <bfgsl.h>
#include <bftypes.h>
#include <bfbuffer.h>
#include <bfexception.h>

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

    using text_data = std::string;                      ///< File format for text data
    using binary_data = bfn::buffer;                    ///< File format for binary data
    using filename_type = std::string;                  ///< File name type
    using extension_type = std::string;                 ///< Extension name type
    using path_list_type = std::vector<std::string>;    ///< Find files path type
    using filesize_type = std::size_t;                  ///< File size type

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
    VIRTUAL ~file() noexcept = default;

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
    /// optimization notes:
    /// - http://insanecoding.blogspot.it/2011/11/how-to-read-in-file-in-c.html
    /// - since std::string has to initialize the backing array, reading in
    ///   a binary will always be faster. Thus, use read_binary if possible
    ///
    VIRTUAL text_data
    read_text(const filename_type &filename) const
    {
        expects(!filename.empty());

        std::fstream handle(filename, std::ios_base::in | std::ios_base::binary);
        if (handle) {

            handle.seekg(0, std::ios::end);
            auto size = handle.tellg();

            if (size <= 0) {
                return text_data{};
            }

            handle.seekg(0, std::ios::beg);
            text_data buffer(static_cast<text_data::size_type>(size), 0);

            handle.read(&buffer.front(), size);
            return buffer;
        }

        throw std::runtime_error("invalid filename: " + filename);
    }

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
    /// optimization notes:
    /// - http://insanecoding.blogspot.it/2011/11/how-to-read-in-file-in-c.html
    ///
    VIRTUAL binary_data
    read_binary(const filename_type &filename) const
    {
        expects(!filename.empty());

        std::fstream handle(filename, std::ios_base::in | std::ios_base::binary);
        if (handle) {

            handle.seekg(0, std::ios::end);
            auto size = handle.tellg();

            if (size <= 0) {
                return binary_data{};
            }

            handle.seekg(0, std::ios::beg);
            binary_data buffer(static_cast<binary_data::size_type>(size));

            handle.read(buffer.data(), size);
            return buffer;
        }

        throw std::runtime_error("invalid filename: " + filename);
    }

    /// Write
    ///
    /// Writes text data to the file provided
    ///
    /// @expects filename.empty() == false
    /// @expects buffer.empty() == false
    /// @ensures none
    ///
    /// @param filename name of the file to write to.
    /// @param buffer data to write
    ///
    VIRTUAL void
    write_text(const filename_type &filename, const text_data &buffer) const
    {
        expects(!filename.empty());

        std::fstream handle(filename, std::ios_base::out | std::ios_base::binary);
        if (handle) {
            handle.write(buffer.data(), static_cast<std::streamsize>(buffer.size()));
            return;
        }

        throw std::runtime_error("invalid filename: " + filename);
    }

    /// Write
    ///
    /// Writes binary data to the file provided
    ///
    /// @expects filename.empty() == false
    /// @expects buffer.empty() == false
    /// @ensures none
    ///
    /// @param filename name of the file to write to.
    /// @param buffer data to write
    ///
    VIRTUAL void
    write_binary(const filename_type &filename, const binary_data &buffer) const
    {
        expects(!filename.empty());

        std::fstream handle(filename, std::ios_base::out | std::ios_base::binary);
        if (handle) {
            handle.write(buffer.data(), static_cast<std::streamsize>(buffer.size()));
            return;
        }

        throw std::runtime_error("invalid filename: " + filename);
    }

    /// Get File Extension
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param filename the file name to extract the extension
    /// @return the filename's extension
    ///
    VIRTUAL extension_type
    extension(const filename_type &filename) const
    {
        if (filename.empty()) {
            return {};
        }

        auto index = filename.find_last_of('.');

        if (index != filename_type::npos) {
            return filename.substr(index);
        }

        return {};
    }

    /// File Exists
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param filename the file name to check
    /// @return true if the file exists, false otherwise
    ///
    VIRTUAL bool
    exists(const filename_type &filename) const
    {
        std::ifstream handle{filename};
        return handle.good();
    }

    /// File Size
    ///
    /// @expects filename.empty() == false
    /// @ensures none
    ///
    /// @param filename to get the size of
    /// @return size of filename
    ///
    VIRTUAL filesize_type
    size(const filename_type &filename) const
    {
        expects(!filename.empty());

        std::fstream handle(filename, std::ios_base::in | std::ios_base::binary);
        if (handle) {
            handle.seekg(0, std::ios::end);
            return static_cast<filesize_type>(handle.tellg());
        }

        throw std::runtime_error("invalid filename: " + filename);
    }

    /// Find Files
    ///
    /// Loops through all of the provided files and file paths and
    /// returns a list of each filename combined with the path and the filename
    /// that was first found. If a filename cannot be found, an exception is
    /// thrown.
    ///
    /// @note we use the '/' separator on both Windows and POSIX. The reason
    ///     is both support '/' for the versions we support.
    ///
    /// @expects files.empty() == false
    /// @expects paths.empty() == false
    /// @ensures ret: path_list_type.size() == files.size()
    ///
    /// @param files list of files to locate in the list of provided paths
    /// @param paths list of paths to search for the provided list of files
    /// @return pull paths for each file located, throws otherwise
    ///
    VIRTUAL path_list_type
    find_files(const path_list_type &files, const path_list_type &paths) const
    {
        expects(!paths.empty());
        path_list_type results;

        for (const auto &filename : files) {
            auto found = false;

            for (auto path : paths) {
                path += '/';
                path += filename;

                if (exists(path)) {
                    results.push_back(path);

                    found = true;
                    break;
                }
            }

            if (!found) {
                throw std::runtime_error("unable to locate file: " + filename);
            }
        }

        return results;
    }

    /// Get Home Directory
    ///
    /// @expects none
    /// @expects none
    ///
    /// @return returns home directory
    ///
    VIRTUAL std::string
    home() const
    {
        char *home;

        home = std::getenv("HOME");
        if (home != nullptr) {
            return {home};
        }

        home = std::getenv("HOMEPATH");
        if (home != nullptr) {
            return {home};
        }

        throw std::runtime_error("HOME or HOMEPATH not set");
    }

public:

    /// @cond

    file(file &&) noexcept = default;
    file &operator=(file &&) noexcept = default;

    file(const file &) = default;
    file &operator=(const file &) = default;

    /// @endcond
};

#endif
