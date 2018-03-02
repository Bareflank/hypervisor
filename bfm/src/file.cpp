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

#include <gsl/gsl>

#include <fstream>

#include <file.h>
#include <exception.h>

file::text_data
file::read_text(const filename_type &filename) const
{
    expects(!filename.empty());

    if (auto && handle = std::fstream(filename, std::ios_base::in))
        return text_data(std::istreambuf_iterator<char>(handle),
                         std::istreambuf_iterator<char>());

    throw invalid_file(filename);
}

file::binary_data
file::read_binary(const filename_type &filename) const
{
    expects(!filename.empty());

    if (auto && handle = std::fstream(filename, std::ios_base::in | std::ios_base::binary))
        return binary_data(std::istreambuf_iterator<char>(handle),
                           std::istreambuf_iterator<char>());

    throw invalid_file(filename);
}

void
file::write_text(const filename_type &filename, const text_data &data) const
{
    expects(!filename.empty());
    expects(!data.empty());

    if (auto && handle = std::fstream(filename, std::ios_base::out | std::ios_base::binary))
    {
        std::copy(data.begin(), data.end(), std::ostreambuf_iterator<char>(handle));
        return;
    }

    throw invalid_file(filename);
}

void
file::write_binary(const filename_type &filename, const binary_data &data) const
{
    expects(!filename.empty());
    expects(!data.empty());

    if (auto && handle = std::fstream(filename, std::ios_base::out | std::ios_base::binary))
    {
        std::copy(data.begin(), data.end(), std::ostreambuf_iterator<char>(handle));
        return;
    }

    throw invalid_file(filename);
}
