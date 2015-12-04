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

#ifndef COMMAND_LINE_PARSER_BASE_H
#define COMMAND_LINE_PARSER_BASE_H

#include <string>

namespace command_line_parser_command
{
    enum type
    {
        unknown = 0,
        help = 1,
        start = 2,
        stop = 3,
        dump = 4
    };
}

class command_line_parser_base
{
public:

    command_line_parser_base() {}
    virtual ~command_line_parser_base() {}

    virtual bool is_valid() const
    { return false; }

    virtual command_line_parser_command::type cmd() const
    { return command_line_parser_command::unknown; }

    virtual std::string modules() const
    { return std::string(); }
};

#endif
