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

#ifndef COMMAND_LINE_PARSER_H
#define COMMAND_LINE_PARSER_H

#include <string>

namespace command_line_parser_error
{
enum type
{
    success = 0,
    unknown = 1,
    missing = 2
};
}

namespace command_line_parser_command
{
enum type
{
    unknown = 0,
    start = 1,
    stop = 2
};
}

class command_line_parser
{
public:

    command_line_parser();
    virtual ~command_line_parser();

    virtual command_line_parser_error::type parse(int argc, const char *argv[]);

    virtual bool is_valid() const;

    virtual bool help() const;
    virtual command_line_parser_command::type cmd() const;
    virtual std::string modules() const;

private:

    bool m_is_valid;

    bool m_help;
    std::string m_modules;
};

#endif
