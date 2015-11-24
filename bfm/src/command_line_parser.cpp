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

#include <command_line_parser.h>

command_line_parser::command_line_parser()
{
}

command_line_parser::~command_line_parser()
{
}

command_line_parser_error::type
command_line_parser::parse(int argc, const char *argv[])
{
    return command_line_parser_error::unknown;
}

bool
command_line_parser::is_valid() const
{
    return false;
}

bool
command_line_parser::help() const
{
    return false;
}

command_line_parser_command::type
command_line_parser::cmd() const
{
    return command_line_parser_command::unknown;
}

std::string
command_line_parser::modules() const
{
    return std::string();
}
