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

#include <debug.h>
#include <string.h>
#include <command_line_parser.h>

command_line_parser::command_line_parser(int argc, const char *argv[]) :
    m_is_valid(false),
    m_cmd(command_line_parser_command::unknown)
{
    if (argc <= 1)
    {
        m_is_valid = true;
        m_cmd = command_line_parser_command::help;
        return;
    }

    for (auto i = 1; i < argc; i++)
    {
        std::string str(argv[i]);

        if (str.compare("-h") == 0 ||
            str.compare("--help") == 0)
        {
            m_is_valid = true;
            m_cmd = command_line_parser_command::help;
            return;
        }
    }

    for (auto i = 1; i < argc; i++)
    {
        std::string str(argv[i]);

        if (str.empty() == true)
            continue;

        if (str[0] == '-')
            continue;

        if (str.compare("start") == 0)
        {
            parse_start(argc, argv, i + 1);
            return;
        }

        if (str.compare("stop") == 0)
        {
            parse_stop(argc, argv, i + 1);
            return;
        }

        if (str.compare("dump") == 0)
        {
            parse_dump(argc, argv, i + 1);
            return;
        }

        bfm_error << "unknown command" << std::endl;
        break;
    }
}

command_line_parser::~command_line_parser()
{
}

bool
command_line_parser::is_valid() const
{
    return m_is_valid;
}

command_line_parser_command::type
command_line_parser::cmd() const
{
    return m_cmd;
}

std::string
command_line_parser::modules() const
{
    return m_modules;
}

void
command_line_parser::parse_start(int argc, const char *argv[], int index)
{
    auto i = index;
    m_cmd = command_line_parser_command::start;

    for (; i < argc; i++)
    {
        std::string str(argv[i]);

        if (str.empty() == true)
            continue;

        if (str[0] == '-')
            continue;

        m_modules = str;
        break;
    }

    if (i >= argc)
    {
        bfm_error << "missing argument" << std::endl;
        return;
    }

    m_is_valid = true;
}

void
command_line_parser::parse_stop(int argc, const char *argv[], int index)
{
    m_is_valid = true;
    m_cmd = command_line_parser_command::stop;
}

void
command_line_parser::parse_dump(int argc, const char *argv[], int index)
{
    m_is_valid = true;
    m_cmd = command_line_parser_command::dump;
}
