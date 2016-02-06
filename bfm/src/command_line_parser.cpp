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

#include <exception.h>

#include <command_line_parser.h>

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

command_line_parser::command_line_parser() noexcept
{
    reset();
}

command_line_parser::~command_line_parser()
{
}

void
command_line_parser::parse(const std::vector<std::string> &args)
{
    for (const auto &arg : args)
    {
        if (arg != "-h" && arg != "--help")
            continue;

        return reset();
    }

    for (auto i = 0U; i < args.size(); i++)
    {
        const auto &arg = args[i];

        if (arg.empty() == true)
            continue;

        if (arg[0] == '-')
            continue;

        if (arg == "load") return parse_load(args, i);
        if (arg == "unload") return parse_unload(args, i);
        if (arg == "start") return parse_start(args, i);
        if (arg == "stop") return parse_stop(args, i);
        if (arg == "dump") return parse_dump(args, i);
        if (arg == "status") return parse_status(args, i);

        throw unknown_command(arg);
    }

    return reset();
}

command_line_parser_command::type
command_line_parser::cmd() const noexcept
{
    return m_cmd;
}

std::string
command_line_parser::modules() const noexcept
{
    return m_modules;
}

void
command_line_parser::reset() noexcept
{
    m_cmd = command_line_parser_command::help;
    m_modules.clear();
}

void
command_line_parser::parse_load(const std::vector<std::string> &args, size_t index)
{
    for (auto i = index + 1; i < args.size(); i++)
    {
        const auto &arg = args[i];

        if (arg.empty() == true)
            continue;

        if (arg[0] == '-')
            continue;

        m_cmd = command_line_parser_command::load;
        m_modules = arg;

        return;
    }

    throw missing_argument();
}

void
command_line_parser::parse_unload(const std::vector<std::string> &args, size_t index)
{
    (void) args;
    (void) index;

    m_cmd = command_line_parser_command::unload;
    m_modules.clear();
}

void
command_line_parser::parse_start(const std::vector<std::string> &args, size_t index)
{
    (void) args;
    (void) index;

    m_cmd = command_line_parser_command::start;
    m_modules.clear();
}

void
command_line_parser::parse_stop(const std::vector<std::string> &args, size_t index)
{
    (void) args;
    (void) index;

    m_cmd = command_line_parser_command::stop;
    m_modules.clear();
}

void
command_line_parser::parse_dump(const std::vector<std::string> &args, size_t index)
{
    (void) args;
    (void) index;

    m_cmd = command_line_parser_command::dump;
    m_modules.clear();
}

void
command_line_parser::parse_status(const std::vector<std::string> &args, size_t index)
{
    (void) args;
    (void) index;

    m_cmd = command_line_parser_command::status;
    m_modules.clear();
}

