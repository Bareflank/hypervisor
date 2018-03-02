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

#include <command_line_parser.h>

#include <bfgsl.h>
#include <bfjson.h>
#include <bfvector.h>
#include <bfvcpuid.h>

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

command_line_parser::command_line_parser()
{ reset(); }

void
command_line_parser::parse(const arg_list_type &args)
{
    arg_type cmd;
    arg_list_type filtered_args;

    auto ___ = gsl::on_failure([&] {
        reset();
    });

    for (auto arg = args.begin(); arg != args.end(); ++arg) {

        if (arg->empty()) {
            continue;
        }

        if (arg->find_first_not_of(" \t") == std::string::npos) {
            continue;
        }

        if (*arg == "--vcpuid") {

            if (++arg == args.end()) {
                break;
            }

            m_vcpuid = std::stoull(*arg, nullptr, 16);
            continue;
        }

        if (*arg == "-h" || *arg == "--help") {
            return reset();
        }

        if (arg->front() == '-') {
            continue;
        }

        if (cmd.empty()) {
            cmd = *arg;
            continue;
        }

        filtered_args.push_back(*arg);
    }

    if (cmd.empty()) {
        return reset();
    }

    if (cmd == "load") { return parse_load(filtered_args); }
    if (cmd == "unload") { return parse_unload(filtered_args); }
    if (cmd == "start") { return parse_start(filtered_args); }
    if (cmd == "stop") { return parse_stop(filtered_args); }
    if (cmd == "quick") { return parse_quick(filtered_args); }
    if (cmd == "dump") { return parse_dump(filtered_args); }
    if (cmd == "status") { return parse_status(filtered_args); }

    throw std::runtime_error("unknown command: " + cmd);
}

command_line_parser::command_type
command_line_parser::cmd() const noexcept
{ return m_cmd; }

const command_line_parser::filename_type &
command_line_parser::modules() const noexcept
{ return m_modules; }

command_line_parser::vcpuid_type
command_line_parser::vcpuid() const noexcept
{ return m_vcpuid; }

void
command_line_parser::reset() noexcept
{
    m_cmd = command_type::help;
    m_modules.clear();
    m_vcpuid = vcpuid::invalid;
}

void
command_line_parser::parse_load(arg_list_type &args)
{
    m_cmd = command_type::load;

    if (!args.empty()) {
        m_modules = args[0];
    }
}

void
command_line_parser::parse_unload(arg_list_type &args)
{
    bfignored(args);
    m_cmd = command_type::unload;
}

void
command_line_parser::parse_start(arg_list_type &args)
{
    bfignored(args);
    m_cmd = command_type::start;
}

void
command_line_parser::parse_stop(arg_list_type &args)
{
    bfignored(args);
    m_cmd = command_type::stop;
}

void
command_line_parser::parse_quick(arg_list_type &args)
{
    bfignored(args);
    m_cmd = command_type::quick;
}

void
command_line_parser::parse_dump(arg_list_type &args)
{
    bfignored(args);
    m_cmd = command_type::dump;
}

void
command_line_parser::parse_status(arg_list_type &args)
{
    bfignored(args);
    m_cmd = command_type::status;
}
