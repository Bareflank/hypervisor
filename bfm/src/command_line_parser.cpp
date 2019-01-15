//
// Copyright (C) 2019 Assured Information Security, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

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
