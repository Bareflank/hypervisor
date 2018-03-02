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

#include <json.h>
#include <exception.h>
#include <vmcall_interface.h>
#include <command_line_parser.h>

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

    auto ___ = gsl::on_failure([&]
    { reset(); });

    for (auto arg = args.begin(); arg != args.end(); ++arg)
    {
        if (arg->empty() || arg->find_first_not_of(" \t") == std::string::npos)
            continue;

        if (*arg == "--cpuid")
        {
            if (++arg == args.end())
                break;

            m_cpuid = std::stoull(*arg, nullptr, 16);
            continue;
        }

        if (*arg == "--vcpuid")
        {
            if (++arg == args.end())
                break;

            m_vcpuid = std::stoull(*arg, nullptr, 16);
            continue;
        }

        if (*arg == "-h" || *arg == "--help")
            return reset();

        if (arg->front() == '-')
            continue;

        if (cmd.empty())
        {
            cmd = *arg;
            continue;
        }

        filtered_args.push_back(*arg);
    }

    if (cmd.empty())
        return reset();

    if (cmd == "load") return parse_load(filtered_args);
    if (cmd == "unload") return parse_unload(filtered_args);
    if (cmd == "start") return parse_start(filtered_args);
    if (cmd == "stop") return parse_stop(filtered_args);
    if (cmd == "dump") return parse_dump(filtered_args);
    if (cmd == "status") return parse_status(filtered_args);
    if (cmd == "vmcall") return parse_vmcall(filtered_args);

    throw unknown_command(cmd);
}

command_line_parser::command_type
command_line_parser::cmd() const noexcept
{ return m_cmd; }

const command_line_parser::filename_type &
command_line_parser::modules() const noexcept
{ return m_modules; }

command_line_parser::cpuid_type
command_line_parser::cpuid() const noexcept
{ return m_cpuid; }

command_line_parser::vcpuid_type
command_line_parser::vcpuid() const noexcept
{ return m_vcpuid; }

const command_line_parser::registers_type &
command_line_parser::registers() const noexcept
{ return m_registers; }

const command_line_parser::filename_type &
command_line_parser::ifile() const noexcept
{ return m_ifile; }

const command_line_parser::filename_type &
command_line_parser::ofile() const noexcept
{ return m_ofile;}

void
command_line_parser::reset() noexcept
{
    m_cmd = command_type::help;
    m_modules.clear();
    m_cpuid = 0;
    m_vcpuid = 0;
    m_registers = registers_type{};
    m_ifile.clear();
    m_ofile.clear();
    m_string_data.clear();
}

void
command_line_parser::parse_load(arg_list_type &args)
{
    if (args.empty())
        throw missing_argument();

    m_cmd = command_type::load;
    m_modules = args[0];
}

void
command_line_parser::parse_unload(arg_list_type &args)
{
    (void) args;
    m_cmd = command_type::unload;
}

void
command_line_parser::parse_start(arg_list_type &args)
{
    (void) args;
    m_cmd = command_type::start;
}

void
command_line_parser::parse_stop(arg_list_type &args)
{
    (void) args;
    m_cmd = command_type::stop;
}

void
command_line_parser::parse_dump(arg_list_type &args)
{
    (void) args;
    m_cmd = command_type::dump;
}

void
command_line_parser::parse_status(arg_list_type &args)
{
    (void) args;
    m_cmd = command_type::status;
}

void
command_line_parser::parse_vmcall(arg_list_type &args)
{
    if (args.empty())
        throw missing_argument();

    auto opcode = bfn::take(args, 0);

    if (opcode == "versions") return parse_vmcall_version(args);
    if (opcode == "registers") return parse_vmcall_registers(args);
    if (opcode == "string") return parse_vmcall_string(args);
    if (opcode == "data") return parse_vmcall_data(args);
    if (opcode == "event") return parse_vmcall_event(args);
    if (opcode == "unittest") return parse_vmcall_unittest(args);

    throw unknown_vmcall_type(opcode);
}

void
command_line_parser::parse_vmcall_version(arg_list_type &args)
{
    if (args.empty())
        throw missing_argument();

    m_registers.r00 = VMCALL_VERSIONS;
    m_registers.r01 = VMCALL_MAGIC_NUMBER;
    m_registers.r02 = std::stoull(args[0]);

    m_cmd = command_type::vmcall;
}

void
command_line_parser::parse_vmcall_registers(arg_list_type &args)
{
    auto index = args.size() - 1;

    m_registers.r00 = VMCALL_REGISTERS;
    m_registers.r01 = VMCALL_MAGIC_NUMBER;

    switch (index)
    {
        case 0xD:
            m_registers.r15 = std::stoull(args[index--], nullptr, 16);
        case 0xC:
            m_registers.r14 = std::stoull(args[index--], nullptr, 16);
        case 0xB:
            m_registers.r13 = std::stoull(args[index--], nullptr, 16);
        case 0xA:
            m_registers.r12 = std::stoull(args[index--], nullptr, 16);
        case 0x9:
            m_registers.r11 = std::stoull(args[index--], nullptr, 16);
        case 0x8:
            m_registers.r10 = std::stoull(args[index--], nullptr, 16);
        case 0x7:
            m_registers.r09 = std::stoull(args[index--], nullptr, 16);
        case 0x6:
            m_registers.r08 = std::stoull(args[index--], nullptr, 16);
        case 0x5:
            m_registers.r07 = std::stoull(args[index--], nullptr, 16);
        case 0x4:
            m_registers.r06 = std::stoull(args[index--], nullptr, 16);
        case 0x3:
            m_registers.r05 = std::stoull(args[index--], nullptr, 16);
        case 0x2:
            m_registers.r04 = std::stoull(args[index--], nullptr, 16);
        case 0x1:
            m_registers.r03 = std::stoull(args[index--], nullptr, 16);
        case 0x0:
            m_registers.r02 = std::stoull(args[index--], nullptr, 16);
            break;

        default:
            break;
    }

    m_cmd = command_type::vmcall;
}

void
command_line_parser::parse_vmcall_string(arg_list_type &args)
{
    if (args.empty())
        throw missing_argument();

    auto type = bfn::take(args, 0);

    if (type == "unformatted") return parse_vmcall_string_unformatted(args);
    if (type == "json") return parse_vmcall_string_json(args);

    throw unknown_vmcall_string_type(type);
}

void
command_line_parser::parse_vmcall_data(arg_list_type &args)
{
    if (args.empty())
        throw missing_argument();

    auto type = bfn::take(args, 0);
    if (type == "unformatted") return parse_vmcall_data_unformatted(args);

    throw unknown_vmcall_data_type(type);
}

void
command_line_parser::parse_vmcall_event(arg_list_type &args)
{
    if (args.empty())
        throw missing_argument();

    m_registers.r00 = VMCALL_EVENT;
    m_registers.r01 = VMCALL_MAGIC_NUMBER;
    m_registers.r02 = std::stoull(args[0], nullptr, 16);

    m_cmd = command_type::vmcall;
}

void
command_line_parser::parse_vmcall_unittest(arg_list_type &args)
{
    if (args.empty())
        throw missing_argument();

    m_registers.r00 = VMCALL_UNITTEST;
    m_registers.r01 = VMCALL_MAGIC_NUMBER;
    m_registers.r02 = std::stoull(args[0], nullptr, 16);

    m_cmd = command_type::vmcall;
}

void
command_line_parser::parse_vmcall_string_unformatted(arg_list_type &args)
{
    if (args.empty())
        throw missing_argument();

    m_string_data = args[0];

    m_registers.r00 = VMCALL_DATA;
    m_registers.r01 = VMCALL_MAGIC_NUMBER;
    m_registers.r02 = 0;
    m_registers.r03 = 0;
    m_registers.r04 = VMCALL_DATA_STRING_UNFORMATTED;
    m_registers.r05 = reinterpret_cast<decltype(m_registers.r05)>(m_string_data.data());
    m_registers.r06 = m_string_data.length();

    m_cmd = command_type::vmcall;
}

void
command_line_parser::parse_vmcall_string_json(arg_list_type &args)
{
    if (args.empty())
        throw missing_argument();

    m_string_data = json::parse(args[0]).dump();

    m_registers.r00 = VMCALL_DATA;
    m_registers.r01 = VMCALL_MAGIC_NUMBER;
    m_registers.r02 = 0;
    m_registers.r03 = 0;
    m_registers.r04 = VMCALL_DATA_STRING_JSON;
    m_registers.r05 = reinterpret_cast<decltype(m_registers.r05)>(m_string_data.data());
    m_registers.r06 = m_string_data.length();

    m_cmd = command_type::vmcall;
}

void
command_line_parser::parse_vmcall_data_unformatted(arg_list_type &args)
{
    if (args.size() < 2)
        throw missing_argument();

    m_registers.r00 = VMCALL_DATA;
    m_registers.r01 = VMCALL_MAGIC_NUMBER;
    m_registers.r02 = 0;
    m_registers.r03 = 0;
    m_registers.r04 = VMCALL_DATA_BINARY_UNFORMATTED;

    m_ifile = args[0];
    m_ofile = args[1];

    m_cmd = command_type::vmcall;
}
