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

#ifndef COMMAND_LINE_PARSER_H
#define COMMAND_LINE_PARSER_H

#include <vector>
#include <string>

#include <ioctl.h>
#include <bffile.h>

enum class command_line_parser_command {
    help = 1,
    load = 2,
    unload = 3,
    start = 4,
    stop = 5,
    quick = 6,
    dump = 7,
    status = 8
};

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4251)
#endif

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

/// Command Line Parser
///
/// The command line parser is responsible for taking the command line
/// arguments that are given to main(), and parse them for the bareflank
/// manager. All of the commands that are accepted, should be contained in
/// this class. Other classes can use the information that this class gathers
/// to decide how to operate.
///
class command_line_parser
{
public:

    using arg_type = std::string;                           ///< Arg type
    using arg_list_type = std::vector<arg_type>;            ///< Arg list type
    using filename_type = file::filename_type;              ///< Filename type
    using vcpuid_type = ioctl::vcpuid_type;                 ///< VCPUID type
    using command_type = command_line_parser_command;       ///< Command type

    /// Command Line Parser Constructor
    ///
    /// @expects none
    /// @ensures none
    ///
    command_line_parser();

    /// Command Line Parser Destructor
    ///
    /// @expects none
    /// @ensures none
    ///
    virtual ~command_line_parser() = default;

    /// Parse Command Line
    ///
    /// Parses the command line. Upon successful completion, resets the
    /// internal state to resemble the provided arguments. On failure, this
    /// function throws an exception, and resets it's internal state.
    /// If an empty list is provided, this function resets the internal state
    /// to that of the default constructor
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param args the arguments to parse
    ///
    virtual void parse(const arg_list_type &args);

    /// Command
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return command provided by the arguments
    ///
    virtual command_type cmd() const noexcept;

    /// Modules
    ///
    /// If the command provided by the arguments is "load", a list of
    /// modules must be provided for the arguments to make sense. This
    /// function returns the filename of the module file that was provided
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return module list filename
    ///
    virtual const filename_type &modules() const noexcept;

    /// vCPU ID
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return returns the vcpuid provided by the user
    ///
    virtual vcpuid_type vcpuid() const noexcept;

private:

    void reset() noexcept;

    void parse_load(arg_list_type &args);
    void parse_unload(arg_list_type &args);
    void parse_start(arg_list_type &args);
    void parse_stop(arg_list_type &args);
    void parse_quick(arg_list_type &args);
    void parse_dump(arg_list_type &args);
    void parse_status(arg_list_type &args);

private:

    command_type m_cmd{};
    filename_type m_modules{};
    vcpuid_type m_vcpuid{};
};

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#endif
