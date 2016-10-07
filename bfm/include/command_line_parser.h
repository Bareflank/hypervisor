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

#include <vector>
#include <string>

namespace command_line_parser_command
{
    enum type
    {
        help = 1,
        load = 2,
        unload = 3,
        start = 4,
        stop = 5,
        dump = 6,
        status = 7
    };
}

/// Command Line Parser
///
/// The command line parser is responsible for taking the command line
/// arguments that are given to main(), and parse them for the bareflank
/// manager. All of the commands that are accepted, should be contained in
/// this class. Other classes can use the information that this class gathers
/// to decide how to operate.
///
/// This class contains a function called is_valid, that is responsbile
/// for deciding if the commands provided make sense. Use this function along
/// with the cmd() function to determine if the command line args provided
/// make sense, as well as which command to execute.
///
class command_line_parser
{
public:

    /// Command Line Parser Constructor
    ///
    /// Creates a default command line parser with:
    /// - cmd() == command_line_parser_command::help
    /// - modules() == std::string()
    ///
    command_line_parser() noexcept;

    /// Command Line Parser Destructor
    ///
    virtual ~command_line_parser() = default;

    /// Parse Command Line
    ///
    /// Parses the command line. Upon successfull completion, resets the
    /// internal state to resemble the provided arguments. On failure, this
    /// function has a strong no-effect guarantee, and throws an exception.
    /// If an empty list is provided, this function resets the internal state
    /// to that of the default constructor
    ///
    /// @param args the arguments to parse (likely a list compiled from
    ///     argc and argv)
    /// @throws unknown_command_error thrown if the provided arguments do not
    ///     contain a recognizable command.
    /// @throws missing_argument_error thrown if a provided argument is
    ///     missing
    ///
    virtual void parse(const std::vector<std::string> &args);

    /// Command
    ///
    /// Returns the command that was provided in the command line
    /// arguments.
    ///
    /// @return command provided by the arguments
    ///
    virtual command_line_parser_command::type cmd() const noexcept;

    /// Modules
    ///
    /// If the command provided by the arguments is "start", a list of
    /// modules must be provided for the arguments to make sense. This
    /// function returns the provided list of modules when applicable.
    ///
    /// @return module list filename
    ///
    virtual std::string modules() const noexcept;

    /// vCPU ID
    ///
    /// Each guest + core combination has its own vCPU ID. This command
    /// lets the user specify which core + guest to target for information.
    ///
    /// @return returns the vcpuid provided by the user
    virtual uint64_t vcpuid() const noexcept;

    /// Reset
    ///
    /// Resets the internal state to that of the default constructor
    ///
    void reset() noexcept;

private:

    void parse_load(const std::vector<std::string> &args, size_t index);
    void parse_unload(const std::vector<std::string> &args, size_t index);
    void parse_start(const std::vector<std::string> &args, size_t index);
    void parse_stop(const std::vector<std::string> &args, size_t index);
    void parse_dump(const std::vector<std::string> &args, size_t index);
    void parse_status(const std::vector<std::string> &args, size_t index);

private:

    command_line_parser_command::type m_cmd;
    std::string m_modules;
    uint64_t m_vcpuid;
};

#endif
