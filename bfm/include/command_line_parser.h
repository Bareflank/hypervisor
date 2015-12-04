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

#include <command_line_parser_base.h>

/// Comand Line Parser
///
/// The command line parser is responsible for taking the command line
/// arguments that are given to main(), and parse them for the bareflank
/// manager. All of the commands that are accepted, should be contained in
/// class. Other classes can use the information that this class gathers to
/// decide how to operate.
///
/// This class contains a function called is_valid, that is responsbile
/// for deciding if the commands provided make sense. Use this function along
/// with the cmd() function to determine if the command line args provided
/// make sense, as well as which command to execute.
///
class command_line_parser : public command_line_parser_base
{
public:

    /// Command Line Parser Constructor
    ///
    /// Creates a command line parser given the arc / argv from the
    /// main function.
    ///
    /// @param argc argc from main()
    /// @param argv argv from main()
    ///
    command_line_parser(int argc, const char *argv[]);

    /// Command Line Parser Destructor
    ///
    ~command_line_parser();

    /// Is Valid
    ///
    /// This function returns true if the command line arguments provided
    /// to this function make sense.
    ///
    /// @return true if the arguments make sense, false otherwise
    ///
    bool is_valid() const override;

    /// Command
    ///
    /// Returns the command that was provided in the command line
    /// arguments.
    ///
    /// @return command provided by the arguments
    ///
    command_line_parser_command::type cmd() const override;

    /// Modules
    ///
    /// If the command provided by the arguments is "start", a list of
    /// modules must be provided for the arguments to make sense. This
    /// function returns the provided list of modules when applicable.
    ///
    /// @return module list filename
    ///
    std::string modules() const override;

private:

    void parse_start(int argc, const char *argv[], int index);
    void parse_stop(int argc, const char *argv[], int index);
    void parse_dump(int argc, const char *argv[], int index);

private:

    bool m_is_valid;
    command_line_parser_command::type m_cmd;
    std::string m_modules;
};

#endif
