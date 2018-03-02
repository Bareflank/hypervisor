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
    status = 8,
    vmcall = 9
};

// -----------------------------------------------------------------------------
// Exports
// -----------------------------------------------------------------------------

#include <bfexports.h>

#ifndef STATIC_BFM_SRC
#ifdef SHARED_BFM_SRC
#define EXPORT_BFM_SRC EXPORT_SYM
#else
#define EXPORT_BFM_SRC IMPORT_SYM
#endif
#else
#define EXPORT_BFM_SRC
#endif

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
class EXPORT_BFM_SRC command_line_parser
{
public:

    using registers_type = ioctl::registers_type;           ///< VMCall registers type
    using arg_type = std::string;                           ///< Arg type
    using arg_list_type = std::vector<arg_type>;            ///< Arg list type
    using filename_type = file::filename_type;              ///< Filename type
    using cpuid_type = uint64_t;                            ///< CPUID type
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

    /// CPU ID
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return returns the cpuid provided by the user
    ///
    virtual cpuid_type cpuid() const noexcept;

    /// vCPU ID
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return returns the vcpuid provided by the user
    ///
    virtual vcpuid_type vcpuid() const noexcept;

    /// VMCall Registers
    ///
    /// When a VMCall command is provided, this struct is filled in which
    /// is then sent to the driver to be delivered to the hypervisor for
    /// processing.
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return returns the vmcall registers provided by the user
    ///
    virtual const registers_type &registers() const noexcept;

    /// Input File
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return input filename for "data" vmcall
    ///
    virtual const filename_type &ifile() const noexcept;

    /// Output File
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return output filename for "data" vmcall
    ///
    virtual const filename_type &ofile() const noexcept;

private:

    void reset() noexcept;

    void parse_load(arg_list_type &args);
    void parse_unload(arg_list_type &args);
    void parse_start(arg_list_type &args);
    void parse_stop(arg_list_type &args);
    void parse_quick(arg_list_type &args);
    void parse_dump(arg_list_type &args);
    void parse_status(arg_list_type &args);
    void parse_vmcall(arg_list_type &args);

    void parse_vmcall_version(arg_list_type &args);
    void parse_vmcall_registers(arg_list_type &args);
    void parse_vmcall_string(arg_list_type &args);
    void parse_vmcall_data(arg_list_type &args);
    void parse_vmcall_event(arg_list_type &args);
    void parse_vmcall_unittest(arg_list_type &args);

    void parse_vmcall_string_unformatted(arg_list_type &args);
    void parse_vmcall_string_json(arg_list_type &args);

    void parse_vmcall_data_unformatted(arg_list_type &args);

private:

    command_type m_cmd{};
    filename_type m_modules{};
    cpuid_type m_cpuid{};
    vcpuid_type m_vcpuid{};
    registers_type m_registers{};
    filename_type m_ifile{};
    filename_type m_ofile{};
    arg_type m_string_data{};
};

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#endif
