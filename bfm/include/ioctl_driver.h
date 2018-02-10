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

#ifndef IOCTL_DRIVER_H
#define IOCTL_DRIVER_H

#include <ioctl.h>
#include <command_line_parser.h>

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4251)
#endif

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

/// IOCTL Driver
///
/// The IOCTL driver is the main work horse of the Bareflank Manager. The
/// IOCTL driver takes the command line parser, and using a file class, and
/// IOCTL class, tells the driver entry what to do based on input provided by
/// the command line parser.
///
/// If certain conditions are not meet, the IOCTL driver will error out on
/// it's attempt to process, and return an error.
///
class ioctl_driver
{
public:

    using status_type = ioctl::status_type;                         ///< Status type
    using filename_type = std::string;                              ///< Filename type
    using list_type = std::vector<std::string>;                     ///< List type

    /// Default Constructor
    ///
    /// @expects f != nullptr
    /// @expects ctl != nullptr
    /// @expects clp != nullptr
    /// @ensures none
    ///
    /// @param f file class used to read/write from/to the filesystem
    /// @param ctl ioctl class used to communicate with the driver entry
    /// @param clp command line parser used to parse user input
    ///
    ioctl_driver(gsl::not_null<file *> f,
                 gsl::not_null<ioctl *> ctl,
                 gsl::not_null<command_line_parser *> clp);

    /// Destructor
    ///
    /// @expects none
    /// @ensures none
    ///
    ~ioctl_driver() = default;

    /// Process
    ///
    /// Processes the IOCTL driver based on the information provided during
    /// construction. If the IOCTL driver has a problem during processing,
    /// this function will return with an error.
    ///
    /// @expects none
    /// @ensures none
    ///
    void process();

#ifndef ENABLE_BUILD_TEST
private:
#endif

    void load_vmm();
    void unload_vmm();
    void start_vmm();
    void stop_vmm();
    void quick_vmm();
    void dump_vmm();
    void vmm_status();

    status_type get_status() const;

    list_type library_path();
    filename_type vmm_filename();
    list_type vmm_module_list(const filename_type &filename);

private:

    gsl::not_null<file *> m_file;
    gsl::not_null<ioctl *> m_ioctl;
    gsl::not_null<command_line_parser *> m_clp;
};

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#endif
