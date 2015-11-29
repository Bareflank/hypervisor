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

#ifndef IOCTL_DRIVER_H
#define IOCTL_DRIVER_H

#include <command_line_parser_base.h>
#include <debug.h>
#include <file_base.h>
#include <ioctl_base.h>
#include <split.h>

namespace ioctl_driver_error
{
    enum type
    {
        success = 0,
        failure = 1
    };
}

/// IOCTL Driver
///
/// The IOCTL driver is the main work horse of the Bareflank Manager. The
/// IOCTL driver takes the command line parser, and using a file class, and
/// IOCTL class, tells the driver entry what to do based on input provided by
/// the command line parser.
///
/// If certain conditions are not meet, the IOCTL driver will error out on
/// it's attempt to process, and return an error.
class ioctl_driver
{
public:

    /// IOCTL Driver Constructor
    ///
    /// Creates and IOCTL driver to tell the driver entry what to do
    /// based on information provided by the command lin e parser.
    ///
    /// @param fb file class used to read from the filesystem
    /// @param ioctlb ioctl class used to communicate with the driver entry
    /// @param clpb command line parser used to parse user input
    ioctl_driver(const file_base *const fb,
                 const ioctl_base *const ioctlb,
                 const command_line_parser_base *const clpb);

    /// IOCTL Driver Destructor
    ///
    ~ioctl_driver();

    /// Process
    ///
    /// Processes the IOCTL driver based on the information provided during
    /// construction. If the IOCTL driver has a problem during processing,
    /// this function will return with an error.
    ///
    /// @return success on success, failure otherwise.
    ///
    ioctl_driver_error::type process() const;

private:

    ioctl_driver_error::type start_vmm() const;
    ioctl_driver_error::type stop_vmm() const;

private:

    const file_base *const m_fb;
    const ioctl_base *const m_ioctlb;
    const command_line_parser_base *const m_clpb;
};

#endif
