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

#include <command_line_parser.h>
#include <file.h>
#include <ioctl.h>
#include <split.h>

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

    /// Default Constructor
    ///
    ioctl_driver() noexcept = default;

    /// Destructor
    ///
    virtual ~ioctl_driver() = default;

    /// Process
    ///
    /// Processes the IOCTL driver based on the information provided during
    /// construction. If the IOCTL driver has a problem during processing,
    /// this function will return with an error.
    ///
    /// @param f file class used to read from the filesystem
    /// @param ctl ioctl class used to communicate with the driver entry
    /// @param clp command line parser used to parse user input
    ///
    /// @throws invalid_argument_error thrown if f == 0, ctl == 0 or clp == 0
    /// @throws corrupt_vmm_error thrown if the VMM is in a corrupt state.
    ///     The VMM gets into a corrupt state when a stop or unload fails.
    ///     Once this happens, dump still works, but everthing else will fail.
    /// @throws unknown_status_error if the VMM is in an unknown state. This
    ///     should never happen. If it doesn, the driver is not working right
    /// @throws invalid_vmm_state_error if the VMM is in an invalid state. This
    ///     usually happens because the clp states the user wanted to start or
    ///     dump but forgot to load the VMM first.
    ///
    virtual void process(std::shared_ptr<file> f,
                         std::shared_ptr<ioctl> ctl,
                         std::shared_ptr<command_line_parser> clp);

private:

    void load_vmm(const std::shared_ptr<file> &f,
                  const std::shared_ptr<ioctl> &ctl,
                  const std::shared_ptr<command_line_parser> &clp);

    void unload_vmm(const std::shared_ptr<ioctl> &ctl);
    void start_vmm(const std::shared_ptr<ioctl> &ctl);
    void stop_vmm(const std::shared_ptr<ioctl> &ctl);
    void dump_vmm(const std::shared_ptr<ioctl> &ctl, uint64_t vcpuid);
    void vmm_status(const std::shared_ptr<ioctl> &ctl);

    int64_t get_status(const std::shared_ptr<ioctl> &ctl);
};

#endif
