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

#ifndef IOCTL_H
#define IOCTL_H

#include <memory>
#include <stdint.h>
#include <driver_entry_interface.h>

/// IOCTL Private Base
///
/// Only needed for dynamic cast
///
class ioctl_private_base
{
public:
    ioctl_private_base() = default;
    virtual ~ioctl_private_base() = default;
};

/// IOCTL
///
/// Calls into the bareflank driver entry to perform a desired action. Note
/// that for this class to function, the driver entry must be loaded, and
/// bfm must be executed with the proper permissions.
///
class ioctl
{
public:

    /// Default Constructor
    ///
    ioctl() noexcept;

    /// Destructor
    ///
    virtual ~ioctl() = default;

    /// Open
    ///
    /// Open a connection to the bareflank driver.
    ///
    /// @throws driver_inaccessible_error thrown when the ioctl class is unable
    ///     to open a connection to the bareflank driver.
    ///
    virtual void open();

    /// Add Module
    ///
    /// Add a module to the driver entry.
    ///
    /// @param str ELF file to be added to the driver entry
    ///
    /// @throws invalid_argument_error thrown if data == nullptr, or len <= 0
    /// @throws ioctl_failed_error thrown if the ioctl failed. Note that this
    ///    could have been because bfm was unable to ioctl the driver, or it
    ///    could be because the driver entry reported a failure when executing
    ///    the ioctl.
    ///
    virtual void call_ioctl_add_module(const std::string &str);

    /// Load VMM
    ///
    /// Loads the VMM
    ///
    /// @throws ioctl_failed_error thrown if the ioctl failed. Note that this
    ///    could have been because bfm was unable to ioctl the driver, or it
    ///    could be because the driver entry reported a failure when executing
    ///    the ioctl.
    ///
    virtual void call_ioctl_load_vmm();

    /// Unload VMM
    ///
    /// Unloads the VMM
    ///
    /// @throws ioctl_failed_error thrown if the ioctl failed. Note that this
    ///    could have been because bfm was unable to ioctl the driver, or it
    ///    could be because the driver entry reported a failure when executing
    ///    the ioctl.
    ///
    virtual void call_ioctl_unload_vmm();

    /// Start VMM
    ///
    /// Starts the VMM
    ///
    /// @throws ioctl_failed_error thrown if the ioctl failed. Note that this
    ///    could have been because bfm was unable to ioctl the driver, or it
    ///    could be because the driver entry reported a failure when executing
    ///    the ioctl.
    ///
    virtual void call_ioctl_start_vmm();

    /// Stop VMM
    ///
    /// Stops the VMM
    ///
    /// @throws ioctl_failed_error thrown if the ioctl failed. Note that this
    ///    could have been because bfm was unable to ioctl the driver, or it
    ///    could be because the driver entry reported a failure when executing
    ///    the ioctl.
    ///
    virtual void call_ioctl_stop_vmm();

    /// Dump VMM
    ///
    /// Dumps the contents of the VMM's debug ring
    ///
    /// @param drr pointer a debug_ring_resources_t
    /// @param vcpuid indicates which drr to get (every vcpu has its own drr)
    ///
    /// @throws invalid_argument_error thrown if drr == nullptr
    /// @throws ioctl_failed_error thrown if the ioctl failed. Note that this
    ///    could have been because bfm was unable to ioctl the driver, or it
    ///    could be because the driver entry reported a failure when executing
    ///    the ioctl.
    ///
    virtual void call_ioctl_dump_vmm(debug_ring_resources_t *drr, uint64_t vcpuid);

    /// VMM Status
    ///
    /// Get the status of the VMM
    ///
    /// @param status pointer to provide the status to
    ///
    /// @throws invalid_argument_error thrown if status == nullptr
    /// @throws ioctl_failed_error thrown if the ioctl failed. Note that this
    ///    could have been because bfm was unable to ioctl the driver, or it
    ///    could be because the driver entry reported a failure when executing
    ///    the ioctl.
    ///
    virtual void call_ioctl_vmm_status(int64_t *status);

private:
    std::shared_ptr<ioctl_private_base> m_d;
};

#endif
