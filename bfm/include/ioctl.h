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

#include <bfgsl.h>
#include <bffile.h>
#include <bfvmcallinterface.h>
#include <bfdebugringinterface.h>

// -----------------------------------------------------------------------------
// Exports
// -----------------------------------------------------------------------------

#include <bfexports.h>

#ifndef STATIC_BFM_IOCTL
#ifdef SHARED_BFM_IOCTL
#define EXPORT_BFM_IOCTL EXPORT_SYM
#else
#define EXPORT_BFM_IOCTL IMPORT_SYM
#endif
#else
#define EXPORT_BFM_IOCTL
#endif

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

/// IOCTL Private Base
///
/// Only needed for dynamic cast
///
class EXPORT_BFM_IOCTL ioctl_private_base
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
class EXPORT_BFM_IOCTL ioctl
{
public:

    using binary_data = file::binary_data;
    using drr_type = debug_ring_resources_t;
    using drr_pointer = drr_type *;
    using vcpuid_type = uint64_t;
    using status_type = int64_t;
    using status_pointer = status_type *;
    using registers_type = struct vmcall_registers_t;
    using registers_pointer = registers_type *;

    /// Default Constructor
    ///
    /// @expects none
    /// @ensures none
    ///
    ioctl();

    /// Destructor
    ///
    /// @expects none
    /// @ensures none
    ///
    virtual ~ioctl() = default;

    /// Open
    ///
    /// Open a connection to the bareflank driver.
    ///
    /// @expects none
    /// @ensures none
    ///
    virtual void open();

    /// Add Module
    ///
    /// Add a module to the driver entry.
    ///
    /// @param module_data ELF file to be added to the driver entry
    ///
    /// @expects none
    /// @ensures none
    ///
    virtual void call_ioctl_add_module(const binary_data &module_data);

    /// Load VMM
    ///
    /// Loads the VMM
    ///
    /// @expects none
    /// @ensures none
    ///
    virtual void call_ioctl_load_vmm();

    /// Unload VMM
    ///
    /// Unloads the VMM
    ///
    /// @expects none
    /// @ensures none
    ///
    virtual void call_ioctl_unload_vmm();

    /// Start VMM
    ///
    /// Starts the VMM
    ///
    /// @expects none
    /// @ensures none
    ///
    virtual void call_ioctl_start_vmm();

    /// Stop VMM
    ///
    /// Stops the VMM
    ///
    /// @expects none
    /// @ensures none
    ///
    virtual void call_ioctl_stop_vmm();

    /// Dump VMM
    ///
    /// Dumps the contents of the VMM's debug ring
    ///
    /// @expects drr != null;
    /// @ensures none
    ///
    /// @param drr pointer a debug_ring_resources_t
    /// @param vcpuid indicates which drr to get (every vcpu has its own drr)
    ///
    virtual void call_ioctl_dump_vmm(gsl::not_null<drr_pointer> drr, vcpuid_type vcpuid);

    /// VMM Status
    ///
    /// Get the status of the VMM
    ///
    /// @expects status != nullptr
    /// @ensures none
    ///
    /// @param status pointer to status variable to store the results
    ///
    virtual void call_ioctl_vmm_status(gsl::not_null<status_pointer> status);

private:

    std::unique_ptr<ioctl_private_base> m_d;
};

#endif
