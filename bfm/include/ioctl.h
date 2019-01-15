//
// Copyright (C) 2019 Assured Information Security, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#ifndef IOCTL_H
#define IOCTL_H

#include <memory>

#include <bfgsl.h>
#include <bffile.h>
#include <bfdebugringinterface.h>

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4251)
#endif

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

/// IOCTL Private Base
///
/// Only needed for dynamic cast
///
class ioctl_private_base
{
public:

    /// Default Constructor
    ///
    ioctl_private_base() = default;

    /// Default Destructor
    ///
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

    using binary_data = file::binary_data;          ///< Binary data type
    using drr_type = debug_ring_resources_t;        ///< Debug ring resources type
    using drr_pointer = drr_type *;                 ///< Debug ring resources pointer type
    using vcpuid_type = uint64_t;                   ///< VCPUID type
    using status_type = int64_t;                    ///< Status type
    using status_pointer = status_type *;           ///< Status pointer type

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

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#endif
