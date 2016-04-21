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

#ifndef VCPU_H
#define VCPU_H

#include <string>
#include <memory>
#include <debug_ring/debug_ring.h>

/// Virtual CPU
///
/// The Virtual CPU represents a "CPU" to the hypervisor. Each core in a
/// multi-core system has a vCPU associated with it. Each guest VM must also
/// have a vCPU for each physical CPU on the system, which means that the
/// total number of vCPUs being managed by the vcpu_manager is
///
/// @code
/// #cores + (#cores * #guests)
/// @endcode
///
/// This generic vCPU class not only provides the base class that architecture
/// specific vCPUs will be created from, but it also provides some of the base
/// functionality that is common between all vCPUs. For example, all vCPUs
/// have an "id" and a debug_ring.
///
/// Note that these should not be created directly, but instead should be
/// created by the vcpu_manager, which uses the vcpu_factory to actually
/// create a vcpu.
///
class vcpu
{
public:

    /// Constructor
    ///
    /// Creates a vCPU with the provided id and default resources.
    ///
    /// @param id the id of the vcpu
    /// @throws invalid_argument_error if the id is invalid
    ///
    vcpu(int64_t id);

    /// Override Constructor
    ///
    /// Creates a vCPU with the provided id and debug ring. This constructor
    /// provides a means to override and repalce the internal resources of the
    /// vCPU. Note that if one of the resources is set to NULL, a default
    /// will be constructed in it's place, providing a means to select which
    /// internal components to override.
    ///
    /// @param id the id of the vcpu
    /// @param dr the debug ring the vcpu should use. If you provide nullptr,
    ///     a default debug ring will be created.
    /// @throws invalid_argument_error if the id is invalid
    ///
    vcpu(int64_t id, const std::shared_ptr<debug_ring> &dr);

    /// Destructor
    ///
    virtual ~vcpu() {}

    /// vCPU Id
    ///
    /// Returns the ID of the vCPU. This ID can be anything, but is only
    /// valid if it is between 0 <= id < MAX_CPUS
    ///
    /// @return the VPU's id
    ///
    virtual int64_t id() const
    { return m_id; }

    /// Start
    ///
    /// Starts the vCPU.
    ///
    virtual void start()
    { }

    /// Dispatch
    ///
    /// Dispatches the exit handler for the vCPU.
    ///
    virtual void dispatch()
    { }

    /// Stop
    ///
    /// Stops the vCPU.
    ///
    virtual void stop()
    { }

    /// Halt
    ///
    /// Halts the vCPU.
    ///
    virtual void halt()
    { }

    /// Promote
    ///
    /// Promote the vCPU to host CPU state
    ///
    virtual void promote()
    { }

    /// Write to Log
    ///
    /// Writes to this specific vCPU's log. Note that this could be writing
    /// to more than one log, but is likely writing to the debug ring for this
    /// vCPU.
    ///
    /// @param str the string to write to the log
    ///
    virtual void write(const std::string &str)
    { m_debug_ring->write(str); }

private:

    int64_t m_id;
    std::shared_ptr<debug_ring> m_debug_ring;
};

#endif
