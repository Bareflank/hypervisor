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
#include <stdint.h>
#include <debug_ring/debug_ring.h>

namespace vcpu_error
{
    enum type
    {
        success = 0,
        failure = 1,
        invalid = 2
    };
}

class vcpu
{
public:

    /// Constructor
    ///
    /// Creates a vCPU with the provided id and default resources.
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
    vcpu(int64_t id, debug_ring *m_debug_ring);

    /// Destructor
    ///
    virtual ~vcpu() {}

    /// Is Valid
    ///
    /// @return true if the vCPU is valid, false otherwise
    ///
    virtual bool is_valid() const;

    /// vCPU Id
    ///
    /// Returns the ID of the vCPU. This ID can be anything, but is only
    /// valid if it is between 0 <= id < MAX_CPUS
    ///
    /// @return the VPU's id
    ///
    virtual int64_t id() const;

    /// Start
    ///
    /// Starts the vCPU.
    ///
    /// @return success on success, failure otherwise
    ///
    virtual vcpu_error::type start();

    /// Dispatch
    ///
    /// Dispatches the exit handler for the vCPU.
    ///
    /// @return success on success, failure otherwise
    ///
    virtual vcpu_error::type dispatch();

    /// Stop
    ///
    /// Stops the vCPU.
    ///
    /// @return success on success, failure otherwise
    ///
    virtual vcpu_error::type stop();

    /// promote
    ///
    /// promote the vCPU to host CPU state
    ///
    /// @return never returns on success, failure otherwise
    ///
    virtual vcpu_error::type promote() { return vcpu_error::success; }


    /// Request teardown
    ///
    /// Call into the hypervisor to promote  the vCPU
    ///  guest state to the host. Following this, the
    /// hypervisor can be shut down from the promoted guest.
    ///
    /// @return success on success, failure otherwise
    ///
    virtual vcpu_error::type request_teardown();

    /// Write to Log
    ///
    /// Writes to this specific vCPU's log. Note that this could be writing
    /// to more than one log, but is likely writing to the debug ring for this
    /// vCPU.
    ///
    /// @param str the string to write to the log
    ///
    virtual void write(std::string &str);

private:

    int64_t m_id;
    debug_ring *m_debug_ring;
};

#endif
