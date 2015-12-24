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

#include <stdint.h>
#include <debug_ring/debug_ring.h>

// TODO: This vCPU is specific to Intel x64. At some point we should
//       abstract the vCPU such that it has a common interface, and then
//       subclass for each arch (i.e. Intel, AMD and ARM)
#include <vmm/vmm_intel_x64.h>
#include <vmcs/vmcs_intel_x64.h>
#include <intrinsics/intrinsics_intel_x64.h>

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

    /// Default vCPU Constructor
    ///
    /// Creates a vCPU with a negative, invalid ID and default
    /// resources. This vCPU should not be used.
    ///
    vcpu();

    /// Constructor
    ///
    /// Creates a vCPU with the provided id and default resources.
    /// This vCPU should not be used.
    ///
    vcpu(int64_t id);

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

    /// Init
    ///
    /// Initializes the vCPU.
    ///
    /// @return success on success, failure otherwise
    ///
    virtual vcpu_error::type init();

    /// Start
    ///
    /// Starts the vCPU.
    ///
    /// @return success on success, failure otherwise
    ///
    virtual vcpu_error::type start();

    /// Stop
    ///
    /// Stops the vCPU.
    ///
    /// @return success on success, failure otherwise
    ///
    virtual vcpu_error::type stop();

    /// Write to Log
    ///
    /// Writes to this specific vCPU's log. Note that this could be writing
    /// to more than one log, but is likely writing to the debug ring for this
    /// vCPU.
    ///
    /// @param str the string to write to the log
    /// @param len the length of the string
    ///
    virtual void write(const char *str, int64_t len);

private:

    int64_t m_id;

    vmm_intel_x64 m_vmm;
    vmcs_intel_x64 m_vmcs;
    intrinsics_intel_x64 m_intrinsics;

    debug_ring m_debug_ring;
};

#endif
