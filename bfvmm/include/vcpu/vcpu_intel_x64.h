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

#ifndef VCPU_INTEL_X64_H
#define VCPU_INTEL_X64_H

#include <vcpu/vcpu.h>

#include <vmxon/vmxon_intel_x64.h>
#include <vmcs/vmcs_intel_x64.h>
#include <exit_handler/exit_handler_intel_x64.h>
#include <intrinsics/intrinsics_intel_x64.h>

class vcpu_intel_x64 : public vcpu
{
public:

    /// Constructor
    ///
    /// Creates a vCPU with the provided id and default resources.
    ///
    vcpu_intel_x64(int64_t id);

    /// Override Constructor
    ///
    /// Creates a vCPU with the provided resources. This constructor
    /// provides a means to override and repalce the internal resources of the
    /// vCPU. Note that if one of the resources is set to NULL, a default
    /// will be constructed in it's place, providing a means to select which
    /// internal components to override.
    ///
    vcpu_intel_x64(int64_t id,
                   debug_ring *debug_ring,
                   vmxon_intel_x64 *vmxon,
                   vmcs_intel_x64 *vmcs,
                   exit_handler_intel_x64 *exit_handler,
                   intrinsics_intel_x64 *intrinsics);

    /// Destructor
    ///
    virtual ~vcpu_intel_x64() {}

    /// Start
    ///
    /// Starts the vCPU.
    ///
    /// @return success on success, failure otherwise
    ///
    virtual vcpu_error::type start() override;

    /// Dispatch
    ///
    /// Dispatches the exit handler for the vCPU.
    ///
    /// @return success on success, failure otherwise
    ///
    virtual vcpu_error::type dispatch() override;

    /// Stop
    ///
    /// Stops the vCPU.
    ///
    /// @return success on success, failure otherwise
    ///
    virtual vcpu_error::type stop() override;

    /// Halt
    ///
    /// Halts the vCPU.
    ///
    /// @return success on success, failure otherwise
    ///
    virtual vcpu_error::type halt() override;

    /// promote
    ///
    /// promote the vCPU to host CPU state
    ///
    /// @return never returns on success, failure otherwise
    ///
    virtual vcpu_error::type promote() override;

private:
    vmxon_intel_x64 *m_vmxon;
    vmcs_intel_x64 *m_vmcs;
    exit_handler_intel_x64 *m_exit_handler;
    intrinsics_intel_x64 *m_intrinsics;
};

#endif
