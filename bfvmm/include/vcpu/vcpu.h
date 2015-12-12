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

// TODO: This VCPU is specific to Intel x64. At some point we should
//       abstract the VCPU such that it has a common interface, and then
//       subclass for each arch (i.e. Intel, AMD and ARM)

#include <stdint.h>

#include <vmm/vmm_intel_x64.h>
#include <vmcs/vmcs_intel_x64.h>
#include <debug_ring/debug_ring.h>
#include <intrinsics/intrinsics_intel_x64.h>

class vcpu
{
public:

    /// Default VCPU Constructor
    ///
    /// Creates a VCPU with a negative, invalid ID and default
    /// resources. This VCPU should not be used.
    ///
    vcpu();

    /// Constructor
    ///
    /// Creates a VCPU with the provided id and default resources.
    /// This VCPU should not be used.
    ///
    vcpu(int64_t id);

    /// Destructor
    ///
    virtual ~vcpu() {}

    /// Is Valid
    ///
    /// @return true if the VCPU is valid, false otherwise
    ///
    virtual bool is_valid() const;

    /// VCPU Id
    ///
    /// Returns the ID of the VCPU. This ID can be anything, but is only
    /// valid if it is between 0 <= id < MAX_CPUS
    ///
    /// @return the VPU's id
    ///
    virtual int64_t id() const;

    /// Get VMM
    ///
    /// @return vmm (will never be NULL)
    ///
    virtual vmm *get_vmm()
    { return &m_vmm; }

    /// Get VMCS
    ///
    /// TODO: Once we support multiple guests, this will have to be a
    /// std::list<vmcs> object as we will have to store more than one of
    /// these. We will also need some for of "guest" object that can store
    /// all of the vmcs object for that single guest as a vcpu will only
    /// work on one vmcs per guest so the "parent" object that is actually
    /// storing the vmcs should be the guest object itself
    ///
    /// @return vmcs (will never be NULL)
    ///
    virtual vmcs *get_vmcs()
    { return &m_vmcs; }


    /// Get Debug Ring
    ///
    /// @return debug ring (will never be NULL)
    ///
    virtual debug_ring *get_debug_ring()
    { return &m_debug_ring; }

    /// Get Intrinsics
    ///
    /// @return intrinsics (will never be NULL)
    ///
    virtual intrinsics_intel_x64 *get_intrinsics()
    { return &m_intrinsics; }

private:

    int64_t m_id;

    vmm_intel_x64 m_vmm;
    vmcs_intel_x64 m_vmcs;
    debug_ring m_debug_ring;
    intrinsics_intel_x64 m_intrinsics;
};

#endif
