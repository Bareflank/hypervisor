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

#define RESERVED_VCPUIDS 0xC000000000000000

/// Virtual CPU
///
/// The vCPU represents a "core" for a virtual machine. There are different
/// types of virtual machines (the host VM and guest VM being good examples)
/// but in either case, a set of vCPUs must be provided.
///
/// For the host VM (also called the hardware domain), 1 vCPU must exist
/// for each physical core. These vCPUs are special. Their IDs are their
/// physical core #s as assigned by the host OS. This is because the "guest"
/// port of the ID is 0. The resources these vCPUs are given should match
/// the resources the host OS is using.
///
/// For a guest VM, there can be any number of vCPUs. The first half of the
/// ID is the guest ID, and the second half of the ID is a unique identifier.
/// Since a vCPU can be scheduled on any core, the ID does not correlate with
/// a physical core.
///
/// This generic vCPU class not only provides the base class that architecture
/// specific vCPUs will be created from, but it also provides some of the base
/// functionality that is common between all vCPUs. For example, all vCPUs
/// have an ID and a debug_ring.
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
    vcpu(uint64_t id);

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
    vcpu(uint64_t id, const std::shared_ptr<debug_ring> &dr);

    /// Destructor
    ///
    virtual ~vcpu();

    /// vCPU Id
    ///
    /// Returns the ID of the vCPU. This ID can be anything, but is only
    /// valid if it is between 0 <= id < MAX_CPUS
    ///
    /// @return the VPU's id
    ///
    virtual uint64_t id() const
    { return m_id; }

    /// Run
    ///
    /// Executes the vCPU.
    ///
    virtual void run()
    { m_is_running = true; }

    /// Halt
    ///
    /// Halts the vCPU.
    ///
    virtual void hlt()
    { m_is_running = false; }

    /// Write to Log
    ///
    /// Writes to this specific vCPU's log. Note that this could be writing
    /// to more than one log, but is likely writing to the debug ring for this
    /// vCPU.
    ///
    /// @param str the string to write to the log
    ///
    virtual void write(const std::string &str) noexcept;

private:

    uint64_t m_id;
    std::shared_ptr<debug_ring> m_debug_ring;

    bool m_is_running;
};

#endif
