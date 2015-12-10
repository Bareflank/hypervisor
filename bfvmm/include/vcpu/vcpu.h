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
    virtual ~vcpu();

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

private:

    int64_t m_id;
};

#endif
