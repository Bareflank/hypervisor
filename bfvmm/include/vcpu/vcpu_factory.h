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

#ifndef VCPU_FACTORY_H
#define VCPU_FACTORY_H

#include <vcpu/vcpu.h>

#include <stdint.h>
#include <constants.h>

namespace vcpu_factory_error
{
    enum type
    {
        success = 0,
        failure = 1,
        invalid = 2
    };
}

class vcpu_factory
{
public:

    /// Default Constructor
    ///
    vcpu_factory() {}

    /// Destructor
    ///
    virtual ~vcpu_factory() {}

    /// Get vCPU
    ///
    /// Gets a vcpu from the vcpu factory. If the vcpuid that is provided
    /// is invalid, this function will return NULL. Otherwise, it will
    /// return a pointer to the vcpu.
    ///
    /// @param vcpuid the vcpu's id
    /// @return NULL if the vcpuid is invalid or a valid pointer to a vcpu
    ///
    virtual vcpu *get_vcpu(int64_t vcpuid);

    /// Add vCPU
    ///
    /// Adds a vcpu to the vCPU factory.
    ///
    /// @param vc the vcpu to add
    /// @return success on success, failure otherwise
    ///
    virtual vcpu_factory_error::type add_vcpu(const vcpu &vc);

    /// vCPU Factory Init vCPU
    ///
    /// Initializes the vCPU.
    ///
    /// @param vcpuid the vcpu to initialize
    /// @return success on success, falure otherwise
    ///
    virtual vcpu_factory_error::type init(int64_t vcpuid);

    /// vCPU Factory Start vCPU
    ///
    /// Starts the vCPU.
    ///
    /// @param vcpuid the vcpu to start
    /// @return success on success, falure otherwise
    ///
    virtual vcpu_factory_error::type start(int64_t vcpuid);

    /// vCPU Factory Stop vCPU
    ///
    /// Stops the vCPU.
    ///
    /// @param vcpuid the vcpu to stop
    /// @return success on success, falure otherwise
    ///
    virtual vcpu_factory_error::type stop(int64_t vcpuid);

    /// Write to Log
    ///
    /// Writes a string of size length to the log. Note that the log
    /// could be to multiple sources but is likely writing to a debug ring
    ///
    /// @param str the string to write to the log
    /// @param len the length of the string
    ///
    virtual void write(const char *str, int64_t len);

private:

    vcpu m_vcpus[MAX_VCPUS];
};

#endif
