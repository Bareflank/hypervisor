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

#ifndef ENTRY_FACTORY_H
#define ENTRY_FACTORY_H

#include <vcpu/vcpu_factory.h>
#include <serial/serial_port_x86.h>

namespace entry_factory_error
{
    enum type
    {
        success = 0,
        failure = 1
    };
}

class entry_factory
{
public:

    /// Entry Factory Default Constructor
    ///
    entry_factory() {}

    /// Entry Factory Default Destructor
    ///
    virtual ~entry_factory() {}

    /// Entry Factory Init VMM
    ///
    /// Initializes the VMM.
    ///
    /// @param vcpuid the vcpu to initialize the vmm on
    /// @return success on success, falure otherwise
    ///
    virtual entry_factory_error::type init_vmm(int64_t vcpuid);

    /// Entry Factory Start VMM
    ///
    /// Starts the VMM.
    ///
    /// @param vcpuid the vcpu to start the vmm on
    /// @return success on success, falure otherwise
    ///
    virtual entry_factory_error::type start_vmm(int64_t vcpuid);

    /// Entry Factory Stop VMM
    ///
    /// Stops the VMM.
    ///
    /// @param vcpuid the vcpu to stop the vmm on
    /// @return success on success, falure otherwise
    ///
    virtual entry_factory_error::type stop_vmm(int64_t vcpuid);

    /// Write to Log
    ///
    /// Writes a string of size length to the log. Note that the log
    /// could be to multiple sources including a debug ring and serial
    ///
    /// @param str the string to write to the log
    /// @param len the length of the string
    ///
    virtual void write(const char *str, int64_t len);

private:

    vcpu_factory m_vcpu_factory;
    serial_port_x86 m_serial_port;
};

entry_factory *ef();

#endif
