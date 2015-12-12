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

#include <iostream>
#include <entry/entry_factory.h>

#ifndef INIT_IOSTREAM
#define INIT_IOSTREAM()
#endif

entry_factory_error::type
entry_factory::init_vmm(int64_t vcpuid)
{
    INIT_IOSTREAM();

    if (m_serial_port.open() != serial::success)
        return entry_factory_error::failure;

    if (m_vcpu_factory.init(vcpuid) != vcpu_factory_error::success)
        return entry_factory_error::failure;

    return entry_factory_error::success;
}

entry_factory_error::type
entry_factory::start_vmm(int64_t vcpuid)
{
    if (m_vcpu_factory.start(vcpuid) != vcpu_factory_error::success)
        return entry_factory_error::failure;

    return entry_factory_error::success;
}

entry_factory_error::type
entry_factory::stop_vmm(int64_t vcpuid)
{
    if (m_vcpu_factory.stop(vcpuid) != vcpu_factory_error::success)
        return entry_factory_error::failure;

    return entry_factory_error::success;
}

void
entry_factory::write(const char *str, int64_t len)
{
    m_serial_port.write(str, len);
    m_vcpu_factory.write(str, len);
}

entry_factory *ef()
{
    static entry_factory ef;
    return &ef;
}
