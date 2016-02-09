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

#include <stddef.h>
#include <vcpu/vcpu_manager.h>

vcpu_manager *
vcpu_manager::instance()
{
    static vcpu_manager self;
    return &self;
}

vcpu_manager_error::type
vcpu_manager::init(int64_t vcpuid)
{
    if (vcpuid < 0 || vcpuid >= MAX_VCPUS)
        return vcpu_manager_error::invalid;

    m_vcpus[vcpuid] = m_factory.make_vcpu(vcpuid);

    return vcpu_manager_error::success;
}

vcpu_manager_error::type
vcpu_manager::start(int64_t vcpuid)
{
    if (vcpuid < 0 || vcpuid >= MAX_VCPUS)
        return vcpu_manager_error::invalid;

    const auto &vc = m_vcpus[vcpuid];

    if (!vc)
        return vcpu_manager_error::invalid;

    if (vc->start() != vcpu_error::success)
        return vcpu_manager_error::failure;

    return vcpu_manager_error::success;
}

vcpu_manager_error::type
vcpu_manager::stop(int64_t vcpuid)
{
    if (vcpuid < 0 || vcpuid >= MAX_VCPUS)
        return vcpu_manager_error::invalid;

    const auto &vc = m_vcpus[vcpuid];

    if (!vc)
        return vcpu_manager_error::invalid;

    if (vc->stop() != vcpu_error::success)
        return vcpu_manager_error::failure;

    return vcpu_manager_error::success;
}

void
vcpu_manager::write(int64_t vcpuid, std::string &str)
{
    const auto &vc = m_vcpus[vcpuid];

    if (!vc)
    {
        for (const auto &kv : m_vcpus)
        {
            if (kv.second)
                kv.second->write(str);
        }
    }
    else
    {
        vc->write(str);
    }
}

vcpu_manager::vcpu_manager()
{
}

#include <serial/serial_port_x86.h>

serial_port_x86 *
internal_serial()
{
    static serial_port_x86 serial;
    return &serial;
}

extern "C" int
write(int file, const void *buffer, size_t count)
{
    std::string str((char *)buffer, count);

    internal_serial()->write(str);

    if (file == 0)
        vcpu_manager::instance()->write(-1, str);
    else
        vcpu_manager::instance()->write(file - 1000, str);

    return count;
}
