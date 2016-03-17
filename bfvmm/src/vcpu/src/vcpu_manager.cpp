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

#include <exception.h>
#include <vcpu/vcpu_manager.h>

vcpu_manager *
vcpu_manager::instance()
{
    static vcpu_manager self;
    return &self;
}

void
vcpu_manager::init(int64_t vcpuid)
{
    if (vcpuid < 0 || vcpuid >= MAX_VCPUS)
        throw invalid_argument(vcpuid, "out of range");

    m_vcpus[vcpuid] = m_factory.make_vcpu(vcpuid);
}

void
vcpu_manager::start(int64_t vcpuid)
{
    if (vcpuid < 0 || vcpuid >= MAX_VCPUS)
        throw invalid_argument(vcpuid, "out of range");

    const auto &vc = m_vcpus[vcpuid];

    if (!vc)
        throw invalid_argument(vcpuid, "vcpu has not yet been created");

    vc->start();
}

void
vcpu_manager::dispatch(int64_t vcpuid)
{
    if (vcpuid < 0 || vcpuid >= MAX_VCPUS)
        throw invalid_argument(vcpuid, "out of range");

    const auto &vc = m_vcpus[vcpuid];

    if (!vc)
        throw invalid_argument(vcpuid, "vcpu has not yet been created");

    vc->dispatch();
}

void
vcpu_manager::stop(int64_t vcpuid)
{
    if (vcpuid < 0 || vcpuid >= MAX_VCPUS)
        throw invalid_argument(vcpuid, "out of range");

    const auto &vc = m_vcpus[vcpuid];

    if (!vc)
        throw invalid_argument(vcpuid, "vcpu has not yet been created");

    vc->stop();
}

void
vcpu_manager::halt(int64_t vcpuid)
{
    if (vcpuid < 0 || vcpuid >= MAX_VCPUS)
        throw invalid_argument(vcpuid, "out of range");

    const auto &vc = m_vcpus[vcpuid];

    if (!vc)
        throw invalid_argument(vcpuid, "vcpu has not yet been created");

    vc->halt();
}

void
vcpu_manager::promote(int64_t vcpuid)
{
    if (vcpuid < 0 || vcpuid >= MAX_VCPUS)
        throw invalid_argument(vcpuid, "out of range");

    const auto &vc = m_vcpus[vcpuid];

    if (!vc)
        throw invalid_argument(vcpuid, "vcpu has not yet been created");

    vc->promote();
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
