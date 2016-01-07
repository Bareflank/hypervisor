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
    if (vcpuid >= MAX_VCPUS)
        return vcpu_manager_error::invalid;

    if (m_vcpus[vcpuid] != 0)
        delete m_vcpus[vcpuid];

    m_vcpus[vcpuid] = m_factory.make_vcpu(vcpuid);

    return vcpu_manager_error::success;
}

vcpu_manager_error::type
vcpu_manager::start(int64_t vcpuid)
{
    if (vcpuid >= MAX_VCPUS)
        return vcpu_manager_error::invalid;

    if (m_vcpus[vcpuid] == 0)
        return vcpu_manager_error::invalid;

    if (m_vcpus[vcpuid]->start() != vcpu_error::success)
        return vcpu_manager_error::failure;

    return vcpu_manager_error::success;
}

vcpu_manager_error::type
vcpu_manager::stop(int64_t vcpuid)
{
    if (vcpuid >= MAX_VCPUS)
        return vcpu_manager_error::invalid;

    if (m_vcpus[vcpuid] == 0)
        return vcpu_manager_error::invalid;

    if (m_vcpus[vcpuid]->stop() != vcpu_error::success)
        return vcpu_manager_error::failure;

    return vcpu_manager_error::success;
}

void
vcpu_manager::write(int64_t vcpuid, const char *str, int64_t len)
{
    if (vcpuid < 0 || vcpuid >= MAX_VCPUS || m_vcpus[vcpuid] == 0)
    {
        for (auto i = 0; i < MAX_VCPUS; i++)
        {
            if (m_vcpus[i] != 0)
                m_vcpus[i]->write(str, len);
        }
    }
    else
    {
        m_vcpus[vcpuid]->write(str, len);
    }
}

vcpu_manager::vcpu_manager() :
    m_vcpus{0}
{
}
