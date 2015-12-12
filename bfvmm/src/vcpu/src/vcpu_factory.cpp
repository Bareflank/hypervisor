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

#include <vcpu/vcpu_factory.h>

vcpu *
vcpu_factory::get_vcpu(int64_t vcpuid)
{
    if (vcpuid >= MAX_VCPUS)
        return 0;

    return &m_vcpus[vcpuid];
}

vcpu_factory_error::type
vcpu_factory::add_vcpu(const vcpu &vc)
{
    if (vc.id() >= MAX_VCPUS)
        return vcpu_factory_error::failure;

    m_vcpus[vc.id()] = vc;

    return vcpu_factory_error::success;
}

vcpu_factory_error::type
vcpu_factory::init(int64_t vcpuid)
{
    if (vcpuid >= MAX_VCPUS)
        return vcpu_factory_error::invalid;

    if (add_vcpu(vcpu(vcpuid)) != vcpu_factory_error::success)
        return vcpu_factory_error::failure;

    if (m_vcpus[vcpuid].init() != vcpu_error::success)
        return vcpu_factory_error::failure;

    return vcpu_factory_error::success;
}

vcpu_factory_error::type
vcpu_factory::start(int64_t vcpuid)
{
    if (vcpuid >= MAX_VCPUS)
        return vcpu_factory_error::invalid;

    if (m_vcpus[vcpuid].start() != vcpu_error::success)
        return vcpu_factory_error::failure;

    return vcpu_factory_error::success;
}

vcpu_factory_error::type
vcpu_factory::stop(int64_t vcpuid)
{
    if (vcpuid >= MAX_VCPUS)
        return vcpu_factory_error::invalid;

    if (m_vcpus[vcpuid].stop() != vcpu_error::success)
        return vcpu_factory_error::failure;

    return vcpu_factory_error::success;
}

void
vcpu_factory::write(const char *str, int64_t len)
{
    for (auto i = 0; i < MAX_VCPUS; i++)
        m_vcpus[i].write(str, len);
}
