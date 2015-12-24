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
#include <constants.h>

#include <vcpu/vcpu.h>
#include <memory_manager/memory_manager.h>

vcpu::vcpu() :
    m_id(-1)
{
}

vcpu::vcpu(int64_t id) :
    m_id(id)
{
}

bool
vcpu::is_valid() const
{
    return m_id >= 0 && m_id < MAX_VCPUS;
}

int64_t
vcpu::id() const
{
    return m_id;
}

vcpu_error::type
vcpu::init()
{
    if (is_valid() == false)
        return vcpu_error::invalid;

    if (m_debug_ring.init(m_id) != debug_ring_error::success)
        return vcpu_error::failure;

    if (m_vmm.init(&m_intrinsics, mm()) != vmm_error::success)
        return vcpu_error::failure;

    if (m_vmcs.init(&m_intrinsics, mm()) != vmcs_error::success)
        return vcpu_error::failure;

    return vcpu_error::success;
}

vcpu_error::type
vcpu::start()
{
    if (m_vmm.start() != vmm_error::success)
        return vcpu_error::failure;

    if (m_vmcs.launch() != vmcs_error::success)
        return vcpu_error::failure;

    return vcpu_error::success;
}

vcpu_error::type
vcpu::stop()
{
    if (m_vmm.stop() != vmm_error::success)
        return vcpu_error::failure;

    return vcpu_error::success;
}

void
vcpu::write(const char *str, int64_t len)
{
    m_debug_ring.write(str, len);
}
