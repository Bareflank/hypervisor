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

#include <debug.h>
#include <exception.h>

#include <vcpu/vcpu.h>

vcpu::vcpu(int64_t id) :
    m_id(id)
{
    if (id < 0 || id >= MAX_VCPUS)
        throw invalid_argument(id, "out of range");

    m_debug_ring = std::make_shared<debug_ring>(id);
}

vcpu::vcpu(int64_t id, const std::shared_ptr<debug_ring> &dr) :
    m_id(id),
    m_debug_ring(dr)
{
    if (id < 0 || id >= MAX_VCPUS)
        throw invalid_argument(id, "out of range");

    if (!dr)
        m_debug_ring = std::make_shared<debug_ring>(id);
}
