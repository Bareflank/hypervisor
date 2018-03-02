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
#include <vcpu/vcpu.h>

vcpu::vcpu(vcpuid::type id, std::unique_ptr<debug_ring> dr) :
    m_id(id),
    m_debug_ring(std::move(dr)),
    m_is_running(false),
    m_is_initialized(false)
{
    if ((id & vcpuid::reserved) != 0)
        throw std::invalid_argument("invalid vcpuid");

    if (!m_debug_ring)
        m_debug_ring = std::make_unique<debug_ring>(id);
}

void
vcpu::init(user_data *data)
{
    (void) data;

    m_is_initialized = true;
}

void
vcpu::fini(user_data *data)
{
    (void) data;

    if (m_is_running)
        this->hlt();

    m_is_initialized = false;
}

void
vcpu::run(user_data *data)
{
    (void) data;

    m_is_running = true;
}

void
vcpu::hlt(user_data *data)
{
    (void) data;

    m_is_running = false;
}

void
vcpu::write(const std::string &str) noexcept
{ m_debug_ring->write(str); }
