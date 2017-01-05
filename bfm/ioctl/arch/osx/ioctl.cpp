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

#include <ioctl.h>
#include <ioctl_private.h>

ioctl::ioctl() noexcept
{
    m_d = std::make_shared<ioctl_private>();
}

void
ioctl::open()
{
    auto d = std::dynamic_pointer_cast<ioctl_private>(m_d);

    if (d)
        d->open();
}

void
ioctl::call_ioctl_add_module(const std::string &str)
{
    auto d = std::dynamic_pointer_cast<ioctl_private>(m_d);

    if (d)
    {
        d->call_ioctl_add_module_length(str.length());
        d->call_ioctl_add_module(str.c_str());
    }
}

void
ioctl::call_ioctl_load_vmm()
{
    auto d = std::dynamic_pointer_cast<ioctl_private>(m_d);

    if (d)
        d->call_ioctl_load_vmm();
}

void
ioctl::call_ioctl_unload_vmm()
{
    auto d = std::dynamic_pointer_cast<ioctl_private>(m_d);

    if (d)
        d->call_ioctl_unload_vmm();
}

void
ioctl::call_ioctl_start_vmm()
{
    auto d = std::dynamic_pointer_cast<ioctl_private>(m_d);

    if (d)
        d->call_ioctl_start_vmm();
}

void
ioctl::call_ioctl_stop_vmm()
{
    auto d = std::dynamic_pointer_cast<ioctl_private>(m_d);

    if (d)
        d->call_ioctl_stop_vmm();
}

void
ioctl::call_ioctl_dump_vmm(debug_ring_resources_t *drr)
{
    auto d = std::dynamic_pointer_cast<ioctl_private>(m_d);

    if (d)
        d->call_ioctl_dump_vmm(drr);
}

void
ioctl::call_ioctl_vmm_status(int64_t *status)
{
    auto d = std::dynamic_pointer_cast<ioctl_private>(m_d);

    if (d)
        d->call_ioctl_vmm_status(status);
}
