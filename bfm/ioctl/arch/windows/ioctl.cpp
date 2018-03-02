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

ioctl::ioctl() :
    m_d {std::make_unique<ioctl_private>()}
{ }

void
ioctl::open()
{
    if (auto d = dynamic_cast<ioctl_private *>(m_d.get()))
        d->open();
}

void
ioctl::call_ioctl_add_module(const binary_data &module_data)
{
    if (auto d = dynamic_cast<ioctl_private *>(m_d.get()))
        d->call_ioctl_add_module(module_data.data(), module_data.size());
}

void
ioctl::call_ioctl_load_vmm()
{
    if (auto d = dynamic_cast<ioctl_private *>(m_d.get()))
        d->call_ioctl_load_vmm();
}

void
ioctl::call_ioctl_unload_vmm()
{
    if (auto d = dynamic_cast<ioctl_private *>(m_d.get()))
        d->call_ioctl_unload_vmm();
}

void
ioctl::call_ioctl_start_vmm()
{
    if (auto d = dynamic_cast<ioctl_private *>(m_d.get()))
        d->call_ioctl_start_vmm();
}

void
ioctl::call_ioctl_stop_vmm()
{
    if (auto d = dynamic_cast<ioctl_private *>(m_d.get()))
        d->call_ioctl_stop_vmm();
}

void
ioctl::call_ioctl_dump_vmm(gsl::not_null<drr_pointer> drr, vcpuid_type vcpuid)
{
    if (auto d = dynamic_cast<ioctl_private *>(m_d.get()))
        d->call_ioctl_dump_vmm(drr, vcpuid);
}

void
ioctl::call_ioctl_vmm_status(gsl::not_null<status_pointer> status)
{
    if (auto d = dynamic_cast<ioctl_private *>(m_d.get()))
        d->call_ioctl_vmm_status(status);
}

void
ioctl::call_ioctl_vmcall(gsl::not_null<registers_pointer> regs, cpuid_type cpuid)
{
    if (auto d = dynamic_cast<ioctl_private *>(m_d.get()))
        d->call_ioctl_vmcall(regs, cpuid);
}
