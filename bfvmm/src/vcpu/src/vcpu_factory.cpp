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
    // TODO: On the Intel archiecture at least, we need to find a way to map
    // the x2APIC CPU addressing scheme to a set of VCPU numbers, similar to
    // how the major operatings systems do this... and in a way that does not
    // require a hash lookup. At the moment it appears that there can be
    // gaps in what cpuid reports. For example, you could end up with an ID
    // of 1, 2, 7, 8.

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
