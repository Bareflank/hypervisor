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

#ifndef ENTRY_FACTORY_H
#define ENTRY_FACTORY_H

#include <vcpu/vcpu_factory.h>
#include <memory_manager/memory_manager.h>

class entry_factory
{
public:

    entry_factory() {}
    virtual ~entry_factory() {}

    virtual vcpu_factory *get_vcpu_factory()
    { return &m_vcpu_factory; }

    virtual memory_manager *get_memory_manager()
    { return &m_memory_manager; }

private:

    vcpu_factory m_vcpu_factory;
    memory_manager m_memory_manager;
};

entry_factory *ef();

#endif
