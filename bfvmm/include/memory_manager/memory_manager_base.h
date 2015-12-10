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

#ifndef MEMORY_MANAGER_BASE_H
#define MEMORY_MANAGER_BASE_H

#include <memory_manager/page.h>

namespace memory_manager_error
{
    enum type
    {
        success = 0,
        failure = 1,
        out_of_memory = 2,
        full = 3,
        already_added = 4
    };
};

class memory_manager_base
{
public:

    memory_manager_base() {}
    virtual ~memory_manager_base() {}

    virtual memory_manager_error::type init()
    { return memory_manager_error::failure; }

    virtual memory_manager_error::type add_page(page &pg)
    { return memory_manager_error::failure; }

    virtual memory_manager_error::type alloc_page(page *pg)
    { return memory_manager_error::failure; }

    virtual void free_page(page &pg)
    {  }
};

#endif
