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

#include <memory_manager/memory_manager.h>

memory_manager &memory_manager::instance()
{
    static memory_manager self;
    return self;
}

memory_manager_error::type
memory_manager::init()
{
    auto blank_page = page();

    for (auto i = 0; i < MAX_PAGES; i++)
        m_pages[i] = blank_page;

    return memory_manager_error::success;
}

memory_manager_error::type
memory_manager::add_page(page &pg)
{
    auto index = -1;

    if (pg.is_valid() == false)
        return memory_manager_error::failure;

    for (auto i = 0; i < MAX_PAGES; i++)
    {
        if (m_pages[i] == page())
            index = i;

        if (m_pages[i] == pg)
            return memory_manager_error::already_added;
    }

    if (index < 0)
        return memory_manager_error::full;

    pg.free();
    m_pages[index] = pg;

    return memory_manager_error::success;
}

memory_manager_error::type
memory_manager::alloc_page(page *pg)
{
    if (pg == 0)
        return memory_manager_error::failure;

    for (auto i = 0; i < MAX_PAGES; i++)
    {
        if (m_pages[i].is_valid() == false)
            continue;

        if (m_pages[i].is_allocated() == true)
            continue;

        m_pages[i].allocate();
        *pg = m_pages[i];

        return memory_manager_error::success;
    }

    return memory_manager_error::out_of_memory;
}

void
memory_manager::free_page(page &pg)
{
    if (pg.is_valid() == false)
        return;

    for (auto i = 0; i < MAX_PAGES; i++)
    {
        if (m_pages[i] == pg)
        {
            pg.free();
            m_pages[i] = pg;

            return;
        }
    }
}
