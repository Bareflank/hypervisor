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

#include <test.h>

#include <memory_manager/memory_manager.h>

void
memory_manager_ut::test_memory_manager_init()
{
    EXPECT_TRUE(memory_manager::instance()->init() == memory_manager_error::success);
}

void
memory_manager_ut::test_memory_manager_add_invalid_page()
{
    page pg;
    memory_manager::instance()->init();

    EXPECT_TRUE(memory_manager::instance()->add_page(pg) == memory_manager_error::failure);
}

void
memory_manager_ut::test_memory_manager_add_valid_page()
{
    page pg(this, this, 10);
    memory_manager::instance()->init();

    EXPECT_TRUE(memory_manager::instance()->add_page(pg) == memory_manager_error::success);
}

void
memory_manager_ut::test_memory_manager_add_same_page()
{
    page pg(this, this, 10);
    memory_manager::instance()->init();
    memory_manager::instance()->add_page(pg);

    EXPECT_TRUE(memory_manager::instance()->add_page(pg) == memory_manager_error::already_added);
}

void
memory_manager_ut::test_memory_manager_add_too_many_pages()
{
    page pg(this, this, MAX_PAGES + 1);
    memory_manager::instance()->init();

    for (auto i = 0; i < MAX_PAGES; i++)
    {
        page pg(this, this, i + 1);
        memory_manager::instance()->add_page(pg);
    }

    EXPECT_TRUE(memory_manager::instance()->add_page(pg) == memory_manager_error::full);
}

void
memory_manager_ut::test_memory_manager_alloc_page_null_arg()
{
    EXPECT_TRUE(memory_manager::instance()->alloc_page(0) == memory_manager_error::failure);
}

void
memory_manager_ut::test_memory_manager_alloc_page_too_many_pages()
{
    page pg(this, this, MAX_PAGES);
    memory_manager::instance()->init();
    memory_manager::instance()->add_page(pg);
    memory_manager::instance()->alloc_page(&pg);

    EXPECT_TRUE(memory_manager::instance()->alloc_page(&pg) == memory_manager_error::out_of_memory);
}

void
memory_manager_ut::test_memory_manager_alloc_page()
{
    page pg(this, this, MAX_PAGES);
    memory_manager::instance()->init();
    memory_manager::instance()->add_page(pg);

    EXPECT_TRUE(pg.is_allocated() == false);
    EXPECT_TRUE(memory_manager::instance()->alloc_page(&pg) == memory_manager_error::success);
    EXPECT_TRUE(pg.is_allocated() == true);
}

void
memory_manager_ut::test_memory_manager_free_allocated_page()
{
    page pg(this, this, MAX_PAGES);
    memory_manager::instance()->init();
    memory_manager::instance()->add_page(pg);
    memory_manager::instance()->alloc_page(&pg);

    EXPECT_TRUE(pg.is_allocated() == true);
    memory_manager::instance()->free_page(pg);
    EXPECT_TRUE(pg.is_allocated() == false);
}
