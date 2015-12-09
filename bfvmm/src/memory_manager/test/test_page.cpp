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

#include <memory_manager/page.h>

void
memory_manager_ut::test_page_constructor_blank_page()
{
    page pg;

    EXPECT_TRUE(pg.is_valid() == false);
}

void
memory_manager_ut::test_page_constructor_invalid_phys()
{
    page pg(0, this, 10);

    EXPECT_TRUE(pg.is_valid() == false);
}

void
memory_manager_ut::test_page_constructor_invalid_virt()
{
    page pg(this, 0, 10);

    EXPECT_TRUE(pg.is_valid() == false);
}

void
memory_manager_ut::test_page_constructor_invalid_size()
{
    page pg(this, this, 0);

    EXPECT_TRUE(pg.is_valid() == false);
}

void
memory_manager_ut::test_page_constructor_valid_page()
{
    page pg(this, this, 10);

    EXPECT_TRUE(pg.is_valid() == true);
}

void
memory_manager_ut::test_page_allocated()
{
    page pg(this, this, 10);

    EXPECT_TRUE(pg.is_allocated() == false);

    pg.allocate();

    EXPECT_TRUE(pg.is_allocated() == true);

    pg.free();

    EXPECT_TRUE(pg.is_allocated() == false);
}

void
memory_manager_ut::test_page_allocated_multiple_times()
{
    page pg(this, this, 10);

    EXPECT_TRUE(pg.is_allocated() == false);

    pg.allocate();
    pg.allocate();

    EXPECT_TRUE(pg.is_allocated() == true);

    pg.free();
    pg.free();

    EXPECT_TRUE(pg.is_allocated() == false);
}

void
memory_manager_ut::test_page_phys()
{
    page pg(this, this, 10);

    EXPECT_TRUE(pg.phys_addr() == this);
}

void
memory_manager_ut::test_page_virt()
{
    page pg(this, this, 10);

    EXPECT_TRUE(pg.virt_addr() == this);
}

void
memory_manager_ut::test_page_size()
{
    page pg(this, this, 10);

    EXPECT_TRUE(pg.size() == 10);
}

void
memory_manager_ut::test_page_copy_constructor_copy_blank()
{
    page pg1;
    page pg2(pg1);

    EXPECT_TRUE(pg2.is_valid() == false);
}

void
memory_manager_ut::test_page_copy_constructor_copy_valid()
{
    page pg1(this, this, 10);
    page pg2(pg1);

    EXPECT_TRUE(pg2.phys_addr() == this);
    EXPECT_TRUE(pg2.virt_addr() == this);
    EXPECT_TRUE(pg2.size() == 10);
}

void
memory_manager_ut::test_page_equal_operator_copy_blank()
{
    page pg1;
    page pg2;

    pg2 = pg1;

    EXPECT_TRUE(pg2.is_valid() == false);
}

void
memory_manager_ut::test_page_equal_operator_copy_valid()
{
    page pg1(this, this, 10);
    page pg2;

    pg2 = pg1;

    EXPECT_TRUE(pg2.phys_addr() == this);
    EXPECT_TRUE(pg2.virt_addr() == this);
    EXPECT_TRUE(pg2.size() == 10);
}

void
memory_manager_ut::test_page_blank_equal_blank()
{
    page pg1;
    page pg2;

    EXPECT_TRUE(pg1 == pg2);
    EXPECT_FALSE(pg1 != pg2);
}

void
memory_manager_ut::test_page_blank_equal_valid()
{
    page pg1(this, this, 10);
    page pg2;

    EXPECT_FALSE(pg1 == pg2);
    EXPECT_TRUE(pg1 != pg2);
}

void
memory_manager_ut::test_page_valid_equal_valid_different_phys()
{
    page pg1(this, this, 10);
    page pg2(&pg1, this, 10);

    EXPECT_FALSE(pg1 == pg2);
    EXPECT_TRUE(pg1 != pg2);
}

void
memory_manager_ut::test_page_valid_equal_valid_different_virt()
{
    page pg1(this, this, 10);
    page pg2(this, &pg1, 10);

    EXPECT_FALSE(pg1 == pg2);
    EXPECT_TRUE(pg1 != pg2);
}

void
memory_manager_ut::test_page_valid_equal_valid_different_size()
{
    page pg1(this, this, 10);
    page pg2(this, this, 20);

    EXPECT_FALSE(pg1 == pg2);
    EXPECT_TRUE(pg1 != pg2);
}

void
memory_manager_ut::test_page_valid_equal_valid_same()
{
    page pg1(this, this, 10);
    page pg2(this, this, 10);

    EXPECT_TRUE(pg1 == pg2);
    EXPECT_FALSE(pg1 != pg2);
}
