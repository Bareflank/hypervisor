//
// Bareflank Hypervisor
// Copyright (C) 2015 Assured Information Security, Inc.
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

#include <catch/catch.hpp>

#include <test/support.h>
#include <memory_manager/memory_manager.h>

TEST_CASE("alloc null")
{
    CHECK(g_mm->alloc(0) == nullptr);
    CHECK(g_mm->alloc_map(0) == nullptr);
}

TEST_CASE("alloc not enough memory")
{
    CHECK(g_mm->alloc(0xFFFFFFFFFFFFFFFF) == nullptr);
    CHECK(g_mm->alloc_map(0xFFFFFFFFFFFFFFFF) == nullptr);
}

TEST_CASE("alloc heap and size")
{
    auto buf01 = g_mm->alloc(0x010);
    auto buf02 = g_mm->alloc(0x020);
    auto buf03 = g_mm->alloc(0x030);
    auto buf04 = g_mm->alloc(0x040);
    auto buf05 = g_mm->alloc(0x080);
    auto buf06 = g_mm->alloc(0x100);
    auto buf07 = g_mm->alloc(0x200);
    auto buf08 = g_mm->alloc(0x400);
    auto buf09 = g_mm->alloc(0x800);
    auto buf10 = g_mm->alloc(0x900);
    auto buf11 = g_mm->alloc(BAREFLANK_PAGE_SIZE);
    auto buf12 = g_mm->alloc(0x10000);

    CHECK(g_mm->size(buf01) == 0x010);
    CHECK(g_mm->size(buf02) == 0x020);
    CHECK(g_mm->size(buf03) == 0x030);
    CHECK(g_mm->size(buf04) == 0x040);
    CHECK(g_mm->size(buf05) == 0x080);
    CHECK(g_mm->size(buf06) == 0x100);
    CHECK(g_mm->size(buf07) == 0x200);
    CHECK(g_mm->size(buf08) == 0x400);
    CHECK(g_mm->size(buf09) == 0x800);
    CHECK(g_mm->size(buf10) == BAREFLANK_PAGE_SIZE);
    CHECK(g_mm->size(buf11) == BAREFLANK_PAGE_SIZE);
    CHECK(g_mm->size(buf12) == 0x10000);

    g_mm->free(buf01);
    g_mm->free(buf02);
    g_mm->free(buf03);
    g_mm->free(buf04);
    g_mm->free(buf05);
    g_mm->free(buf06);
    g_mm->free(buf07);
    g_mm->free(buf08);
    g_mm->free(buf09);
    g_mm->free(buf10);
    g_mm->free(buf11);
    g_mm->free(buf12);
}

TEST_CASE("alloc page and size")
{
    auto buf01 = g_mm->alloc_page();
    CHECK(g_mm->size_page(buf01) == BAREFLANK_PAGE_SIZE);
    g_mm->free_page(buf01);
}

TEST_CASE("alloc map and size")
{
    auto buf01 = g_mm->alloc_map(BAREFLANK_PAGE_SIZE);
    CHECK(g_mm->size_map(buf01) == BAREFLANK_PAGE_SIZE);
    g_mm->free_map(buf01);
}

TEST_CASE("size unallocated")
{
    int i{};

    CHECK(g_mm->size(&i) == 0);
    CHECK(g_mm->size_map(&i) == 0);
    CHECK(g_mm->size_page(&i) == 0);
}

TEST_CASE("free unallocated")
{
    int i{};

    CHECK_NOTHROW(g_mm->free(&i));
    CHECK_NOTHROW(g_mm->free_map(&i));
    CHECK_NOTHROW(g_mm->free_page(&i));
}

TEST_CASE("add_md unaligned physical")
{
    CHECK_THROWS(g_mm->add_md(0x12345000, 0x54321123, 0));
}

TEST_CASE("add_md unaligned virtual")
{
    CHECK_THROWS(g_mm->add_md(0x12345123, 0x54321000, 0));
}

TEST_CASE("add_md already added virtual")
{
    CHECK_NOTHROW(g_mm->add_md(0x12345000, 0x54321000, 0));
    CHECK_THROWS(g_mm->add_md(0x12345000, 0x65432000, 0));
    CHECK_NOTHROW(g_mm->remove_md(0x12345000, 0x54321000));
}

TEST_CASE("add_md already added physical")
{
    CHECK_NOTHROW(g_mm->add_md(0x12345000, 0x54321000, 0));
    CHECK_THROWS(g_mm->add_md(0x65432000, 0x54321000, 0));
    CHECK_NOTHROW(g_mm->remove_md(0x12345000, 0x54321000));
}

TEST_CASE("add_md success")
{
    CHECK_NOTHROW(g_mm->add_md(0x12345000, 0x54321000, 0));
    CHECK_NOTHROW(g_mm->remove_md(0x12345000, 0x54321000));
}

TEST_CASE("remove_md unaligned physical")
{
    CHECK_THROWS(g_mm->remove_md(0x12345000, 0x54321123));
}

TEST_CASE("remove_md unaligned virtual")
{
    CHECK_THROWS(g_mm->remove_md(0x12345123, 0x54321000));
}

TEST_CASE("remove_md without add")
{
    CHECK_NOTHROW(g_mm->remove_md(0x12345000, 0x54321000));
}

TEST_CASE("virtint to physint failure")
{
    CHECK_THROWS(g_mm->virtint_to_physint(0x12345000));

    CHECK_THROWS(g_mm->virtint_to_physint(0));
    CHECK_THROWS(g_mm->virtint_to_physptr(0));
    CHECK_THROWS(g_mm->virtptr_to_physint(nullptr));
    CHECK_THROWS(g_mm->virtptr_to_physptr(nullptr));
}

TEST_CASE("physint to virtint failure")
{
    CHECK_THROWS(g_mm->physint_to_virtint(0x54321000));

    CHECK_THROWS(g_mm->physint_to_virtint(0));
    CHECK_THROWS(g_mm->physint_to_virtptr(0));
    CHECK_THROWS(g_mm->physptr_to_virtint(nullptr));
    CHECK_THROWS(g_mm->physptr_to_virtptr(nullptr));
}

TEST_CASE("virtint_to_physint success")
{
    g_mm->add_md(0x12345000, 0x54321000, 0);

    CHECK(g_mm->virtint_to_physint(0x12345ABC) == 0x54321ABC);
    CHECK(g_mm->virtint_to_physint(0x12345FFF) == 0x54321FFF);
    CHECK(g_mm->virtint_to_physint(0x12345000) == 0x54321000);

    g_mm->remove_md(0x12345000, 0x54321000);
}

TEST_CASE("physint_to_virtint success")
{
    g_mm->add_md(0x12345000, 0x54321000, 0);

    CHECK(g_mm->physint_to_virtint(0x54321ABC) == 0x12345ABC);
    CHECK(g_mm->physint_to_virtint(0x54321FFF) == 0x12345FFF);
    CHECK(g_mm->physint_to_virtint(0x54321000) == 0x12345000);

    g_mm->remove_md(0x12345000, 0x54321000);
}
