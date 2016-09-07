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
#include <constants.h>
#include <memory_manager/mem_pool.h>
#include <memory_manager/memory_manager.h>

#include <vector>
#include <gsl/gsl>

extern "C" int64_t
add_md(struct memory_descriptor *md) noexcept;

void
memory_manager_ut::test_memory_manager_free_zero()
{
    mem_pool<128, 3> pool(100);

    pool.free(0);
    pool.free(0xFFFFFFFFFFFFFFFF);
}

void
memory_manager_ut::test_memory_manager_free_heap_twice()
{
    mem_pool<128, 3> pool(100);

    auto addr1 = pool.alloc(1 << 3);

    pool.free(addr1);
    pool.free(addr1);
}

void
memory_manager_ut::test_memory_manager_malloc_zero()
{
    mem_pool<128, 3> pool(100);

    EXPECT_EXCEPTION(pool.alloc(0), std::bad_alloc);
}

void
memory_manager_ut::test_memory_manager_multiple_malloc_heap_should_be_contiguous()
{
    mem_pool<128, 3> pool(100);

    uintptr_t addr1 = 0;
    uintptr_t addr2 = 0;
    uintptr_t addr3 = 0;
    uintptr_t addr4 = 0;

    addr1 = pool.alloc((1 << 3));
    addr2 = pool.alloc((1 << 3));
    addr3 = pool.alloc((1 << 3));
    addr4 = pool.alloc((1 << 3));

    this->expect_true(addr1 == 100 + ((1 << 3) * 0));  // 100
    this->expect_true(addr2 == 100 + ((1 << 3) * 1));  // 108
    this->expect_true(addr3 == 100 + ((1 << 3) * 2));  // 116
    this->expect_true(addr4 == 100 + ((1 << 3) * 3));  // 124

    pool.free(addr1);
    pool.free(addr2);
    pool.free(addr3);
    pool.free(addr4);

    addr1 = pool.alloc((1 << 3) + 2);
    addr2 = pool.alloc((1 << 3) + 2);
    addr3 = pool.alloc((1 << 3) + 2);
    addr4 = pool.alloc((1 << 3) * 4);

    this->expect_true(addr1 == 132 + ((1 << 3) * 0));  // 132
    this->expect_true(addr2 == 132 + ((1 << 3) * 2));  // 148
    this->expect_true(addr3 == 132 + ((1 << 3) * 4));  // 164
    this->expect_true(addr4 == 132 + ((1 << 3) * 6));  // 180

    pool.free(addr1);
    pool.free(addr2);
    pool.free(addr3);
    pool.free(addr4);
}

void
memory_manager_ut::test_memory_manager_malloc_heap_all_of_memory()
{
    mem_pool<128, 3> pool(100);
    std::vector<uintptr_t> addrs;

    for (auto i = 0; i < 16; i++)
        addrs.push_back(pool.alloc(1 << 3));

    EXPECT_EXCEPTION(pool.alloc(1 << 3), std::bad_alloc);

    for (const auto &addr : addrs)
        pool.free(addr);

    for (auto i = 0; i < 16; i++)
        addrs.push_back(pool.alloc(1 << 3));

    EXPECT_EXCEPTION(pool.alloc(1 << 3), std::bad_alloc);

    for (const auto &addr : addrs)
        pool.free(addr);
}

void
memory_manager_ut::test_memory_manager_malloc_heap_all_of_memory_one_block()
{
    mem_pool<128, 3> pool(100);
    this->expect_true(pool.alloc(128) == 100);
}

void
memory_manager_ut::test_memory_manager_malloc_heap_all_memory_fragmented()
{
    mem_pool<128, 3> pool(100);
    std::vector<uintptr_t> addrs;

    for (auto i = 0; i < 16; i++)
        addrs.push_back(pool.alloc(1 << 3));

    for (const auto &addr : addrs)
        pool.free(addr);

    this->expect_true(pool.alloc(128) == 100);
}

void
memory_manager_ut::test_memory_manager_malloc_heap_too_much_memory_one_block()
{
    mem_pool<128, 3> pool(100);
    EXPECT_EXCEPTION(pool.alloc(136), std::bad_alloc);
}

void
memory_manager_ut::test_memory_manager_malloc_heap_too_much_memory_non_block_size()
{
    mem_pool<128, 3> pool(100);
    EXPECT_EXCEPTION(pool.alloc(129), std::bad_alloc);
}

void
memory_manager_ut::test_memory_manager_malloc_heap_massive()
{
    mem_pool<128, 3> pool(100);

    EXPECT_EXCEPTION(pool.alloc(0xFFFFFFFFFFFFFFFF), std::bad_alloc);
}

void
memory_manager_ut::test_memory_manager_size_out_of_bounds()
{
    mem_pool<128, 3> pool(100);

    this->expect_true(pool.size(0) == 0);
    this->expect_true(g_mm->size(nullptr) == 0);
}

void
memory_manager_ut::test_memory_manager_size_unallocated()
{
    mem_pool<128, 3> pool(100);

    this->expect_true(pool.size(100) == 0);
}

void
memory_manager_ut::test_memory_manager_size()
{
    mem_pool<128, 3> pool(100);

    pool.alloc(8);
    this->expect_true(pool.size(100) == 8);
}

void
memory_manager_ut::test_memory_manager_contains_out_of_bounds()
{
    mem_pool<128, 3> pool(100);

    this->expect_false(pool.contains(0));
    this->expect_false(pool.contains(99));
    this->expect_false(pool.contains(228));
    this->expect_false(pool.contains(500));
}

void
memory_manager_ut::test_memory_manager_contains()
{
    mem_pool<128, 3> pool(100);

    this->expect_true(pool.contains(100));
    this->expect_true(pool.contains(227));
}

void
memory_manager_ut::test_memory_manager_malloc_out_of_memory()
{
    this->expect_true(g_mm->alloc(0xFFFFFFFFFFFFFF00) == nullptr);
}

void
memory_manager_ut::test_memory_manager_malloc_heap()
{
    auto ptr = g_mm->alloc(MAX_CACHE_LINE_SIZE);

    this->expect_true(ptr != nullptr);
    this->expect_true(g_mm->size(ptr) == MAX_CACHE_LINE_SIZE);

    g_mm->free(ptr);
}

void
memory_manager_ut::test_memory_manager_malloc_page()
{
    auto ptr = g_mm->alloc(MAX_PAGE_SIZE);

    this->expect_true(ptr != nullptr);
    this->expect_true(g_mm->size(ptr) == MAX_PAGE_SIZE);

    g_mm->free(ptr);
}

void
memory_manager_ut::test_memory_manager_add_md_no_exceptions()
{
    this->expect_true(add_md(nullptr) == MEMORY_MANAGER_FAILURE);
}

void
memory_manager_ut::test_memory_manager_add_md_invalid_md()
{
    EXPECT_EXCEPTION(g_mm->add_md(nullptr), std::invalid_argument);
}

void
memory_manager_ut::test_memory_manager_add_md_invalid_virt()
{
    memory_descriptor md = {0, 0x54321000, 7};

    EXPECT_EXCEPTION(g_mm->add_md(&md), std::invalid_argument);
}

void
memory_manager_ut::test_memory_manager_add_md_invalid_phys()
{
    memory_descriptor md = {0x12345123, 0, 7};

    EXPECT_EXCEPTION(g_mm->add_md(&md), std::invalid_argument);
}

void
memory_manager_ut::test_memory_manager_add_md_invalid_type()
{
    memory_descriptor md = {0x12345000, 0x54321000, 0};

    EXPECT_EXCEPTION(g_mm->add_md(&md), std::invalid_argument);
}

void
memory_manager_ut::test_memory_manager_add_md_unaligned_physical()
{
    memory_descriptor md = {0x12345123, 0x54321000, 7};

    EXPECT_EXCEPTION(g_mm->add_md(&md), std::logic_error);
}

void
memory_manager_ut::test_memory_manager_add_md_unaligned_virtual()
{
    memory_descriptor md = {0x12345000, 0x54321123, 7};

    EXPECT_EXCEPTION(g_mm->add_md(&md), std::logic_error);
}

void
memory_manager_ut::test_memory_manager_virtint_to_physint_unknown()
{
    this->expect_true(g_mm->virtint_to_physint(0x54321000) == 0);
}

void
memory_manager_ut::test_memory_manager_physint_to_virtint_unknown()
{
    this->expect_true(g_mm->physint_to_virtint(0x12346000) == 0);
}

void
memory_manager_ut::test_memory_manager_virtint_to_physint_random_address()
{
    memory_descriptor md = {0x12345000, 0x54321000, 7};

    EXPECT_NO_EXCEPTION(g_mm->add_md(&md));
    this->expect_true(g_mm->virtint_to_physint(0x54321ABC) == 0x12345ABC);
}

void
memory_manager_ut::test_memory_manager_virtint_to_physint_nullptr()
{
    this->expect_true(g_mm->virtint_to_physint(0) == 0);
    this->expect_true(g_mm->virtptr_to_physint(nullptr) == 0);
    this->expect_true(g_mm->virtint_to_physptr(0) == nullptr);
    this->expect_true(g_mm->virtptr_to_physptr(nullptr) == nullptr);
}

void
memory_manager_ut::test_memory_manager_virtint_to_physint_upper_limit()
{
    memory_descriptor md = {0x12345000, 0x54321000, 7};

    EXPECT_NO_EXCEPTION(g_mm->add_md(&md));
    this->expect_true(g_mm->virtint_to_physint(0x54321FFF) == 0x12345FFF);
}

void
memory_manager_ut::test_memory_manager_virtint_to_physint_lower_limit()
{
    memory_descriptor md = {0x12345000, 0x54321000, 7};

    EXPECT_NO_EXCEPTION(g_mm->add_md(&md));
    this->expect_true(g_mm->virtint_to_physint(0x54321000) == 0x12345000);
}

void
memory_manager_ut::test_memory_manager_virt_to_phys_map()
{
    memory_descriptor md = {0x12345000, 0x54321000, 7};

    EXPECT_NO_EXCEPTION(g_mm->add_md(&md));

    for (const auto &iter : g_mm->virt_to_phys_map())
    {
        this->expect_true(iter.first == (0x54321000 >> 12));
        this->expect_true(iter.second.phys == md.phys);
        this->expect_true(iter.second.virt == md.virt);
        this->expect_true(iter.second.type == md.type);
    }
}

void
memory_manager_ut::test_memory_manager_physint_to_virtint_random_address()
{
    memory_descriptor md = {0x12345000, 0x54321000, 7};

    EXPECT_NO_EXCEPTION(g_mm->add_md(&md));
    this->expect_true(g_mm->physint_to_virtint(0x12345ABC) == 0x54321ABC);
}

void
memory_manager_ut::test_memory_manager_physint_to_virtint_nullptr()
{
    this->expect_true(g_mm->physint_to_virtint(0) == 0);
    this->expect_true(g_mm->physptr_to_virtint(nullptr) == 0);
    this->expect_true(g_mm->physint_to_virtptr(0) == nullptr);
    this->expect_true(g_mm->physptr_to_virtptr(nullptr) == nullptr);
}

void
memory_manager_ut::test_memory_manager_physint_to_virtint_upper_limit()
{
    memory_descriptor md = {0x12345000, 0x54321000, 7};

    EXPECT_NO_EXCEPTION(g_mm->add_md(&md));
    this->expect_true(g_mm->physint_to_virtint(0x12345FFF) == 0x54321FFF);
}

void
memory_manager_ut::test_memory_manager_physint_to_virtint_lower_limit()
{
    memory_descriptor md = {0x12345000, 0x54321000, 7};

    EXPECT_NO_EXCEPTION(g_mm->add_md(&md));
    this->expect_true(g_mm->physint_to_virtint(0x12345000) == 0x54321000);
}

void
memory_manager_ut::test_memory_manager_phys_to_virt_map()
{
    memory_descriptor md = {0x12345000, 0x54321000, 7};

    EXPECT_NO_EXCEPTION(g_mm->add_md(&md));

    for (const auto &iter : g_mm->phys_to_virt_map())
    {
        this->expect_true(iter.first == (0x12345000 >> 12));
        this->expect_true(iter.second.phys == md.phys);
        this->expect_true(iter.second.virt == md.virt);
        this->expect_true(iter.second.type == md.type);
    }
}
