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
#include <memory_manager/memory_manager.h>

#include <vector>
#include <gsl/gsl>

extern "C" int64_t
add_md(struct memory_descriptor *md) noexcept;

void
memory_manager_ut::test_memory_manager_malloc_zero()
{
    EXPECT_TRUE(g_mm->malloc(0) == nullptr);
}

void
memory_manager_ut::test_memory_manager_free_zero()
{
    g_mm->free(nullptr);
}

void
memory_manager_ut::test_memory_manager_malloc_heap_valid()
{
    EXPECT_TRUE(g_mm->malloc(sizeof(uint64_t)) != nullptr);

    g_mm->clear();
}

void
memory_manager_ut::test_memory_manager_multiple_malloc_heap_should_be_contiguous()
{
    auto addr1 = static_cast<uint64_t *>(g_mm->malloc(sizeof(uint64_t)));
    auto addr2 = static_cast<uint64_t *>(g_mm->malloc(sizeof(uint64_t)));
    auto addr3 = static_cast<uint64_t *>(g_mm->malloc(sizeof(uint64_t)));
    auto addr4 = static_cast<uint64_t *>(g_mm->malloc(sizeof(uint64_t)));

    EXPECT_TRUE(addr2 == addr1 + 2);
    EXPECT_TRUE(addr3 == addr2 + 2);
    EXPECT_TRUE(addr4 == addr3 + 2);

    g_mm->clear();

    auto addr5 = static_cast<uint64_t *>(g_mm->malloc(10));
    auto addr6 = static_cast<uint64_t *>(g_mm->malloc(10));
    auto addr7 = static_cast<uint64_t *>(g_mm->malloc(10));
    auto addr8 = static_cast<uint64_t *>(g_mm->malloc(10));

    EXPECT_TRUE(addr6 == addr5 + 3);
    EXPECT_TRUE(addr7 == addr6 + 3);
    EXPECT_TRUE(addr8 == addr7 + 3);

    g_mm->clear();
}

void
memory_manager_ut::test_memory_manager_malloc_heap_free_malloc()
{
    void *addr1 = nullptr;
    void *addr2 = nullptr;

    g_mm->malloc(sizeof(uint64_t));
    addr1 = g_mm->malloc(sizeof(uint64_t));
    g_mm->free(addr1);
    addr2 = g_mm->malloc(sizeof(uint64_t));

    EXPECT_TRUE(addr2 == addr1);
    g_mm->clear();

    g_mm->malloc(sizeof(uint64_t));
    addr1 = g_mm->malloc(sizeof(uint64_t));
    g_mm->malloc(sizeof(uint64_t));
    g_mm->free(addr1);
    addr2 = g_mm->malloc(sizeof(uint64_t));

    EXPECT_TRUE(addr2 == addr1);
    g_mm->clear();

    g_mm->malloc(sizeof(uint64_t));
    addr1 = g_mm->malloc(sizeof(uint64_t));
    g_mm->free(addr1);
    addr2 = g_mm->malloc(10);

    EXPECT_TRUE(addr1 == addr2);
    g_mm->clear();

    g_mm->malloc(sizeof(uint64_t));
    addr1 = g_mm->malloc(sizeof(uint64_t));
    g_mm->malloc(sizeof(uint64_t));
    g_mm->free(addr1);
    addr2 = g_mm->malloc(10);

    EXPECT_TRUE(addr1 != addr2);
    g_mm->clear();

    g_mm->malloc(sizeof(uint64_t));
    addr1 = g_mm->malloc(10);
    g_mm->free(addr1);
    addr2 = g_mm->malloc(sizeof(uint64_t));

    EXPECT_TRUE(addr1 == addr2);
    g_mm->clear();

    g_mm->malloc(sizeof(uint64_t));
    addr1 = g_mm->malloc(10);
    g_mm->malloc(sizeof(uint64_t));
    g_mm->free(addr1);
    addr2 = g_mm->malloc(sizeof(uint64_t));

    EXPECT_TRUE(addr1 == addr2);
    g_mm->clear();
}

void
memory_manager_ut::test_memory_manager_free_heap_twice()
{
    auto addr1 = g_mm->malloc(sizeof(uint64_t));

    g_mm->free(addr1);
    g_mm->free(addr1);

    g_mm->clear();
}

void
memory_manager_ut::test_memory_manager_malloc_heap_all_of_memory()
{
    std::vector<void *> addrs;

    for (auto i = 0U; i < MAX_HEAP_POOL / 2 - 1; i++)
        addrs.push_back(g_mm->malloc(sizeof(uint64_t)));

    auto fill_mem_pool = g_mm->malloc(sizeof(uint64_t));
    auto mem_pool_full = g_mm->malloc(sizeof(uint64_t));

    EXPECT_TRUE(fill_mem_pool != nullptr);
    EXPECT_TRUE(mem_pool_full == nullptr);

    g_mm->free(fill_mem_pool);
    g_mm->free(mem_pool_full);

    for (const auto &addr : addrs)
        g_mm->free(addr);

    for (auto i = 0U; i < MAX_HEAP_POOL / 2 - 1; i++)
        addrs[i] = g_mm->malloc(sizeof(uint64_t));

    fill_mem_pool = g_mm->malloc(sizeof(uint64_t));
    mem_pool_full = g_mm->malloc(sizeof(uint64_t));

    EXPECT_TRUE(fill_mem_pool != nullptr);
    EXPECT_TRUE(mem_pool_full == nullptr);

    g_mm->clear();
}

void
memory_manager_ut::test_memory_manager_malloc_heap_all_of_memory_one_block()
{
    EXPECT_TRUE(g_mm->malloc((MAX_HEAP_POOL - 1) * sizeof(uint64_t)) != nullptr);
    g_mm->clear();
}

void
memory_manager_ut::test_memory_manager_malloc_heap_all_memory_fragmented()
{
    std::vector<void *> addrs;

    for (auto i = 0U; i < MAX_HEAP_POOL / 2; i++)
        addrs.push_back(g_mm->malloc(sizeof(uint64_t)));

    for (const auto &addr : addrs)
        g_mm->free(addr);

    EXPECT_TRUE(g_mm->malloc((MAX_HEAP_POOL - 1) * sizeof(uint64_t)) != nullptr);

    g_mm->clear();
}

void
memory_manager_ut::test_memory_manager_malloc_heap_too_much_memory_one_block()
{
    EXPECT_TRUE(g_mm->malloc((MAX_HEAP_POOL) * sizeof(uint64_t)) == nullptr);
    g_mm->clear();
}

void
memory_manager_ut::test_memory_manager_malloc_heap_too_much_memory_non_block_size()
{
    g_mm->malloc((MAX_HEAP_POOL - 2) * sizeof(uint64_t));
    EXPECT_TRUE(g_mm->malloc(100) == nullptr);

    g_mm->clear();
}

void
memory_manager_ut::test_memory_manager_malloc_heap_really_small_fragment()
{
    g_mm->malloc(sizeof(uint64_t));
    auto addr1 = g_mm->malloc(sizeof(uint64_t));
    auto addr2 = g_mm->malloc(sizeof(uint64_t));
    g_mm->malloc(sizeof(uint64_t));
    auto addr3 = g_mm->malloc(sizeof(uint64_t));
    g_mm->free(addr1);
    g_mm->free(addr2);
    g_mm->free(addr3);
    auto addr4 = g_mm->malloc(10);
    auto addr5 = g_mm->malloc(sizeof(uint64_t));

    EXPECT_TRUE(addr4 == addr1);
    EXPECT_TRUE(addr5 == addr3);
    g_mm->clear();
}

void
memory_manager_ut::test_memory_manager_malloc_heap_sparse_fragments()
{
    void *addr1 = nullptr;
    void *addr2 = nullptr;
    void *addr3 = nullptr;
    void *addr4 = nullptr;

    g_mm->malloc(sizeof(uint64_t));
    addr1 = g_mm->malloc(sizeof(uint64_t));
    g_mm->malloc(sizeof(uint64_t));
    addr2 = g_mm->malloc(sizeof(uint64_t));
    g_mm->malloc(sizeof(uint64_t));
    g_mm->free(addr1);
    g_mm->free(addr2);
    addr3 = g_mm->malloc(sizeof(uint64_t));
    addr4 = g_mm->malloc(sizeof(uint64_t));

    EXPECT_TRUE(addr3 == addr1);
    EXPECT_TRUE(addr4 == addr2);
    g_mm->clear();

    g_mm->malloc(sizeof(uint64_t));
    addr1 = g_mm->malloc(10);
    g_mm->malloc(sizeof(uint64_t));
    addr2 = g_mm->malloc(sizeof(uint64_t));
    g_mm->malloc(sizeof(uint64_t));
    g_mm->free(addr1);
    g_mm->free(addr2);
    addr3 = g_mm->malloc(10);
    addr4 = g_mm->malloc(sizeof(uint64_t));

    EXPECT_TRUE(addr3 == addr1);
    EXPECT_TRUE(addr4 == addr2);
    g_mm->clear();

    g_mm->malloc(sizeof(uint64_t));
    addr1 = g_mm->malloc(10);
    g_mm->malloc(sizeof(uint64_t));
    addr2 = g_mm->malloc(sizeof(uint64_t));
    g_mm->malloc(sizeof(uint64_t));
    g_mm->free(addr1);
    g_mm->free(addr2);
    addr3 = g_mm->malloc(sizeof(uint64_t));
    addr4 = g_mm->malloc(10);

    EXPECT_TRUE(addr3 == addr1);
    EXPECT_TRUE(addr4 != addr1);
    g_mm->clear();

    g_mm->malloc(sizeof(uint64_t));
    addr1 = g_mm->malloc(sizeof(uint64_t));
    g_mm->malloc(sizeof(uint64_t));
    addr2 = g_mm->malloc(10);
    g_mm->malloc(sizeof(uint64_t));
    g_mm->free(addr1);
    g_mm->free(addr2);
    addr3 = g_mm->malloc(10);
    addr4 = g_mm->malloc(sizeof(uint64_t));

    EXPECT_TRUE(addr3 == addr2);
    EXPECT_TRUE(addr4 == addr1);
    g_mm->clear();

    g_mm->malloc(sizeof(uint64_t));
    addr1 = g_mm->malloc(sizeof(uint64_t));
    g_mm->malloc(sizeof(uint64_t));
    addr2 = g_mm->malloc(10);
    g_mm->malloc(sizeof(uint64_t));
    g_mm->free(addr1);
    g_mm->free(addr2);
    addr3 = g_mm->malloc(sizeof(uint64_t));
    addr4 = g_mm->malloc(10);

    EXPECT_TRUE(addr3 == addr1);
    EXPECT_TRUE(addr4 == addr2);
    g_mm->clear();
}

void
memory_manager_ut::test_memory_manager_malloc_heap_massive()
{
    EXPECT_TRUE(g_mm->malloc(0xFFFFFFFFFFFFFFFF) == nullptr);
    EXPECT_TRUE(g_mm->malloc((MAX_HEAP_POOL + 10U) * 8) == nullptr);
    EXPECT_TRUE(g_mm->malloc((MAX_PAGE_POOL + MAX_PAGE_SIZE) * 4096) == nullptr);
    g_mm->clear();
}

void
memory_manager_ut::test_memory_manager_malloc_heap_resize_fragments()
{
    void *addr1 = nullptr;
    void *addr2 = nullptr;
    void *addr3 = nullptr;
    void *addr4 = nullptr;
    void *addr5 = nullptr;
    void *addr6 = nullptr;

    g_mm->malloc(sizeof(uint64_t));
    addr1 = g_mm->malloc(8);
    addr2 = g_mm->malloc(24);
    g_mm->free(addr1);
    g_mm->free(addr2);
    addr3 = g_mm->malloc(16);
    addr4 = g_mm->malloc(16);
    g_mm->malloc(sizeof(uint64_t));
    g_mm->free(addr3);
    g_mm->free(addr4);
    addr5 = g_mm->malloc(8);
    addr6 = g_mm->malloc(24);

    EXPECT_TRUE(addr5 == addr1);
    EXPECT_TRUE(addr6 == addr2);
    EXPECT_TRUE(addr5 == addr3);
    g_mm->clear();

    g_mm->malloc(sizeof(uint64_t));
    addr1 = g_mm->malloc(24);
    addr2 = g_mm->malloc(8);
    g_mm->free(addr1);
    g_mm->free(addr2);
    addr3 = g_mm->malloc(16);
    addr4 = g_mm->malloc(16);
    g_mm->malloc(sizeof(uint64_t));
    g_mm->free(addr3);
    g_mm->free(addr4);
    addr5 = g_mm->malloc(24);
    addr6 = g_mm->malloc(8);

    EXPECT_TRUE(addr5 == addr1);
    EXPECT_TRUE(addr6 == addr2);
    EXPECT_TRUE(addr5 == addr3);
    g_mm->clear();

    g_mm->malloc(sizeof(uint64_t));
    addr1 = g_mm->malloc(16);
    addr2 = g_mm->malloc(16);
    g_mm->free(addr1);
    g_mm->free(addr2);
    addr3 = g_mm->malloc(8);
    addr4 = g_mm->malloc(24);
    g_mm->malloc(sizeof(uint64_t));
    g_mm->free(addr3);
    g_mm->free(addr4);
    addr5 = g_mm->malloc(16);
    addr6 = g_mm->malloc(16);

    EXPECT_TRUE(addr5 == addr1);
    EXPECT_TRUE(addr6 == addr2);
    EXPECT_TRUE(addr5 == addr3);
    g_mm->clear();

    g_mm->malloc(sizeof(uint64_t));
    addr1 = g_mm->malloc(16);
    addr2 = g_mm->malloc(16);
    g_mm->free(addr1);
    g_mm->free(addr2);
    addr3 = g_mm->malloc(24);
    addr4 = g_mm->malloc(8);
    g_mm->malloc(sizeof(uint64_t));
    g_mm->free(addr3);
    g_mm->free(addr4);
    addr5 = g_mm->malloc(16);
    addr6 = g_mm->malloc(16);

    EXPECT_TRUE(addr5 == addr1);
    EXPECT_TRUE(addr6 == addr2);
    EXPECT_TRUE(addr5 == addr3);
    g_mm->clear();
}

void
memory_manager_ut::test_memory_manager_malloc_page_valid()
{
    EXPECT_TRUE(g_mm->malloc(0x1000) != nullptr);

    g_mm->clear();
}

void
memory_manager_ut::test_memory_manager_multiple_malloc_page_should_be_contiguous()
{
    auto addr1 = static_cast<uint8_t *>(g_mm->malloc(0x1000));
    auto addr2 = static_cast<uint8_t *>(g_mm->malloc(0x1000));
    auto addr3 = static_cast<uint8_t *>(g_mm->malloc(0x1000));
    auto addr4 = static_cast<uint8_t *>(g_mm->malloc(0x1000));

    EXPECT_TRUE(addr2 == addr1 + 0x1000);
    EXPECT_TRUE(addr3 == addr2 + 0x1000);
    EXPECT_TRUE(addr4 == addr3 + 0x1000);

    g_mm->clear();

    auto addr5 = static_cast<uint8_t *>(g_mm->malloc(0x2000));
    auto addr6 = static_cast<uint8_t *>(g_mm->malloc(0x2000));
    auto addr7 = static_cast<uint8_t *>(g_mm->malloc(0x2000));
    auto addr8 = static_cast<uint8_t *>(g_mm->malloc(0x2000));

    EXPECT_TRUE(addr6 == addr5 + 0x2000);
    EXPECT_TRUE(addr7 == addr6 + 0x2000);
    EXPECT_TRUE(addr8 == addr7 + 0x2000);

    g_mm->clear();
}

void
memory_manager_ut::test_memory_manager_malloc_page_free_malloc()
{
    void *addr1 = nullptr;
    void *addr2 = nullptr;

    g_mm->malloc(0x1000);
    addr1 = g_mm->malloc(0x1000);
    g_mm->free(addr1);
    addr2 = g_mm->malloc(0x1000);

    EXPECT_TRUE(addr2 == addr1);
    g_mm->clear();

    g_mm->malloc(0x1000);
    addr1 = g_mm->malloc(0x1000);
    g_mm->malloc(0x1000);
    g_mm->free(addr1);
    addr2 = g_mm->malloc(0x1000);

    EXPECT_TRUE(addr2 == addr1);
    g_mm->clear();

    g_mm->malloc(0x1000);
    addr1 = g_mm->malloc(0x1000);
    g_mm->free(addr1);
    addr2 = g_mm->malloc(0x2000);

    EXPECT_TRUE(addr1 == addr2);
    g_mm->clear();

    g_mm->malloc(0x1000);
    addr1 = g_mm->malloc(0x1000);
    g_mm->malloc(0x1000);
    g_mm->free(addr1);
    addr2 = g_mm->malloc(0x2000);

    EXPECT_TRUE(addr1 != addr2);
    g_mm->clear();

    g_mm->malloc(0x1000);
    addr1 = g_mm->malloc(0x2000);
    g_mm->free(addr1);
    addr2 = g_mm->malloc(0x1000);

    EXPECT_TRUE(addr1 == addr2);
    g_mm->clear();

    g_mm->malloc(0x1000);
    addr1 = g_mm->malloc(0x2000);
    g_mm->malloc(0x1000);
    g_mm->free(addr1);
    addr2 = g_mm->malloc(0x1000);

    EXPECT_TRUE(addr1 == addr2);
    g_mm->clear();
}

void
memory_manager_ut::test_memory_manager_free_page_twice()
{
    auto addr1 = g_mm->malloc(0x1000);

    g_mm->free(addr1);
    g_mm->free(addr1);

    g_mm->clear();
}

void
memory_manager_ut::test_memory_manager_malloc_page_all_of_memory()
{
    std::vector<void *> addrs;

    for (auto i = 0U; i < MAX_PAGE_POOL - 1; i++)
        addrs.push_back(g_mm->malloc(0x1000));

    auto fill_mem_pool = g_mm->malloc(0x1000);
    auto mem_pool_full = g_mm->malloc(0x1000);

    EXPECT_TRUE(fill_mem_pool != nullptr);
    EXPECT_TRUE(mem_pool_full == nullptr);

    g_mm->free(fill_mem_pool);
    g_mm->free(mem_pool_full);

    for (const auto &addr : addrs)
        g_mm->free(addr);

    for (auto i = 0U; i < MAX_PAGE_POOL - 1; i++)
        addrs[i] = g_mm->malloc(0x1000);

    fill_mem_pool = g_mm->malloc(0x1000);
    mem_pool_full = g_mm->malloc(0x1000);

    EXPECT_TRUE(fill_mem_pool != nullptr);
    EXPECT_TRUE(mem_pool_full == nullptr);

    g_mm->clear();
}

void
memory_manager_ut::test_memory_manager_malloc_page_all_of_memory_one_block()
{
    EXPECT_TRUE(g_mm->malloc(MAX_PAGE_POOL * 0x1000) != nullptr);
    g_mm->clear();
}

void
memory_manager_ut::test_memory_manager_malloc_page_all_memory_fragmented()
{
    std::vector<void *> addrs;

    for (auto i = 0U; i < MAX_PAGE_POOL; i++)
        addrs.push_back(g_mm->malloc(0x1000));

    for (const auto &addr : addrs)
        g_mm->free(addr);

    EXPECT_TRUE(g_mm->malloc(MAX_PAGE_POOL * 0x1000) != nullptr);

    g_mm->clear();
}

void
memory_manager_ut::test_memory_manager_malloc_page_too_much_memory_one_block()
{
    EXPECT_TRUE(g_mm->malloc((MAX_PAGE_POOL + 1) * 0x1000) == nullptr);
    g_mm->clear();
}

void
memory_manager_ut::test_memory_manager_malloc_page_sparse_fragments()
{
    void *addr1 = nullptr;
    void *addr2 = nullptr;
    void *addr3 = nullptr;
    void *addr4 = nullptr;

    g_mm->malloc(0x1000);
    addr1 = g_mm->malloc(0x1000);
    g_mm->malloc(0x1000);
    addr2 = g_mm->malloc(0x1000);
    g_mm->malloc(0x1000);
    g_mm->free(addr1);
    g_mm->free(addr2);
    addr3 = g_mm->malloc(0x1000);
    addr4 = g_mm->malloc(0x1000);

    EXPECT_TRUE(addr3 == addr1);
    EXPECT_TRUE(addr4 == addr2);
    g_mm->clear();

    g_mm->malloc(0x1000);
    addr1 = g_mm->malloc(0x2000);
    g_mm->malloc(0x1000);
    addr2 = g_mm->malloc(0x1000);
    g_mm->malloc(0x1000);
    g_mm->free(addr1);
    g_mm->free(addr2);
    addr3 = g_mm->malloc(0x2000);
    addr4 = g_mm->malloc(0x1000);

    EXPECT_TRUE(addr3 == addr1);
    EXPECT_TRUE(addr4 == addr2);
    g_mm->clear();

    g_mm->malloc(0x1000);
    addr1 = g_mm->malloc(0x2000);
    g_mm->malloc(0x1000);
    addr2 = g_mm->malloc(0x1000);
    g_mm->malloc(0x1000);
    g_mm->free(addr1);
    g_mm->free(addr2);
    addr3 = g_mm->malloc(0x1000);
    addr4 = g_mm->malloc(0x2000);

    EXPECT_TRUE(addr3 == addr1);
    EXPECT_TRUE(addr4 != addr1);
    g_mm->clear();

    g_mm->malloc(0x1000);
    addr1 = g_mm->malloc(0x1000);
    g_mm->malloc(0x1000);
    addr2 = g_mm->malloc(0x2000);
    g_mm->malloc(0x1000);
    g_mm->free(addr1);
    g_mm->free(addr2);
    addr3 = g_mm->malloc(0x2000);
    addr4 = g_mm->malloc(0x1000);

    EXPECT_TRUE(addr3 == addr2);
    EXPECT_TRUE(addr4 == addr1);
    g_mm->clear();

    g_mm->malloc(0x1000);
    addr1 = g_mm->malloc(0x1000);
    g_mm->malloc(0x1000);
    addr2 = g_mm->malloc(0x2000);
    g_mm->malloc(0x1000);
    g_mm->free(addr1);
    g_mm->free(addr2);
    addr3 = g_mm->malloc(0x1000);
    addr4 = g_mm->malloc(0x2000);

    EXPECT_TRUE(addr3 == addr1);
    EXPECT_TRUE(addr4 == addr2);
    g_mm->clear();
}

void
memory_manager_ut::test_memory_manager_malloc_page_resize_fragments()
{
    void *addr1 = nullptr;
    void *addr2 = nullptr;
    void *addr3 = nullptr;
    void *addr4 = nullptr;
    void *addr5 = nullptr;
    void *addr6 = nullptr;

    g_mm->malloc(0x1000);
    addr1 = g_mm->malloc(0x1000);
    addr2 = g_mm->malloc(0x3000);
    g_mm->free(addr1);
    g_mm->free(addr2);
    addr3 = g_mm->malloc(0x2000);
    addr4 = g_mm->malloc(0x2000);
    g_mm->malloc(0x1000);
    g_mm->free(addr3);
    g_mm->free(addr4);
    addr5 = g_mm->malloc(0x1000);
    addr6 = g_mm->malloc(0x3000);

    EXPECT_TRUE(addr5 == addr1);
    EXPECT_TRUE(addr6 == addr2);
    EXPECT_TRUE(addr5 == addr3);
    g_mm->clear();

    g_mm->malloc(0x1000);
    addr1 = g_mm->malloc(0x3000);
    addr2 = g_mm->malloc(0x1000);
    g_mm->free(addr1);
    g_mm->free(addr2);
    addr3 = g_mm->malloc(0x2000);
    addr4 = g_mm->malloc(0x2000);
    g_mm->malloc(0x1000);
    g_mm->free(addr3);
    g_mm->free(addr4);
    addr5 = g_mm->malloc(0x3000);
    addr6 = g_mm->malloc(0x1000);

    EXPECT_TRUE(addr5 == addr1);
    EXPECT_TRUE(addr6 == addr2);
    EXPECT_TRUE(addr5 == addr3);
    g_mm->clear();

    g_mm->malloc(0x1000);
    addr1 = g_mm->malloc(0x2000);
    addr2 = g_mm->malloc(0x2000);
    g_mm->free(addr1);
    g_mm->free(addr2);
    addr3 = g_mm->malloc(0x1000);
    addr4 = g_mm->malloc(0x3000);
    g_mm->malloc(0x1000);
    g_mm->free(addr3);
    g_mm->free(addr4);
    addr5 = g_mm->malloc(0x2000);
    addr6 = g_mm->malloc(0x2000);

    EXPECT_TRUE(addr5 == addr1);
    EXPECT_TRUE(addr6 == addr2);
    EXPECT_TRUE(addr5 == addr3);
    g_mm->clear();

    g_mm->malloc(0x1000);
    addr1 = g_mm->malloc(0x2000);
    addr2 = g_mm->malloc(0x2000);
    g_mm->free(addr1);
    g_mm->free(addr2);
    addr3 = g_mm->malloc(0x3000);
    addr4 = g_mm->malloc(0x1000);
    g_mm->malloc(0x1000);
    g_mm->free(addr3);
    g_mm->free(addr4);
    addr5 = g_mm->malloc(0x2000);
    addr6 = g_mm->malloc(0x2000);

    EXPECT_TRUE(addr5 == addr1);
    EXPECT_TRUE(addr6 == addr2);
    EXPECT_TRUE(addr5 == addr3);
    g_mm->clear();
}

void
memory_manager_ut::test_memory_manager_malloc_page_alignment()
{
    EXPECT_TRUE((reinterpret_cast<uintptr_t>(g_mm->malloc(0x1000)) & (MAX_PAGE_SIZE - 1)) == 0);
    EXPECT_TRUE((reinterpret_cast<uintptr_t>(g_mm->malloc(0x2000)) & (MAX_PAGE_SIZE - 1)) == 0);
    EXPECT_TRUE((reinterpret_cast<uintptr_t>(g_mm->malloc(0x3000)) & (MAX_PAGE_SIZE - 1)) == 0);
    EXPECT_TRUE((reinterpret_cast<uintptr_t>(g_mm->malloc(0x4000)) & (MAX_PAGE_SIZE - 1)) == 0);
}

void
memory_manager_ut::test_memory_manager_add_md_no_exceptions()
{
    EXPECT_TRUE(add_md(nullptr) == MEMORY_MANAGER_FAILURE);
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
    EXPECT_TRUE(g_mm->virtint_to_physint(0x54321000) == 0);
}

void
memory_manager_ut::test_memory_manager_physint_to_virtint_unknown()
{
    EXPECT_TRUE(g_mm->physint_to_virtint(0x12346000) == 0);
}

void
memory_manager_ut::test_memory_manager_virtint_to_physint_random_address()
{
    memory_descriptor md = {0x12345000, 0x54321000, 7};

    EXPECT_NO_EXCEPTION(g_mm->add_md(&md));
    EXPECT_TRUE(g_mm->virtint_to_physint(0x54321ABC) == 0x12345ABC);
}

void
memory_manager_ut::test_memory_manager_virtint_to_physint_nullptr()
{
    EXPECT_TRUE(g_mm->virtint_to_physint(0) == 0);
    EXPECT_TRUE(g_mm->virtptr_to_physint(nullptr) == 0);
    EXPECT_TRUE(g_mm->virtint_to_physptr(0) == nullptr);
    EXPECT_TRUE(g_mm->virtptr_to_physptr(nullptr) == nullptr);
}

void
memory_manager_ut::test_memory_manager_virtint_to_physint_upper_limit()
{
    memory_descriptor md = {0x12345000, 0x54321000, 7};

    EXPECT_NO_EXCEPTION(g_mm->add_md(&md));
    EXPECT_TRUE(g_mm->virtint_to_physint(0x54321FFF) == 0x12345FFF);
}

void
memory_manager_ut::test_memory_manager_virtint_to_physint_lower_limit()
{
    memory_descriptor md = {0x12345000, 0x54321000, 7};

    EXPECT_NO_EXCEPTION(g_mm->add_md(&md));
    EXPECT_TRUE(g_mm->virtint_to_physint(0x54321000) == 0x12345000);
}

void
memory_manager_ut::test_memory_manager_virt_to_phys_map()
{
    memory_descriptor md = {0x12345000, 0x54321000, 7};

    EXPECT_NO_EXCEPTION(g_mm->add_md(&md));

    for (const auto &iter : g_mm->virt_to_phys_map())
    {
        EXPECT_TRUE(iter.first == (0x54321000 >> 12));
        EXPECT_TRUE(iter.second.phys == md.phys);
        EXPECT_TRUE(iter.second.virt == md.virt);
        EXPECT_TRUE(iter.second.type == md.type);
    }
}

void
memory_manager_ut::test_memory_manager_physint_to_virtint_random_address()
{
    memory_descriptor md = {0x12345000, 0x54321000, 7};

    EXPECT_NO_EXCEPTION(g_mm->add_md(&md));
    EXPECT_TRUE(g_mm->physint_to_virtint(0x12345ABC) == 0x54321ABC);
}

void
memory_manager_ut::test_memory_manager_physint_to_virtint_nullptr()
{
    EXPECT_TRUE(g_mm->physint_to_virtint(0) == 0);
    EXPECT_TRUE(g_mm->physptr_to_virtint(nullptr) == 0);
    EXPECT_TRUE(g_mm->physint_to_virtptr(0) == nullptr);
    EXPECT_TRUE(g_mm->physptr_to_virtptr(nullptr) == nullptr);
}

void
memory_manager_ut::test_memory_manager_physint_to_virtint_upper_limit()
{
    memory_descriptor md = {0x12345000, 0x54321000, 7};

    EXPECT_NO_EXCEPTION(g_mm->add_md(&md));
    EXPECT_TRUE(g_mm->physint_to_virtint(0x12345FFF) == 0x54321FFF);
}

void
memory_manager_ut::test_memory_manager_physint_to_virtint_lower_limit()
{
    memory_descriptor md = {0x12345000, 0x54321000, 7};

    EXPECT_NO_EXCEPTION(g_mm->add_md(&md));
    EXPECT_TRUE(g_mm->physint_to_virtint(0x12345000) == 0x54321000);
}

void
memory_manager_ut::test_memory_manager_phys_to_virt_map()
{
    memory_descriptor md = {0x12345000, 0x54321000, 7};

    EXPECT_NO_EXCEPTION(g_mm->add_md(&md));

    for (const auto &iter : g_mm->phys_to_virt_map())
    {
        EXPECT_TRUE(iter.first == (0x12345000 >> 12));
        EXPECT_TRUE(iter.second.phys == md.phys);
        EXPECT_TRUE(iter.second.virt == md.virt);
        EXPECT_TRUE(iter.second.type == md.type);
    }
}
