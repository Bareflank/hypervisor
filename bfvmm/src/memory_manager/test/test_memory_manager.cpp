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

extern "C" int64_t
add_md(struct memory_descriptor *md) noexcept;

void
memory_manager_ut::test_memory_manager_malloc_zero()
{
    EXPECT_TRUE(g_mm->malloc(0) == 0);
}

void
memory_manager_ut::test_memory_manager_malloc_valid()
{
    auto addr = g_mm->malloc(10);

    EXPECT_TRUE(addr != 0);
    EXPECT_TRUE(g_mm->free_blocks() == MAX_BLOCKS - 1);

    g_mm->free(addr);
    EXPECT_TRUE(g_mm->free_blocks() == MAX_BLOCKS);
}

void
memory_manager_ut::test_memory_manager_multiple_malloc_should_be_contiguous()
{
    auto addr1 = static_cast<char *>(g_mm->malloc(10));
    auto addr2 = static_cast<char *>(g_mm->malloc(10));
    auto addr3 = static_cast<char *>(g_mm->malloc(10));
    auto addr4 = static_cast<char *>(g_mm->malloc(10));

    EXPECT_TRUE(addr2 == addr1 + MAX_CACHE_LINE_SIZE);
    EXPECT_TRUE(addr3 == addr2 + MAX_CACHE_LINE_SIZE);
    EXPECT_TRUE(addr4 == addr3 + MAX_CACHE_LINE_SIZE);
    EXPECT_TRUE(g_mm->free_blocks() == MAX_BLOCKS - 4);

    g_mm->free(addr1);
    EXPECT_TRUE(g_mm->free_blocks() == MAX_BLOCKS - 3);

    g_mm->free(addr2);
    EXPECT_TRUE(g_mm->free_blocks() == MAX_BLOCKS - 2);

    g_mm->free(addr3);
    EXPECT_TRUE(g_mm->free_blocks() == MAX_BLOCKS - 1);

    g_mm->free(addr4);
    EXPECT_TRUE(g_mm->free_blocks() == MAX_BLOCKS);
}

void
memory_manager_ut::test_memory_manager_malloc_free_malloc()
{
    auto addr1 = g_mm->malloc(10);
    g_mm->free(addr1);
    auto addr2 = g_mm->malloc(10);

    EXPECT_TRUE(addr2 == addr1);
    EXPECT_TRUE(g_mm->free_blocks() == MAX_BLOCKS - 1);

    g_mm->free(addr2);
    EXPECT_TRUE(g_mm->free_blocks() == MAX_BLOCKS);
}

void
memory_manager_ut::test_memory_manager_malloc_page_is_page_aligned()
{
    auto addr1 = g_mm->malloc(10);
    auto addr2 = g_mm->malloc(MAX_PAGE_SIZE);

    EXPECT_TRUE(reinterpret_cast<uint64_t>(addr2) % MAX_PAGE_SIZE == 0);
    EXPECT_TRUE(g_mm->free_blocks() == MAX_BLOCKS - 65);

    g_mm->free(addr1);
    EXPECT_TRUE(g_mm->free_blocks() == MAX_BLOCKS - MAX_CACHE_LINE_SIZE);

    g_mm->free(addr2);
    EXPECT_TRUE(g_mm->free_blocks() == MAX_BLOCKS);
}

void
memory_manager_ut::test_memory_manager_free_zero()
{
    g_mm->free(0);

    EXPECT_TRUE(g_mm->free_blocks() == MAX_BLOCKS);
}

void
memory_manager_ut::test_memory_manager_free_random()
{
    g_mm->free(reinterpret_cast<void *>(0xDEADBEEF));

    EXPECT_TRUE(g_mm->free_blocks() == MAX_BLOCKS);
}

void
memory_manager_ut::test_memory_manager_free_twice()
{
    auto addr1 = g_mm->malloc(10);

    g_mm->free(addr1);
    g_mm->free(addr1);
    EXPECT_TRUE(g_mm->free_blocks() == MAX_BLOCKS);
}

void
memory_manager_ut::test_memory_manager_malloc_all_of_memory()
{
    void *addr[MAX_BLOCKS] = {0};

    for (auto i = 0U; i < MAX_BLOCKS - 1; i++)
        addr[i] = g_mm->malloc(MAX_CACHE_LINE_SIZE);

    EXPECT_TRUE(g_mm->free_blocks() == 1);
    addr[MAX_BLOCKS - 1] = g_mm->malloc(MAX_CACHE_LINE_SIZE);

    EXPECT_TRUE(g_mm->free_blocks() == 0);
    EXPECT_TRUE(g_mm->malloc(10) == 0);

    for (auto i = 0U; i < MAX_BLOCKS; i++)
        g_mm->free(addr[i]);

    EXPECT_TRUE(g_mm->free_blocks() == MAX_BLOCKS);
}

void
memory_manager_ut::test_memory_manager_malloc_all_of_memory_fragmented()
{
    void *addr[TOTAL_NUM_PAGES] = {0};

    for (auto i = 0U; i < TOTAL_NUM_PAGES - 1; i++)
        addr[i] = g_mm->malloc(MAX_PAGE_SIZE);

    EXPECT_TRUE(g_mm->free_blocks() == BLOCKS_PER_PAGE);
    addr[TOTAL_NUM_PAGES - 1] = g_mm->malloc(10);

    EXPECT_TRUE(g_mm->free_blocks() == BLOCKS_PER_PAGE - 1);
    EXPECT_TRUE(g_mm->malloc(MAX_PAGE_SIZE) == 0);

    for (auto i = 0U; i < TOTAL_NUM_PAGES; i++)
        g_mm->free(addr[i]);

    EXPECT_TRUE(g_mm->free_blocks() == MAX_BLOCKS);
}

void
memory_manager_ut::test_memory_manager_malloc_aligned_ignored_alignment()
{
    auto addr1 = g_mm->malloc_aligned(10, 0);
    auto addr2 = g_mm->malloc_aligned(10, -1);

    EXPECT_TRUE(addr1 != 0);
    EXPECT_TRUE(addr2 != 0);

    g_mm->free(addr1);
    g_mm->free(addr2);
}

void
memory_manager_ut::test_memory_manager_malloc_aligned()
{
    auto addr1 = g_mm->malloc_aligned(10, 3);
    auto addr2 = g_mm->malloc_aligned(10, 5);
    auto addr3 = g_mm->malloc_aligned(10, MAX_CACHE_LINE_SIZE);
    auto addr4 = g_mm->malloc_aligned(10, MAX_PAGE_SIZE);
    auto addr5 = g_mm->malloc_aligned(10, 3);

    EXPECT_TRUE(reinterpret_cast<uint64_t>(addr1) % 3 == 0);
    EXPECT_TRUE(reinterpret_cast<uint64_t>(addr2) % 5 == 0);
    EXPECT_TRUE(reinterpret_cast<uint64_t>(addr3) % MAX_CACHE_LINE_SIZE == 0);
    EXPECT_TRUE(reinterpret_cast<uint64_t>(addr4) % MAX_PAGE_SIZE == 0);
    EXPECT_TRUE(reinterpret_cast<uint64_t>(addr5) % 3 == 0);

    g_mm->free(addr1);
    g_mm->free(addr2);
    g_mm->free(addr3);
    g_mm->free(addr4);
    g_mm->free(addr5);

    EXPECT_TRUE(g_mm->free_blocks() == MAX_BLOCKS);
}

void
memory_manager_ut::test_memory_manager_malloc_alloc_fragment()
{
    auto addr1 = g_mm->malloc_aligned(10, 16);
    auto addr2 = g_mm->malloc_aligned(MAX_PAGE_SIZE, MAX_PAGE_SIZE);
    auto addr3 = g_mm->malloc_aligned(10, 0);
    auto addr4 = g_mm->malloc_aligned(10, 0);
    auto addr5 = g_mm->malloc_aligned(10, 0);

    EXPECT_TRUE(addr1 != 0);
    EXPECT_TRUE(addr2 != 0);
    EXPECT_TRUE(addr3 != 0);
    EXPECT_TRUE(addr4 != 0);
    EXPECT_TRUE(addr5 != 0);

    EXPECT_TRUE(reinterpret_cast<uint64_t>(addr3) < reinterpret_cast<uint64_t>(addr2));
    EXPECT_TRUE(reinterpret_cast<uint64_t>(addr4) < reinterpret_cast<uint64_t>(addr2));
    EXPECT_TRUE(reinterpret_cast<uint64_t>(addr5) < reinterpret_cast<uint64_t>(addr2));

    g_mm->free(addr4);
    auto addr6 = g_mm->malloc_aligned(10, 0);

    EXPECT_TRUE(reinterpret_cast<uint64_t>(addr4) == reinterpret_cast<uint64_t>(addr6));

    g_mm->free(addr1);
    g_mm->free(addr2);
    g_mm->free(addr3);
    g_mm->free(addr5);
    g_mm->free(addr6);

    EXPECT_TRUE(g_mm->free_blocks() == MAX_BLOCKS);
}

void
memory_manager_ut::test_memory_manager_malloc_alloc_multiple_fragments()
{
    auto addr1 = g_mm->malloc(64);
    auto addr2 = g_mm->malloc_aligned(64, 128);
    auto addr3 = g_mm->malloc(128);
    g_mm->free(addr1);
    g_mm->free(addr2);
    g_mm->free(addr3);
}

void
memory_manager_ut::test_memory_manager_add_md_no_exceptions()
{
    EXPECT_TRUE(add_md(0) == MEMORY_MANAGER_FAILURE);
}

void
memory_manager_ut::test_memory_manager_add_md_invalid_md()
{
    EXPECT_EXCEPTION(g_mm->add_md(0), std::invalid_argument);
}

void
memory_manager_ut::test_memory_manager_add_md_invalid_virt()
{
    memory_descriptor md = {reinterpret_cast<void *>(0), reinterpret_cast<void *>(0x54321000), 7};

    EXPECT_EXCEPTION(g_mm->add_md(&md), std::invalid_argument);
}

void
memory_manager_ut::test_memory_manager_add_md_invalid_phys()
{
    memory_descriptor md = {reinterpret_cast<void *>(0x12345123), reinterpret_cast<void *>(0), 7};

    EXPECT_EXCEPTION(g_mm->add_md(&md), std::invalid_argument);
}

void
memory_manager_ut::test_memory_manager_add_md_invalid_type()
{
    memory_descriptor md = {reinterpret_cast<void *>(0x12345000), reinterpret_cast<void *>(0x54321000), 0};

    EXPECT_EXCEPTION(g_mm->add_md(&md), std::invalid_argument);
}

void
memory_manager_ut::test_memory_manager_add_md_unaligned_physical()
{
    memory_descriptor md = {reinterpret_cast<void *>(0x12345123), reinterpret_cast<void *>(0x54321000), 7};

    EXPECT_EXCEPTION(g_mm->add_md(&md), std::logic_error);
}

void
memory_manager_ut::test_memory_manager_add_md_unaligned_virtual()
{
    memory_descriptor md = {reinterpret_cast<void *>(0x12345000), reinterpret_cast<void *>(0x54321123), 7};

    EXPECT_EXCEPTION(g_mm->add_md(&md), std::logic_error);
}

void
memory_manager_ut::test_memory_manager_block_to_virt_unknown()
{
    EXPECT_TRUE(g_mm->block_to_virt(-1) == 0);
    EXPECT_TRUE(g_mm->block_to_virt(0x0FFFFFFFFFFFFFFF) == 0);
}

void
memory_manager_ut::test_memory_manager_virt_to_block_unknown()
{
    EXPECT_TRUE(g_mm->virt_to_block(reinterpret_cast<void *>(0)) == -1);
    EXPECT_TRUE(g_mm->virt_to_block(reinterpret_cast<void *>(0xFFFFFFFFFFFFFFFF)) == -1);
}

void
memory_manager_ut::test_memory_manager_is_block_aligned_unknown()
{
    EXPECT_TRUE(g_mm->is_block_aligned(-1, 64) == false);
    EXPECT_TRUE(g_mm->is_block_aligned(0x0FFFFFFFFFFFFFFF, 64) == false);
}

void
memory_manager_ut::test_memory_manager_virt_to_phys_unknown()
{
    EXPECT_TRUE(g_mm->virt_to_phys(reinterpret_cast<void *>(0x54321000)) == reinterpret_cast<void *>(0));
}

void
memory_manager_ut::test_memory_manager_phys_to_virt_unknown()
{
    EXPECT_TRUE(g_mm->phys_to_virt(reinterpret_cast<void *>(0x12346000)) == reinterpret_cast<void *>(0));
}

void
memory_manager_ut::test_memory_manager_virt_to_phys_random_address()
{
    memory_descriptor md = {reinterpret_cast<void *>(0x12345000), reinterpret_cast<void *>(0x54321000), 7};

    EXPECT_NO_EXCEPTION(g_mm->add_md(&md));
    EXPECT_TRUE(g_mm->virt_to_phys(reinterpret_cast<void *>(0x54321ABC)) == reinterpret_cast<void *>(0x12345ABC));
}

void
memory_manager_ut::test_memory_manager_virt_to_phys_upper_limit()
{
    memory_descriptor md = {reinterpret_cast<void *>(0x12345000), reinterpret_cast<void *>(0x54321000), 7};

    EXPECT_NO_EXCEPTION(g_mm->add_md(&md));
    EXPECT_TRUE(g_mm->virt_to_phys(reinterpret_cast<void *>(0x54321FFF)) == reinterpret_cast<void *>(0x12345FFF));
}

void
memory_manager_ut::test_memory_manager_virt_to_phys_lower_limit()
{
    memory_descriptor md = {reinterpret_cast<void *>(0x12345000), reinterpret_cast<void *>(0x54321000), 7};

    EXPECT_NO_EXCEPTION(g_mm->add_md(&md));
    EXPECT_TRUE(g_mm->virt_to_phys(reinterpret_cast<void *>(0x54321000)) == reinterpret_cast<void *>(0x12345000));
}

void
memory_manager_ut::test_memory_manager_virt_to_phys_map()
{
    memory_descriptor md = {reinterpret_cast<void *>(0x12345000), reinterpret_cast<void *>(0x54321000), 7};

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
memory_manager_ut::test_memory_manager_phys_to_virt_random_address()
{
    memory_descriptor md = {reinterpret_cast<void *>(0x12345000), reinterpret_cast<void *>(0x54321000), 7};

    EXPECT_NO_EXCEPTION(g_mm->add_md(&md));
    EXPECT_TRUE(g_mm->phys_to_virt(reinterpret_cast<void *>(0x12345ABC)) == reinterpret_cast<void *>(0x54321ABC));
}

void
memory_manager_ut::test_memory_manager_phys_to_virt_upper_limit()
{
    memory_descriptor md = {reinterpret_cast<void *>(0x12345000), reinterpret_cast<void *>(0x54321000), 7};

    EXPECT_NO_EXCEPTION(g_mm->add_md(&md));
    EXPECT_TRUE(g_mm->phys_to_virt(reinterpret_cast<void *>(0x12345FFF)) == reinterpret_cast<void *>(0x54321FFF));
}

void
memory_manager_ut::test_memory_manager_phys_to_virt_lower_limit()
{
    memory_descriptor md = {reinterpret_cast<void *>(0x12345000), reinterpret_cast<void *>(0x54321000), 7};

    EXPECT_NO_EXCEPTION(g_mm->add_md(&md));
    EXPECT_TRUE(g_mm->phys_to_virt(reinterpret_cast<void *>(0x12345000)) == reinterpret_cast<void *>(0x54321000));
}

void
memory_manager_ut::test_memory_manager_phys_to_virt_map()
{
    memory_descriptor md = {reinterpret_cast<void *>(0x12345000), reinterpret_cast<void *>(0x54321000), 7};

    EXPECT_NO_EXCEPTION(g_mm->add_md(&md));

    for (const auto &iter : g_mm->phys_to_virt_map())
    {
        EXPECT_TRUE(iter.first == (0x12345000 >> 12));
        EXPECT_TRUE(iter.second.phys == md.phys);
        EXPECT_TRUE(iter.second.virt == md.virt);
        EXPECT_TRUE(iter.second.type == md.type);
    }
}

void
memory_manager_ut::test_memory_manager_power_of_two_zero()
{
    EXPECT_TRUE(g_mm->private_is_power_of_2(0) == false);
}
