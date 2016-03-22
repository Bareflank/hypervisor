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

#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <debug.h>
#include <constants.h>
#include <commit_or_rollback.h>
#include <memory_manager/memory_manager.h>
#include <memory_manager/memory_manager_exceptions.h>

// -----------------------------------------------------------------------------
// Macros
// -----------------------------------------------------------------------------

#define FREE_BLOCK (-1)

// -----------------------------------------------------------------------------
// Global Memory
// -----------------------------------------------------------------------------

// The following defines the entire memory pool. This pool will be used by the
// VMM to create the different resources that it needs, which is mainly given
// out using new/delete. If space runs out, this will need to be increased.
uint8_t g_mem_pool[MAX_MEM_POOL] ALIGN_MEMORY = {0};

// The memory pool itself is given out in blocks. Any attempt to new / delete
// will always allocate at least a block of memory, which is usually set to a
// cache line size. This stores whether a block is allocated or not. Note that
// the way we know if a block is allocated, is it's not set to FREE_BLOCK.
// We use the value stored here to tell us what the starting address is when a
// block is allocated. This greatly simplifies freeing memory at the expense of
// a lot of memory needed to manage memory.
int64_t g_block_allocated[MAX_BLOCKS] = {0};

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

void *
out_of_memory(void)
{

#ifdef CROSS_COMPILED

    const char *msg = "FATAL ERROR: Out of memory!!!";

    write(0, msg, strlen(msg));
    abort();

#endif

    return 0;
}

template<typename T> int64_t
guard_exceptions(T func)
{
    try
    {
        func();

        return MEMORY_MANAGER_SUCCESS;
    }
    catch (bfn::general_exception &ge)
    {
        bferror << "----------------------------------------" << bfendl;
        bferror << "- General Exception Caught             -" << bfendl;
        bferror << "----------------------------------------" << bfendl;
        bfinfo << ge << bfendl;
    }
    catch (std::exception &e)
    {
        bferror << "----------------------------------------" << bfendl;
        bferror << "- Standard Exception Caught            -" << bfendl;
        bferror << "----------------------------------------" << bfendl;
        bfinfo << e.what() << bfendl;
    }
    catch (...)
    {
        bferror << "----------------------------------------" << bfendl;
        bferror << "- Unknown Exception Caught             -" << bfendl;
        bferror << "----------------------------------------" << bfendl;
    }

    return MEMORY_MANAGER_FAILURE;
}

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

memory_manager *
memory_manager::instance()
{
    static memory_manager self;
    return &self;
}

int64_t
memory_manager::free_blocks()
{
    auto num_blocks = 0;

    for (auto i = 0U; i < MAX_BLOCKS; i++)
        if (g_block_allocated[i] == FREE_BLOCK)
            num_blocks++;

    return num_blocks;
}

void *
memory_manager::malloc(size_t size)
{
    return malloc_aligned(size, size == MAX_PAGE_SIZE ? MAX_PAGE_SIZE : 0);
}

void *
memory_manager::malloc_aligned(size_t size, int64_t alignment)
{
    if (size == 0)
        return 0;

    // This is a really simple "first fit" algorithm. The only optimization
    // that we have here is m_start. This algorithm works by looping from the
    // start of the list of blocks, and looking for a contiguous set of
    // blocks, that matches the provided alignment. Once we find the set of
    // blocks the user is asking for, we set each block to "allocated" by
    // providing the start block for the chunk of memory that was allocated.
    // Free will use this "start" block to identify the starting block for
    // any allocated virtual address.
    //
    // m_start defines the starting position to search the list of blocks.
    // Without m_start, we would start from 0, and loop to MAX_BLOCKS on
    // every allocation. In practice, we don't need to start from 0, as each
    // block is likely to be consumed as we allocate more and more memory.
    // It's not until the first hole or "fragmentation" occurs, that m_start
    // must stop until the fragmentation is removed.

    auto count = 0U;
    auto block = 0U;
    auto reset = 0U;
    auto num_blocks = size >> MAX_CACHE_LINE_SHIFT;

    if (size % MAX_CACHE_LINE_SIZE != 0)
        num_blocks++;

    for (auto b = m_start; b < MAX_BLOCKS && count < num_blocks; b++)
    {
        if (g_block_allocated[b] == FREE_BLOCK)
        {
            if (count == 0)
            {
                if (is_block_aligned(b, alignment) == false)
                {
                    reset = 1;
                    continue;
                }

                block = b;
            }

            count++;

            if (reset == 0 && b > m_start)
                m_start = b;
        }
        else
        {
            if (count > 0)
                reset = 1;

            count = 0;
        }
    }

    if (count == num_blocks)
    {
        for (auto b = block; b < MAX_BLOCKS && b < num_blocks + block; b++)
            g_block_allocated[b] = block;

        return block_to_virt(block);
    }

    return out_of_memory();
}

void
memory_manager::free(void *ptr)
{
    if (ptr == 0)
        return;

    // Our version of free is a lot cleaner than most memory manager, but is
    // terribly inefficent with respect to how much memory it consumes for
    // bookeeping. We store the starting block for every virtual address. This
    // means that if you were to delete a base class for a subclass that did
    // not specify "virtual" for the base class, all of memory would still be
    // deleted. This is because we know where the starting address should be
    // even if the virtual address that was provided is offset from the
    // virtual address that was actually allocated.
    //
    // Also note that we need to adjust m_start if we freed memory that opened
    // up a "fragmentation" in list of allocated blocks.

    auto block = virt_to_block(ptr);

    if (block < 0 || (uint32_t)block >= MAX_BLOCKS)
        return;

    auto start = g_block_allocated[block];

    if (start < 0 || (uint32_t)start >= MAX_BLOCKS)
        return;

    for (auto b = (uint32_t)start; b < MAX_BLOCKS; b++)
    {
        if (b < m_start)
            m_start = b;

        if (g_block_allocated[b] != start)
            break;

        g_block_allocated[b] = FREE_BLOCK;
    }
}

void *
memory_manager::block_to_virt(int64_t block)
{
    if (block < 0 || (uint32_t)block >= MAX_BLOCKS)
        return 0;

    return g_mem_pool + (block * MAX_CACHE_LINE_SIZE);
}

int64_t
memory_manager::virt_to_block(void *virt)
{
    if (virt >= g_mem_pool + MAX_MEM_POOL)
        return -1;

    return ((uint8_t *)virt - g_mem_pool) >> MAX_CACHE_LINE_SHIFT;
}

void *
memory_manager::virt_to_phys(void *virt)
{
    auto key = (uintptr_t)virt >> MAX_PAGE_SHIFT;
    const auto &md_iter = m_virt_to_phys_map.find(key);

    if (md_iter == m_virt_to_phys_map.end())
        return 0;

    auto upper = ((uintptr_t)md_iter->second.phys & ~(MAX_PAGE_SIZE - 1));
    auto lower = ((uintptr_t)virt & (MAX_PAGE_SIZE - 1));

    return (void *)(upper | lower);
}

void *
memory_manager::phys_to_virt(void *phys)
{

    auto key = (uintptr_t)phys >> MAX_PAGE_SHIFT;
    const auto &md_iter = m_phys_to_virt_map.find(key);

    if (md_iter == m_phys_to_virt_map.end())
        return 0;

    auto upper = ((uintptr_t)md_iter->second.virt & ~(MAX_PAGE_SIZE - 1));
    auto lower = ((uintptr_t)phys & (MAX_PAGE_SIZE - 1));

    return (void *)(upper | lower);
}

bool
memory_manager::is_block_aligned(int64_t block, int64_t alignment)
{
    if (block < 0 || (uint32_t)block >= MAX_BLOCKS)
        return false;

    if (alignment <= 0)
        return true;

    return ((uint64_t)block_to_virt(block) % alignment) == 0;
}

void
memory_manager::add_mdl(struct memory_descriptor *mdl, int64_t num)
{
    if (mdl == NULL)
        throw invalid_argument(mdl, "mdl == NULL");

    if (num == 0)
        throw invalid_argument(num, "num == 0");

    for (auto i = 0; i < num; i++)
    {
        const auto &md = mdl[i];

        if (md.size != MAX_PAGE_SIZE)
            throw invalid_mdl("md.size != MAX_PAGE_SIZE", i);

        if (((uintptr_t)md.virt & (MAX_PAGE_SIZE - 1)) != 0)
            throw invalid_mdl("virt address is not page aligned", i);

        if (((uintptr_t)md.phys & (MAX_PAGE_SIZE - 1)) != 0)
            throw invalid_mdl("phys address is not page aligned", i);

        auto cor1 = commit_or_rollback([&]
        {
            m_virt_to_phys_map.erase((uintptr_t)md.virt >> MAX_PAGE_SHIFT);
            m_phys_to_virt_map.erase((uintptr_t)md.phys >> MAX_PAGE_SHIFT);
        });

        m_virt_to_phys_map[(uintptr_t)md.virt >> MAX_PAGE_SHIFT] = md;
        m_phys_to_virt_map[(uintptr_t)md.phys >> MAX_PAGE_SHIFT] = md;

        cor1.commit();
    }
}

memory_manager::memory_manager()
{
    m_start = 0;

    for (auto i = 0U; i < MAX_MEM_POOL; i++)
        g_mem_pool[i] = 0;

    for (auto i = 0U; i < MAX_BLOCKS; i++)
        g_block_allocated[i] = FREE_BLOCK;
}

extern "C" void *
_malloc_r(struct _reent *reent, size_t size)
{
    (void) reent;

    size_t i;
    char *ptr = (char *)g_mm->malloc(size);

    if (ptr != NULL)
    {
        for (i = 0; i < size; i++)
            ptr[i] = 0;
    }

    return ptr;
}

extern "C" void
_free_r(struct _reent *reent, void *ptr)
{
    (void) reent;

    g_mm->free(ptr);
}

extern "C" void *
_calloc_r(struct _reent *reent, size_t nmemb, size_t size)
{
    return _malloc_r(reent, nmemb * size);
}

extern "C" void *
_realloc_r(struct _reent *reent, void *ptr, size_t size)
{
    _free_r(reent, ptr);
    return _malloc_r(reent, size);
}

extern "C" int64_t
add_mdl(struct memory_descriptor *mdl, int64_t num)
{
    return guard_exceptions([&]()
    { g_mm->add_mdl(mdl, num); });
}
