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
#include <guard_exceptions.h>
#include <commit_or_rollback.h>
#include <memory_manager/memory_manager.h>

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
out_of_memory(void) noexcept
{

#if defined(OUT_OF_MEMORY_ABORT)

    const char *msg = "FATAL ERROR: Out of memory!!!";

    write(0, msg, strlen(msg));
    abort();

#endif

    return 0;
}

// -----------------------------------------------------------------------------
// Mutexes
// -----------------------------------------------------------------------------

#include <mutex>

std::mutex g_malloc_mutex;
std::mutex g_add_md_mutex;

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

memory_manager *
memory_manager::instance() noexcept
{
    static memory_manager self;
    return &self;
}

int64_t
memory_manager::free_blocks() noexcept
{
    auto num_blocks = 0;
    std::lock_guard<std::mutex> guard(g_malloc_mutex);

    for (auto i = 0ULL; i < MAX_BLOCKS; i++)
        if (g_block_allocated[i] == FREE_BLOCK)
            num_blocks++;

    return num_blocks;
}

void *
memory_manager::malloc(size_t size) noexcept
{
    return malloc_aligned(size, size == MAX_PAGE_SIZE ? MAX_PAGE_SIZE : 0);
}

void *
memory_manager::malloc_aligned(size_t size, uint64_t alignment) noexcept
{
    if (size == 0)
        return 0;

    std::lock_guard<std::mutex> guard(g_malloc_mutex);

    // This is a really simple "first fit" algorithm. The only optimization
    // that we have here is m_start. This algorithm works by looping from
    // the start of the list of blocks, and looking for a contiguous set of
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

    auto count = 0ULL;
    auto block = 0ULL;
    auto reset = 0ULL;
    auto num_blocks = size >> MAX_CACHE_LINE_SHIFT;

    if ((size & (MAX_CACHE_LINE_SIZE - 1)) != 0)
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
memory_manager::free(void *ptr) noexcept
{
    if (ptr == 0)
        return;

    std::lock_guard<std::mutex> guard(g_malloc_mutex);

    // Our version of free is a lot cleaner than most memory manager, but is
    // terribly inefficent with respect to how much memory it consumes for
    // bookeeping. We store the starting block for every virtual address.
    // This means that if you were to delete a base class for a subclass
    // that did not specify "virtual" for the base class, all of memory
    // would still be deleted. This is because we know where the starting
    // address should be even if the virtual address that was provided is
    // offset from the virtual address that was actually allocated.
    //
    // Also note that we need to adjust m_start if we freed memory that
    // opened up a "fragmentation" in list of allocated blocks.

    auto block = virt_to_block(ptr);

    if (block < 0 || static_cast<uint32_t>(block) >= MAX_BLOCKS)
        return;

    auto start = g_block_allocated[block];

    if (start < 0 || static_cast<uint32_t>(start) >= MAX_BLOCKS)
        return;

    for (auto b = static_cast<uint32_t>(start); b < MAX_BLOCKS; b++)
    {
        if (b < m_start)
            m_start = b;

        if (g_block_allocated[b] != start)
            break;

        g_block_allocated[b] = FREE_BLOCK;
    }
}

void *
memory_manager::block_to_virt(int64_t block) noexcept
{
    if (block < 0 || static_cast<uint32_t>(block) >= MAX_BLOCKS)
        return 0;

    return g_mem_pool + (block * MAX_CACHE_LINE_SIZE);
}

int64_t
memory_manager::virt_to_block(void *virt) noexcept
{
    if (virt < g_mem_pool || virt >= g_mem_pool + MAX_MEM_POOL)
        return -1;

    return (reinterpret_cast<uint8_t *>(virt) - g_mem_pool) >> MAX_CACHE_LINE_SHIFT;
}

void *
memory_manager::virt_to_phys(void *virt)
{
    std::lock_guard<std::mutex> guard(g_add_md_mutex);

    auto key = reinterpret_cast<uintptr_t>(virt) >> MAX_PAGE_SHIFT;
    const auto &md_iter = m_virt_to_phys_map.find(key);

    if (md_iter == m_virt_to_phys_map.end())
        return 0;

    auto upper = (reinterpret_cast<uintptr_t>(md_iter->second.phys) & ~(MAX_PAGE_SIZE - 1));
    auto lower = (reinterpret_cast<uintptr_t>(virt) & (MAX_PAGE_SIZE - 1));

    return reinterpret_cast<void *>(upper | lower);
}

void *
memory_manager::phys_to_virt(void *phys)
{
    std::lock_guard<std::mutex> guard(g_add_md_mutex);

    auto key = reinterpret_cast<uintptr_t>(phys) >> MAX_PAGE_SHIFT;
    const auto &md_iter = m_phys_to_virt_map.find(key);

    if (md_iter == m_phys_to_virt_map.end())
        return 0;

    auto upper = (reinterpret_cast<uintptr_t>(md_iter->second.virt) & ~(MAX_PAGE_SIZE - 1));
    auto lower = (reinterpret_cast<uintptr_t>(phys) & (MAX_PAGE_SIZE - 1));

    return reinterpret_cast<void *>(upper | lower);
}

bool
memory_manager::private_is_power_of_2(uint64_t x) noexcept
{
    if (x <= 0)
        return false;

    return !(x & (x - 1));
}

bool
memory_manager::is_block_aligned(int64_t block, int64_t alignment) noexcept
{
    if (block < 0 || static_cast<uint32_t>(block) >= MAX_BLOCKS)
        return false;

    if (alignment <= 0)
        return true;

    if (this->private_is_power_of_2(alignment) == false)
        return false;

    return (reinterpret_cast<uint64_t>(block_to_virt(block)) & (alignment - 1)) == 0;
}

void
memory_manager::add_md(memory_descriptor *md)
{
    if (md == NULL)
        throw std::invalid_argument("md == NULL");

    if (md->virt == 0)
        throw std::invalid_argument("md->virt == 0");

    if (md->phys == 0)
        throw std::invalid_argument("md->phys == 0");

    if ((reinterpret_cast<uintptr_t>(md->virt) & (MAX_PAGE_SIZE - 1)) != 0)
        throw std::logic_error("virt address is not page aligned");

    if ((reinterpret_cast<uintptr_t>(md->phys) & (MAX_PAGE_SIZE - 1)) != 0)
        throw std::logic_error("phys address is not page aligned");

    auto cor1 = commit_or_rollback([&]
    {
        std::lock_guard<std::mutex> guard(g_add_md_mutex);

        m_virt_to_phys_map.erase(reinterpret_cast<uintptr_t>(md->virt) >> MAX_PAGE_SHIFT);
        m_phys_to_virt_map.erase(reinterpret_cast<uintptr_t>(md->phys) >> MAX_PAGE_SHIFT);
    });

    if (md->type == 0)
        throw std::invalid_argument("md->type == 0");
    else
    {
        std::lock_guard<std::mutex> guard(g_add_md_mutex);

        m_virt_to_phys_map[reinterpret_cast<uintptr_t>(md->virt) >> MAX_PAGE_SHIFT] = *md;
        m_phys_to_virt_map[reinterpret_cast<uintptr_t>(md->phys) >> MAX_PAGE_SHIFT] = *md;
    }

    cor1.commit();
}

memory_manager::memory_manager() noexcept
{
    m_start = 0;

    for (auto i = 0ULL; i < MAX_MEM_POOL; i++)
        g_mem_pool[i] = 0;

    for (auto i = 0ULL; i < MAX_BLOCKS; i++)
        g_block_allocated[i] = FREE_BLOCK;
}

extern "C" int64_t
add_md(struct memory_descriptor *md) noexcept
{
    return guard_exceptions(MEMORY_MANAGER_FAILURE, [&]
    {
        g_mm->add_md(md);
    });
}

#ifdef CROSS_COMPILED

extern "C" void *
_malloc_r(struct _reent *reent, size_t size)
{
    (void) reent;

    if (auto ptr = static_cast<char *>(g_mm->malloc(size)))
    {
        for (auto i = 0ULL; i < size; i++)
            ptr[i] = 0;

        return ptr;
    }

    return nullptr;
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

#endif
