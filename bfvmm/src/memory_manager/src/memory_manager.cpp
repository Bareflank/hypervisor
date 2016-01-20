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

#include <constants.h>
#include <memory_manager/memory_manager.h>

// -----------------------------------------------------------------------------
// Macros
// -----------------------------------------------------------------------------

#define FREE_BLOCK (-1)

// -----------------------------------------------------------------------------
// GLobal Memory
// -----------------------------------------------------------------------------

// The following defines the entire memory pool. This pool will be used by the
// VMM to create the different resources that it needs, which is mainly given
// out using new/delete. If space runs out, this will need to be increased.
uint8_t g_mem_pool[MAX_MEM_POOL] ALIGN = {0};

// The memory pool itself is given out in blocks. Any attempt to new / delete
// will always allocate at least a block of memory, which is usually set to a
// cache line size. This stores whether a block is allocated or not. Note that
// the way we know if a block is allocated, is it's not set to FREE_BLOCK.
// We use the value stored here to tell us what the starting address is when a
// block is allocated. This greatly simplifies freeing memory at the expense of
// a lot of memory needed to manage memory.
int64_t g_block_allocated[MAX_BLOCKS] = {0};

// A memory descriptor stores information about each page of memory. The
// memory manager will use this information to provide trnaslations for the rest
// of the VMM. For example, if the VMM needs to know the physical address of a
// virtual address, it can ask the memory manager, which provides this
// information using the MDLs.
struct memory_descriptor g_mdl[MAX_NUM_MEMORY_DESCRIPTORS] = {0, 0, 0, 0};

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

    for (auto i = 0; i < MAX_BLOCKS; i++)
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

    int64_t count = 0;
    int64_t block = 0;
    int64_t reset = 0;
    int64_t num_blocks = size / MAX_CACHE_LINE_SIZE;

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
        for (auto b = block;  b < MAX_BLOCKS && b < num_blocks + block; b++)
            g_block_allocated[b] = block;

        return block_to_virt(block);
    }

    return 0;
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

    if (block < 0 || block >= MAX_BLOCKS)
        return;

    auto start = g_block_allocated[block];

    if (start < 0 || start >= MAX_BLOCKS)
        return;

    for (auto b = start; b < MAX_BLOCKS; b++)
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
    if (block >= MAX_BLOCKS)
        return 0;

    return g_mem_pool + (block * MAX_CACHE_LINE_SIZE);
}

void *
memory_manager::virt_to_phys(void *virt)
{
    (void) virt;

    return 0;
}

void *
memory_manager::phys_to_virt(void *phys)
{
    (void) phys;

    return 0;
}

int64_t
memory_manager::virt_to_block(void *virt)
{
    if (virt >= g_mem_pool + MAX_MEM_POOL)
        return -1;

    return ((uint8_t *)virt - g_mem_pool) / MAX_CACHE_LINE_SIZE;
}

bool
memory_manager::is_block_aligned(int64_t block, int64_t alignment)
{
    if (block >= MAX_BLOCKS)
        return false;

    if (alignment <= 0)
        return true;

    return ((uint64_t)block_to_virt(block) % alignment) == 0;
}

int64_t
memory_manager::add_mdl(struct memory_descriptor *mdl, int64_t num)
{
    (void) mdl;
    (void) num;

    return MEMORY_MANAGER_SUCCESS;
}

memory_manager::memory_manager()
{
    m_start = 0;

    for (auto i = 0; i < MAX_MEM_POOL; i++)
        g_mem_pool[i] = 0;

    for (auto i = 0; i < MAX_BLOCKS; i++)
        g_block_allocated[i] = FREE_BLOCK;

    for (auto i = 0; i < MAX_NUM_MEMORY_DESCRIPTORS; i++)
        g_mdl[i] = {0, 0, 0, 0};
}

int64_t
add_mdl_trampoline(struct memory_descriptor *mdl, int64_t num)
{
    return g_mm->add_mdl(mdl, num);
}

extern "C" long long int
add_mdl(struct memory_descriptor *mdl, long long int num)
{
    return add_mdl_trampoline(mdl, num);
}

extern "C" void *
_malloc_r(size_t size)
{
    size_t i;
    char *ptr = (char *)g_mm->malloc(size);

    if (ptr != NULL)
    {
        // Per the spec, you are not supposed to zero out memory for malloc,
        // but we do anyways just to me on the safe side.
        for (i = 0; i < size; i++)
            ptr[i] = 0;
    }

    return ptr;
}

extern "C" void
_free_r(void *ptr)
{
    g_mm->free(ptr);
}

extern "C" void *
_calloc_r(size_t nmemb, size_t size)
{
    return _malloc_r(nmemb * size);
}

extern "C" void *
_realloc_r(void *ptr, size_t size)
{
    _free_r(ptr);
    return _malloc_r(size);
}
