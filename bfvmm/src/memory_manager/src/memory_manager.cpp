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

#include <array>
#include <limits>
#include <gsl/gsl>

#include <debug.h>
#include <constants.h>
#include <guard_exceptions.h>
#include <memory_manager/memory_manager.h>

// -----------------------------------------------------------------------------
// Macros
// -----------------------------------------------------------------------------

#define ALLOCATED 0x8000000000000000ULL

// -----------------------------------------------------------------------------
// Global Memory
// -----------------------------------------------------------------------------

struct mmpage_t
{ uint8_t mem[MAX_PAGE_SIZE]; };

uint64_t g_heap_pool_owner[MAX_HEAP_POOL] __attribute__((aligned(MAX_PAGE_SIZE))) = {};
gsl::span<uint64_t> g_heap_pool{g_heap_pool_owner};

mmpage_t g_page_pool_owner[MAX_PAGE_POOL] __attribute__((aligned(MAX_PAGE_SIZE))) = {};
gsl::span<mmpage_t> g_page_pool{g_page_pool_owner};

uint64_t g_page_allocated_owner[MAX_PAGE_POOL] __attribute__((aligned(MAX_PAGE_SIZE))) = {};
gsl::span<uint64_t> g_page_allocated{g_page_allocated_owner};

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

void *
memory_manager::malloc(size_t size) noexcept
{
    if (size == 0)
        return nullptr;

    if (size > static_cast<size_t>(std::numeric_limits<int64_t>::max()))
        return nullptr;

    // We ensure that when allocating memory that if it is a multiple of a page,
    // we use the page pool instead of the heap. The page pool is page aligned
    // which is needed for a lot of tasks.
    //
    // Note that when creating a shared_ptr, the reference counter is allocated
    // with the memory which means that if you std::make_shared<page>() you
    // will allocate more than a page, resulting in unaligned memory. The
    // solution to this is to new the memory, and pass the resulting ptr to
    // share_ptr constructor (which will create it's own reference on it's own)
    //
    // Note the heap uses a header to keep track of each segment, while the
    // page pool uses a seperate allocated buffer. The page pool needs it's
    // own buffer to ensure each page is page aligned.

    if ((size & (MAX_PAGE_SIZE - 1)) == 0)
        return malloc_page(static_cast<int64_t>(size));

    return malloc_heap(static_cast<int64_t>(size));
}

void
memory_manager::free(void *ptr) noexcept
{
    if (ptr == nullptr)
        return;

    if (g_heap_pool.contains(static_cast<uint64_t *>(ptr)))
        free_heap(ptr);

    if (g_page_pool.contains(static_cast<mmpage_t *>(ptr)))
        free_page(ptr);
}

uintptr_t
memory_manager::virtint_to_physint(uintptr_t virt)
{
    std::lock_guard<std::mutex> guard(g_add_md_mutex);

    const auto &md_iter = m_virt_to_phys_map.find(virt >> MAX_PAGE_SHIFT);

    if (md_iter == m_virt_to_phys_map.end())
        return 0;

    auto upper = md_iter->second.phys & ~(MAX_PAGE_SIZE - 1);
    auto lower = virt & (MAX_PAGE_SIZE - 1);

    return upper | lower;
}

uintptr_t
memory_manager::virtptr_to_physint(void *virt)
{
    return this->virtint_to_physint(reinterpret_cast<uintptr_t>(virt));
}

void *
memory_manager::virtint_to_physptr(uintptr_t virt)
{
    return reinterpret_cast<void *>(this->virtint_to_physint(virt));
}

void *
memory_manager::virtptr_to_physptr(void *virt)
{
    return reinterpret_cast<void *>(this->virtptr_to_physint(virt));
}

uintptr_t
memory_manager::physint_to_virtint(uintptr_t phys)
{
    std::lock_guard<std::mutex> guard(g_add_md_mutex);

    const auto &md_iter = m_phys_to_virt_map.find(phys >> MAX_PAGE_SHIFT);

    if (md_iter == m_phys_to_virt_map.end())
        return 0;

    auto upper = md_iter->second.virt & ~(MAX_PAGE_SIZE - 1);
    auto lower = phys & (MAX_PAGE_SIZE - 1);

    return upper | lower;
}

uintptr_t
memory_manager::physptr_to_virtint(void *phys)
{
    return this->physint_to_virtint(reinterpret_cast<uintptr_t>(phys));
}

void *
memory_manager::physint_to_virtptr(uintptr_t phys)
{
    return reinterpret_cast<void *>(this->physint_to_virtint(phys));
}

void *
memory_manager::physptr_to_virtptr(void *phys)
{
    return reinterpret_cast<void *>(this->physptr_to_virtint(phys));
}

void *
memory_manager::malloc_heap(int64_t size) noexcept
{
    int64_t blocks = (size & (0x7)) != 0 ? (size >> 3) + 2 : (size >> 3) + 1;

    if (blocks > g_heap_pool.size())
        return nullptr;

    std::lock_guard<std::mutex> guard(g_malloc_mutex);

    int64_t sidx = m_heap_index;
    int64_t cidx = m_heap_index;
    int64_t fragment_size = 0;

    auto fa1 = gsl::finally([&]
    {
        m_heap_index = sidx + blocks;
    });

    auto fa2 = gsl::finally([&]
    {
        g_heap_pool[sidx] = static_cast<uint64_t>(blocks) | ALLOCATED;
    });

    while (cidx < g_heap_pool.size() && sidx + blocks <= g_heap_pool.size())
    {
        if (g_heap_pool[cidx] == 0)
            return &g_heap_pool[sidx + 1];

        auto allocated = ((g_heap_pool[cidx] & ALLOCATED) == 0);

        if (allocated)
        {
            fragment_size += static_cast<int64_t>(g_heap_pool[cidx]);

            if (fragment_size == blocks)
                return &g_heap_pool[sidx + 1];

            if (fragment_size < blocks)
                fa1.ignore();

            if (fragment_size > blocks)
            {
                g_heap_pool[sidx + blocks] = static_cast<uint64_t>(fragment_size - blocks);
                return &g_heap_pool[sidx + 1];
            }
        }

        cidx += static_cast<int64_t>(g_heap_pool[cidx] & ~ALLOCATED);

        if (!allocated)
        {
            sidx = cidx;
            fragment_size = 0;
        }
    }

    fa1.ignore();
    fa2.ignore();

    return nullptr;
}

void *
memory_manager::malloc_page(int64_t size) noexcept
{
    int64_t pages = size >> 12;

    if (pages > g_page_allocated.size())
        return nullptr;

    std::lock_guard<std::mutex> guard(g_malloc_mutex);

    int64_t sidx = m_page_index;
    int64_t cidx = m_page_index;
    int64_t fragment_size = 0;

    auto fa1 = gsl::finally([&]
    {
        m_page_index = sidx + pages;
    });

    auto fa2 = gsl::finally([&]
    {
        g_page_allocated[sidx] = static_cast<uint64_t>(pages) | ALLOCATED;
    });

    while (cidx < g_page_pool.size() && sidx + pages <= g_page_pool.size())
    {
        if (g_page_allocated[cidx] == 0)
            return &g_page_pool[sidx];

        auto allocated = ((g_page_allocated[cidx] & ALLOCATED) == 0);

        if (allocated)
        {
            fragment_size += static_cast<int64_t>(g_page_allocated[cidx]);

            if (fragment_size == pages)
                return &g_page_pool[sidx];

            if (fragment_size < pages)
                fa1.ignore();

            if (fragment_size > pages)
            {
                g_page_allocated[sidx + pages] = static_cast<uint64_t>(fragment_size - pages);
                return &g_page_pool[sidx];
            }
        }

        cidx += static_cast<int64_t>(g_page_allocated[cidx] & ~ALLOCATED);

        if (!allocated)
        {
            sidx = cidx;
            fragment_size = 0;
        }
    }

    fa1.ignore();
    fa2.ignore();

    return nullptr;
}

void
memory_manager::free_heap(void *ptr) noexcept
{
    auto idx = g_heap_pool.index_from_ptr(static_cast<uint64_t *>(ptr)) - 1;

    g_heap_pool[idx] &= ~ALLOCATED;

    if (m_heap_index > idx)
        m_heap_index = idx;
}
void
memory_manager::free_page(void *ptr) noexcept
{
    auto idx = g_page_pool.index_from_ptr(static_cast<mmpage_t *>(ptr));

    g_page_allocated[idx] &= ~ALLOCATED;

    if (m_page_index > idx)
        m_page_index = idx;
}

void
memory_manager::add_md(memory_descriptor *md)
{
    if (md == nullptr)
        throw std::invalid_argument("md == NULL");

    if (md->virt == 0)
        throw std::invalid_argument("md->virt == 0");

    if (md->phys == 0)
        throw std::invalid_argument("md->phys == 0");

    if ((reinterpret_cast<uintptr_t>(md->virt) & (MAX_PAGE_SIZE - 1)) != 0)
        throw std::logic_error("virt address is not page aligned");

    if ((reinterpret_cast<uintptr_t>(md->phys) & (MAX_PAGE_SIZE - 1)) != 0)
        throw std::logic_error("phys address is not page aligned");

    auto fa1 = gsl::finally([&]
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

    fa1.ignore();
}

void
memory_manager::clear() noexcept
{
    m_heap_index = 0;
    m_page_index = 0;

    __builtin_memset(static_cast<void *>(g_heap_pool_owner), 0, MAX_HEAP_POOL * sizeof(uint64_t));
    __builtin_memset(static_cast<void *>(g_page_pool_owner), 0, MAX_PAGE_POOL * sizeof(mmpage_t));
    __builtin_memset(static_cast<void *>(g_page_allocated_owner), 0, MAX_PAGE_POOL * sizeof(uint64_t));
}

memory_manager::memory_manager() noexcept :
    m_heap_index(0),
    m_page_index(0)
{
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

    if (auto ptr = g_mm->malloc(size))
        return __builtin_memset(ptr, 0, size);

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
