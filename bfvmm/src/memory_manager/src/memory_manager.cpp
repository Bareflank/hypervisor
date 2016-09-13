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

#include <gsl/gsl>

#include <constants.h>
#include <guard_exceptions.h>
#include <memory_manager/memory_manager.h>

#include <memory_manager/mem_pool.h>

// -----------------------------------------------------------------------------
// Global Memory
// -----------------------------------------------------------------------------

uint8_t g_heap_pool_owner[MAX_HEAP_POOL] __attribute__((aligned(MAX_PAGE_SIZE))) = {};
mem_pool<MAX_HEAP_POOL, MAX_CACHE_LINE_SHIFT> g_heap_pool(reinterpret_cast<uintptr_t>(g_heap_pool_owner));

uint8_t g_page_pool_owner[MAX_PAGE_POOL] __attribute__((aligned(MAX_PAGE_SIZE))) = {};
mem_pool<MAX_PAGE_POOL, MAX_PAGE_SHIFT> g_page_pool(reinterpret_cast<uintptr_t>(g_page_pool_owner));

// -----------------------------------------------------------------------------
// Mutexes
// -----------------------------------------------------------------------------

#include <mutex>
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
memory_manager::alloc(size_t size) noexcept
{
    try
    {
        if ((size & (MAX_PAGE_SIZE - 1)) == 0)
            return reinterpret_cast<void *>(g_page_pool.alloc(size));

        return reinterpret_cast<void *>(g_heap_pool.alloc(size));
    }
    catch (...)
    {
        return nullptr;
    }
}

void
memory_manager::free(void *ptr) noexcept
{
    auto uintptr = reinterpret_cast<uintptr_t>(ptr);

    if (g_heap_pool.contains(uintptr))
        g_heap_pool.free(reinterpret_cast<uintptr_t>(ptr));

    if (g_page_pool.contains(uintptr))
        g_page_pool.free(reinterpret_cast<uintptr_t>(ptr));
}

uintptr_t
memory_manager::size(void *ptr) const noexcept
{
    auto uintptr = reinterpret_cast<uintptr_t>(ptr);

    if (g_heap_pool.contains(uintptr))
        return g_heap_pool.size(uintptr);

    if (g_page_pool.contains(uintptr))
        return g_page_pool.size(uintptr);

    return 0;
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

    auto ___ = gsl::on_failure([&]
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
_malloc_r(struct _reent *, size_t size)
{
    return g_mm->alloc(size);
}

extern "C" void
_free_r(struct _reent *, void *ptr)
{
    g_mm->free(ptr);
}

extern "C" void *
_calloc_r(struct _reent *, size_t nmemb, size_t size)
{
    if (auto ptr = g_mm->alloc(nmemb * size))
        return __builtin_memset(ptr, 0, nmemb * size);

    return nullptr;
}

extern "C" void *
_realloc_r(struct _reent *, void *ptr, size_t size)
{
    auto old_sze = g_mm->size(ptr);
    auto new_ptr = g_mm->alloc(size);

    if (!new_ptr || old_sze == 0)
        return nullptr;

    if (ptr)
    {
        __builtin_memcpy(new_ptr, ptr, size > old_sze ? old_sze : size);
        g_mm->free(ptr);
    }

    return new_ptr;
}

#endif
