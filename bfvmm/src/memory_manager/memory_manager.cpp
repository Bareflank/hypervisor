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

#include <bfgsl.h>
#include <bfconstants.h>
#include <bfexception.h>

#include <memory_manager/mem_pool.h>
#include <memory_manager/memory_manager.h>
#include <memory_manager/arch/x64/map_ptr.h>
#include <memory_manager/arch/x64/page_table.h>

namespace bfvmm
{

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

constexpr const auto page_size = 0x1000ULL;

// -----------------------------------------------------------------------------
// Global Memory
// -----------------------------------------------------------------------------

/// \cond

alignas(page_size) uint8_t g_heap_pool_owner[MAX_HEAP_POOL] = {};
alignas(page_size) uint8_t g_page_pool_owner[MAX_PAGE_POOL] = {};

/// \endcond

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
    // [[ensures ret: ret != nullptr]]

    static memory_manager self;
    return &self;
}

memory_manager::pointer
memory_manager::alloc(size_type size) noexcept
{
    if (size == 0) {
        return nullptr;
    }

    try {
        if (lower(size) == 0) {
            return reinterpret_cast<pointer>(g_page_pool.alloc(size));
        }

        return reinterpret_cast<pointer>(g_heap_pool.alloc(size));
    }
    catch (...)
    { }

    return nullptr;
}

memory_manager::pointer
memory_manager::alloc_map(size_type size) noexcept
{
    if (size == 0) {
        return nullptr;
    }

    try {
        return reinterpret_cast<pointer>(g_mem_map_pool.alloc(size));
    }
    catch (...)
    { }

    return nullptr;
}

void
memory_manager::free(pointer ptr) noexcept
{
    auto uintptr = reinterpret_cast<integer_pointer>(ptr);

    if (g_heap_pool.contains(uintptr)) {
        return g_heap_pool.free(uintptr);
    }

    if (g_page_pool.contains(uintptr)) {
        return g_page_pool.free(uintptr);
    }
}

void
memory_manager::free_map(pointer ptr) noexcept
{
    auto uintptr = reinterpret_cast<integer_pointer>(ptr);

    if (g_mem_map_pool.contains(uintptr)) {
        return g_mem_map_pool.free(uintptr);
    }
}

memory_manager::size_type
memory_manager::size(pointer ptr) const noexcept
{
    auto uintptr = reinterpret_cast<integer_pointer>(ptr);

    if (g_heap_pool.contains(uintptr)) {
        return g_heap_pool.size(uintptr);
    }

    if (g_page_pool.contains(uintptr)) {
        return g_page_pool.size(uintptr);
    }

    return 0;
}

memory_manager::size_type
memory_manager::size_map(pointer ptr) const noexcept
{
    auto uintptr = reinterpret_cast<integer_pointer>(ptr);

    if (g_mem_map_pool.contains(uintptr)) {
        return g_mem_map_pool.size(uintptr);
    }

    return 0;
}

memory_manager::integer_pointer
memory_manager::virtint_to_physint(integer_pointer virt) const
{
    // [[ensures ret: ret != 0]]
    expects(virt != 0);

    std::lock_guard<std::mutex> guard(g_add_md_mutex);
    return upper(m_virt_to_phys_map.at(upper(virt))) | lower(virt);
}

memory_manager::integer_pointer
memory_manager::virtptr_to_physint(pointer virt) const
{ return this->virtint_to_physint(reinterpret_cast<integer_pointer>(virt)); }

memory_manager::pointer
memory_manager::virtint_to_physptr(integer_pointer virt) const
{ return reinterpret_cast<pointer>(this->virtint_to_physint(virt)); }

memory_manager::pointer
memory_manager::virtptr_to_physptr(pointer virt) const
{ return reinterpret_cast<pointer>(this->virtptr_to_physint(virt)); }

memory_manager::integer_pointer
memory_manager::physint_to_virtint(integer_pointer phys) const
{
    // [[ensures ret: ret != 0]]
    expects(phys != 0);

    std::lock_guard<std::mutex> guard(g_add_md_mutex);
    return upper(m_phys_to_virt_map.at(upper(phys))) | lower(phys);
}

memory_manager::integer_pointer
memory_manager::physptr_to_virtint(pointer phys) const
{ return this->physint_to_virtint(reinterpret_cast<integer_pointer>(phys)); }

memory_manager::pointer
memory_manager::physint_to_virtptr(integer_pointer phys) const
{ return reinterpret_cast<pointer>(this->physint_to_virtint(phys)); }

memory_manager::pointer
memory_manager::physptr_to_virtptr(pointer phys) const
{ return reinterpret_cast<pointer>(this->physptr_to_virtint(phys)); }

memory_manager::attr_type
memory_manager::virtint_to_attrint(integer_pointer virt) const
{
    expects(virt != 0);

    std::lock_guard<std::mutex> guard(g_add_md_mutex);
    return m_virt_to_attr_map.at(upper(virt));
}

memory_manager::attr_type
memory_manager::virtptr_to_attrint(pointer virt) const
{ return this->virtint_to_attrint(reinterpret_cast<integer_pointer>(virt)); }

void
memory_manager::add_md(integer_pointer virt, integer_pointer phys, attr_type attr)
{
    auto ___ = gsl::on_failure([&] {
        std::lock_guard<std::mutex> guard(g_add_md_mutex);

        m_virt_to_phys_map.erase(virt);
        m_phys_to_virt_map.erase(phys);
        m_virt_to_attr_map.erase(virt);
    });

    expects(attr != 0);
    expects(lower(virt) == 0);
    expects(lower(phys) == 0);

    {
        std::lock_guard<std::mutex> guard(g_add_md_mutex);

        m_virt_to_phys_map[virt] = phys;
        m_phys_to_virt_map[phys] = virt;
        m_virt_to_attr_map[virt] = attr;
    }
}

void
memory_manager::remove_md(integer_pointer virt) noexcept
{
    integer_pointer phys;

    if (virt == 0) {
        bfalert_info(0, "memory_manager::remove_md: virt == 0");
        return;
    }

    if (lower(virt) != 0) {
        bfalert_nhex(0, "memory_manager::remove_md: lower(virt) != 0", lower(virt));
        return;
    }

    guard_exceptions([&] {
        phys = virtint_to_physint(virt);
        std::lock_guard<std::mutex> guard(g_add_md_mutex);

        m_virt_to_phys_map.erase(virt);
        m_phys_to_virt_map.erase(phys);
        m_virt_to_attr_map.erase(virt);
    });
}

memory_manager::memory_descriptor_list
memory_manager::descriptors() const
{
    memory_descriptor_list list;
    std::lock_guard<std::mutex> guard(g_add_md_mutex);

    for (const auto &p : m_virt_to_phys_map) {
        auto virt = p.first;
        auto phys = p.second;
        auto attr = m_virt_to_attr_map.at(virt);

        list.push_back({phys, virt, attr});
    }

    return list;
}

memory_manager::memory_manager() noexcept :
    g_heap_pool(reinterpret_cast<uintptr_t>(g_heap_pool_owner)),
    g_page_pool(reinterpret_cast<uintptr_t>(g_page_pool_owner)),
    g_mem_map_pool(MEM_MAP_POOL_START)
{ }

memory_manager::integer_pointer
memory_manager::lower(integer_pointer ptr) const noexcept
{ return ptr & (page_size - 1); }

memory_manager::integer_pointer
memory_manager::upper(integer_pointer ptr) const noexcept
{ return ptr & ~(page_size - 1); }

}

#ifdef VMM

extern "C" EXPORT_SYM void *
_malloc_r(struct _reent *ent, size_t size)
{
    bfignored(ent);
    return g_mm->alloc(size);
}

extern "C" EXPORT_SYM void
_free_r(struct _reent *ent, void *ptr)
{
    bfignored(ent);
    g_mm->free(ptr);
}

extern "C" EXPORT_SYM void *
_calloc_r(struct _reent *ent, size_t nmemb, size_t size)
{
    bfignored(ent);

    if (auto ptr = g_mm->alloc(nmemb * size)) {
        return memset(ptr, 0, nmemb * size);
    }

    return nullptr;
}

extern "C" EXPORT_SYM void *
_realloc_r(struct _reent *ent, void *ptr, size_t size)
{
    bfignored(ent);

    auto old_sze = g_mm->size(ptr);
    auto new_ptr = g_mm->alloc(size);

    if (new_ptr == nullptr || old_sze == 0) {
        return nullptr;
    }

    if (ptr != nullptr) {
        memcpy(new_ptr, ptr, size > old_sze ? old_sze : size);
        g_mm->free(ptr);
    }

    return new_ptr;
}

#endif
