//
// Copyright (C) 2019 Assured Information Security, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// TIDY_EXCLUSION=-cert-err58-cpp
//
// Reason:
//     This triggers a false positive WRT the allocators, which are marked
//     as noexcept, yet this check still thinks an exception could occur.
//

// TIDY_EXCLUSION=-cppcoreguidelines-pro-type-reinterpret-cast
//
// Reason:
//     Although in general this is a good rule, for hypervisor level code that
//     interfaces with the kernel, and raw hardware, this rule is
//     impractical.
//

#include <bfgsl.h>
#include <bfconstants.h>
#include <bfexception.h>
#include <bfupperlower.h>

#include <memory_manager/memory_manager.h>

// -----------------------------------------------------------------------------
// Mutexes
// -----------------------------------------------------------------------------

#include <mutex>

auto &md_mutex()
{
    static std::mutex s_md_mutex{};
    return s_md_mutex;
}

auto &alloc_mutex()
{
    static std::mutex s_alloc_mutex{};
    return s_alloc_mutex;
}

auto &alloc_page_mutex()
{
    static std::mutex s_alloc_page_mutex{};
    return s_alloc_page_mutex;
}

auto &alloc_mem_map_mutex()
{
    static std::mutex s_alloc_mem_map_mutex{};
    return s_alloc_mem_map_mutex;
}

// -----------------------------------------------------------------------------
// Stats
// -----------------------------------------------------------------------------

#if 0

struct stats_data_t {
    size_t size;
    size_t count;
};

int g_stats_index = 0;
stats_data_t g_stats_data[2048] = {};

extern "C" void
print_stats()
{
    char numstr[64]; \
    const char *str_text = "\033[1;32mDEBUG\033[0m: size = "; \
    const char *str_next = ", count = "; \
    const char *str_endl = "\n"; \

    for (int i = 0; i < g_stats_index; i++) {
        unsafe_write_cstr(str_text, strlen(str_text)); \
        bfitoa(g_stats_data[i].size, numstr, 16); \
        unsafe_write_cstr(numstr, strlen(numstr)); \
        unsafe_write_cstr(str_next, strlen(str_next)); \
        bfitoa(g_stats_data[i].count, numstr, 16); \
        unsafe_write_cstr(numstr, strlen(numstr)); \
        unsafe_write_cstr(str_endl, strlen(str_endl)); \
    }
}

inline void add_stats(size_t size)
{
    auto found = false;

    for (int i = 0; i < g_stats_index; i++) {
        if (g_stats_data[i].size == size) {
            found = true;
            g_stats_data[i].count++;
        }
    }

    if (!found) {
        g_stats_data[g_stats_index].size = size;
        g_stats_data[g_stats_index].count++;
        g_stats_index++;
    }
}

#endif

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

namespace bfvmm
{

// -----------------------------------------------------------------------------
// Global Memory
// -----------------------------------------------------------------------------

/// \cond

constexpr auto g_page_pool_k = PAGE_POOL_K;
alignas(BAREFLANK_PAGE_SIZE) uint8_t g_page_pool_buffer[buddy_allocator::buffer_size(g_page_pool_k)] = {};
alignas(BAREFLANK_PAGE_SIZE) uint8_t g_page_pool_node_tree[buddy_allocator::node_tree_size(g_page_pool_k)] = {};

constexpr auto g_huge_pool_k = HUGE_POOL_K;
alignas(BAREFLANK_PAGE_SIZE) uint8_t g_huge_pool_buffer[buddy_allocator::buffer_size(g_huge_pool_k)] = {};
alignas(BAREFLANK_PAGE_SIZE) uint8_t g_huge_pool_node_tree[buddy_allocator::node_tree_size(g_huge_pool_k)] = {};

constexpr auto g_mem_map_pool_k = MEM_MAP_POOL_K;
alignas(BAREFLANK_PAGE_SIZE) uint8_t g_mem_map_pool_node_tree[buddy_allocator::node_tree_size(g_mem_map_pool_k)] = {};

/// \endcond

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
    std::lock_guard<std::mutex> lock(alloc_mutex());

    if (size == 0) {
        return nullptr;
    }

    try {
        if (size <= 0x010) {
            return slab010.allocate();
        }

        if (size <= 0x020) {
            return slab020.allocate();
        }

        if (size <= 0x030) {
            return slab030.allocate();
        }

        if (size <= 0x040) {
            return slab040.allocate();
        }

        if (size <= 0x080) {
            return slab080.allocate();
        }

        if (size <= 0x100) {
            return slab100.allocate();
        }

        if (size <= 0x200) {
            return slab200.allocate();
        }

        if (size <= 0x400) {
            return slab400.allocate();
        }

        if (size <= 0x800) {
            return slab800.allocate();
        }

        if (size > BAREFLANK_PAGE_SIZE) {
            return static_cast<pointer>(g_huge_pool.allocate(size));
        }

        return alloc_page();
    }
    catch (...)
    { WARNING("memory_manager::alloc: std::bad_alloc thrown"); }

    return nullptr;
}

memory_manager::pointer
memory_manager::alloc_page() noexcept
{
#ifdef ENABLE_BUILD_TEST
    return static_cast<pointer>(g_page_pool.allocate(BAREFLANK_PAGE_SIZE));
#else
    std::lock_guard<std::mutex> lock(alloc_page_mutex());

    try {
        return static_cast<pointer>(g_page_pool.allocate(BAREFLANK_PAGE_SIZE));
    }
    catch (...)
    { WARNING("memory_manager::alloc_page: std::bad_alloc thrown"); }

    return nullptr;
#endif
}

memory_manager::pointer
memory_manager::alloc_map(size_type size) noexcept
{
    std::lock_guard<std::mutex> lock(alloc_mem_map_mutex());

    try {
        return reinterpret_cast<pointer>(g_mem_map_pool.allocate(size));
    }
    catch (...)
    { WARNING("memory_manager::alloc_map: std::bad_alloc thrown"); }

    return nullptr;
}

void
memory_manager::free(pointer ptr) noexcept
{
    std::lock_guard<std::mutex> lock(alloc_mutex());

    if (slab010.contains(ptr)) {
        return slab010.deallocate(ptr);
    }

    if (slab020.contains(ptr)) {
        return slab020.deallocate(ptr);
    }

    if (slab030.contains(ptr)) {
        return slab030.deallocate(ptr);
    }

    if (slab040.contains(ptr)) {
        return slab040.deallocate(ptr);
    }

    if (slab080.contains(ptr)) {
        return slab080.deallocate(ptr);
    }

    if (slab100.contains(ptr)) {
        return slab100.deallocate(ptr);
    }

    if (slab200.contains(ptr)) {
        return slab200.deallocate(ptr);
    }

    if (slab400.contains(ptr)) {
        return slab400.deallocate(ptr);
    }

    if (slab800.contains(ptr)) {
        return slab800.deallocate(ptr);
    }

    if (g_huge_pool.contains(ptr)) {
        return g_huge_pool.deallocate(ptr);
    }

    free_page(ptr);
}

void
memory_manager::free_page(pointer ptr) noexcept
{
    std::lock_guard<std::mutex> lock(alloc_page_mutex());
    return g_page_pool.deallocate(ptr);
}

void
memory_manager::free_map(pointer ptr) noexcept
{
    std::lock_guard<std::mutex> lock(alloc_mem_map_mutex());
    return g_mem_map_pool.deallocate(ptr);
}

memory_manager::size_type
memory_manager::size(pointer ptr) const noexcept
{
    std::lock_guard<std::mutex> lock(alloc_mutex());

    if (slab010.contains(ptr)) {
        return slab010.size(ptr);
    }

    if (slab020.contains(ptr)) {
        return slab020.size(ptr);
    }

    if (slab030.contains(ptr)) {
        return slab030.size(ptr);
    }

    if (slab040.contains(ptr)) {
        return slab040.size(ptr);
    }

    if (slab080.contains(ptr)) {
        return slab080.size(ptr);
    }

    if (slab100.contains(ptr)) {
        return slab100.size(ptr);
    }

    if (slab200.contains(ptr)) {
        return slab200.size(ptr);
    }

    if (slab400.contains(ptr)) {
        return slab400.size(ptr);
    }

    if (slab800.contains(ptr)) {
        return slab800.size(ptr);
    }

    if (g_huge_pool.contains(ptr)) {
        return g_huge_pool.size(ptr);
    }

    return size_page(ptr);
}

memory_manager::size_type
memory_manager::size_page(pointer ptr) const noexcept
{
    std::lock_guard<std::mutex> lock(alloc_page_mutex());

    if (g_page_pool.contains(ptr)) {
        return g_page_pool.size(ptr);
    }

    return 0;
}

memory_manager::size_type
memory_manager::size_map(pointer ptr) const noexcept
{
    std::lock_guard<std::mutex> lock(alloc_mem_map_mutex());

    if (g_mem_map_pool.contains(ptr)) {
        return g_mem_map_pool.size(ptr);
    }

    return 0;
}

memory_manager::integer_pointer
memory_manager::virtint_to_physint(integer_pointer virt) const
{
    auto lower = bfn::lower(virt);
    auto upper = bfn::upper(virt);

    std::lock_guard<std::mutex> guard(md_mutex());

    if (auto iter = m_virt_map.find(upper); iter != m_virt_map.end()) {
        return iter->second.phys | lower;
    }

    throw std::runtime_error(
        "virtint_to_physint failed: " + bfn::to_string(virt, 16)
    );
}

memory_manager::integer_pointer
memory_manager::virtptr_to_physint(const pointer virt) const
{ return this->virtint_to_physint(reinterpret_cast<integer_pointer>(virt)); }

memory_manager::pointer
memory_manager::virtint_to_physptr(integer_pointer virt) const
{ return reinterpret_cast<pointer>(this->virtint_to_physint(virt)); }

memory_manager::pointer
memory_manager::virtptr_to_physptr(const pointer virt) const
{ return reinterpret_cast<pointer>(this->virtptr_to_physint(virt)); }

memory_manager::integer_pointer
memory_manager::physint_to_virtint(integer_pointer phys) const
{
    auto lower = bfn::lower(phys);
    auto upper = bfn::upper(phys);

    std::lock_guard<std::mutex> guard(md_mutex());

    if (auto iter = m_phys_map.find(upper); iter != m_phys_map.end()) {
        return iter->second.virt | lower;
    }

    throw std::runtime_error(
        "physint_to_virtint failed: " + bfn::to_string(phys, 16)
    );
}

memory_manager::integer_pointer
memory_manager::physptr_to_virtint(const pointer phys) const
{ return this->physint_to_virtint(reinterpret_cast<integer_pointer>(phys)); }

memory_manager::pointer
memory_manager::physint_to_virtptr(integer_pointer phys) const
{ return reinterpret_cast<pointer>(this->physint_to_virtint(phys)); }

memory_manager::pointer
memory_manager::physptr_to_virtptr(const pointer phys) const
{ return reinterpret_cast<pointer>(this->physptr_to_virtint(phys)); }

void
memory_manager::add_md(integer_pointer virt, integer_pointer phys, attr_type attr)
{
    auto ___ = gsl::on_failure([&] {
        std::lock_guard<std::mutex> guard(md_mutex());

        m_virt_map.erase(virt);
        m_phys_map.erase(phys);
    });

    expects(bfn::lower(virt) == 0);
    expects(bfn::lower(phys) == 0);

    {
        std::lock_guard<std::mutex> guard(md_mutex());

        if (m_virt_map.find(virt) != m_virt_map.end()) {
            throw std::runtime_error(
                "memory_manager::add_md: virt already added: " + bfn::to_string(virt, 16)
            );
        }

        if (m_phys_map.find(phys) != m_phys_map.end()) {
            throw std::runtime_error(
                "memory_manager::add_md: phys already added: " + bfn::to_string(phys, 16)
            );
        }

        m_virt_map[virt] = {phys, attr};
        m_phys_map[phys] = {virt, attr};
    }
}

void
memory_manager::remove_md(integer_pointer virt, integer_pointer phys)
{
    expects(bfn::lower(virt) == 0);
    expects(bfn::lower(phys) == 0);

    {
        std::lock_guard<std::mutex> guard(md_mutex());

        m_virt_map.erase(virt);
        m_phys_map.erase(phys);
    }
}

memory_manager::memory_descriptor_list
memory_manager::descriptors() const
{
    memory_descriptor_list list;
    std::lock_guard<std::mutex> guard(md_mutex());

    for (const auto &p : m_virt_map) {
        list.push_back({p.second.phys, p.first, p.second.attr});
    }

    return list;
}

memory_manager::memory_manager() noexcept :
    g_page_pool(static_cast<void *>(g_page_pool_buffer), g_page_pool_k, static_cast<void *>(g_page_pool_node_tree)),
    g_huge_pool(static_cast<void *>(g_huge_pool_buffer), g_huge_pool_k, static_cast<void *>(g_huge_pool_node_tree)),
    g_mem_map_pool(MEM_MAP_POOL_START, g_mem_map_pool_k, static_cast<void *>(g_mem_map_pool_node_tree)),
    slab010(0x010, 0),
    slab020(0x020, 0),
    slab030(0x030, 0),
    slab040(0x040, 0),
    slab080(0x080, 0),
    slab100(0x100, 0),
    slab200(0x200, 0),
    slab400(0x400, 0),
    slab800(0x800, 0)
{ }

}

#ifdef VMM

extern "C" void *
_malloc_r(struct _reent *ent, size_t size)
{
    bfignored(ent);
    return g_mm->alloc(size);
}

extern "C" void
_free_r(struct _reent *ent, void *ptr)
{
    bfignored(ent);
    g_mm->free(ptr);
}

extern "C" void *
_calloc_r(struct _reent *ent, size_t nmemb, size_t size)
{
    bfignored(ent);

    if (auto ptr = g_mm->alloc(nmemb * size)) {
        return memset(ptr, 0, nmemb * size);
    }

    return nullptr;
}

extern "C" void *
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

extern "C" void *
alloc_page()
{ return memset(g_mm->alloc_page(), 0, BAREFLANK_PAGE_SIZE); }

extern "C" void
free_page(void *ptr)
{ g_mm->free_page(ptr); }

#endif
