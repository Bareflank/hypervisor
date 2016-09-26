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

#ifndef MEM_POOL_H
#define MEM_POOL_H

#include <array>
#include <mutex>
#include <gsl/gsl>
#include <constants.h>

constexpr uintptr_t mem_pool_used_index = 0xFFFFFFFFFFFFFFFE;
constexpr uintptr_t mem_pool_free_index = 0xFFFFFFFFFFFFFFFF;

/// Memory Pool
///
/// The VMM has to manage a lot of memory. This includes:
/// - Heap for new / delete
/// - Page pool for new / delete
/// - Virtual memory space for mapping memory
/// - Guest memory
///
/// The problem is, some of these memory pools point to pre-allocated space
/// while others point to virtual memory that simply needs to be reserved for
/// memory mapping (classic alloc vs map problem). In all cases, a contiguous
/// memory space needs to be divided up and managed. This memory pool provides
/// a really simple "next fit" algorithm for managing these different memory
/// pools. Clearly there is room for improvement with this algorithm,
/// but it should work for basic allocations. Further optimizations could be
/// done using custom new / delete operators at the class level if needed
/// until we can provide a more complicated algorithm.
///
/// @param TS total size in bytes of the memory pool
/// @param BS block size in bit shifts (i.e. 8 bytes == 3 bits)
/// @param addr the starting address of the memory pool
///
/// @throws std::bad_alloc on failure
/// @return valid memory address on success
///
template<size_t TS, size_t BS>
class mem_pool
{
    static_assert(TS > 0, "total size must be larger than 0");
    static_assert(TS % (1 << BS) == 0, "total size must be a multiple of block size");
    static_assert(MAX_PAGE_SHIFT >= BS &&BS > 0, "block shift must be larger than 0");

public:
    mem_pool(uintptr_t addr) noexcept :
        m_addr(addr),
        m_size(TS >> BS)
    {
#ifdef CROSS_COMPILED
        uintptr_t end;

        if (__builtin_uaddl_overflow(m_addr, TS, &end))
            std::terminate();
#endif
        clear();
    }

    ~mem_pool() = default;

    mem_pool(const mem_pool &) = delete;
    mem_pool &operator=(const mem_pool &) = delete;
    mem_pool(mem_pool &&) noexcept = delete;
    mem_pool &operator=(mem_pool &&) noexcept = delete;

    uintptr_t alloc(uintptr_t size)
    {
        std::lock_guard<std::mutex> lock(m_mutex);

        uintptr_t start = 0;
        uintptr_t total = total_blocks(size);

        if (size == 0 || size > TS)
            throw std::bad_alloc();

        if ((start = next_search(m_next, total)) != mem_pool_used_index)
        {
            m_next = start + total;
            gsl::at(m_allocated, start) = total;

            return m_addr + (start << BS);
        }

        throw std::bad_alloc();
    }

    void free(uintptr_t addr) noexcept
    {
        std::lock_guard<std::mutex> lock(m_mutex);

        if (addr < m_addr)
            return;

        uintptr_t start = (addr - m_addr) >> BS;

        if (start >= m_allocated.size())
            return;

        gsl::at(m_allocated, start) = mem_pool_free_index;
    }

    bool contains(uintptr_t addr) const noexcept
    {
        return (addr >= m_addr && addr < m_addr + TS);
    }

    uintptr_t size(uintptr_t addr) noexcept
    {
        std::lock_guard<std::mutex> lock(m_mutex);

        if (!contains(addr))
            return 0;

        auto size = gsl::at(m_allocated, (addr - m_addr) >> BS);

        if (size == mem_pool_free_index)
            return 0;

        return size << BS;
    }

    void clear() noexcept
    {
        std::lock_guard<std::mutex> lock(m_mutex);

        m_next = 0;
        __builtin_memset(m_allocated.data(), 0xFF, sizeof(m_allocated));
    }

private:

    uintptr_t next_search(uintptr_t initial, uintptr_t total)
    {
        uintptr_t check = 0;
        uintptr_t count = 0;
        uintptr_t start = 0;
        uintptr_t index = initial;

        while (true)
        {
            if (index >= m_size)
            {
                count = 0;
                index = 0;
            }

            if (gsl::at(m_allocated, index) == mem_pool_free_index)
            {
                if (count == 0)
                    start = index;

                count++;
                index++;
                check++;
            }
            else
            {
                auto blocks = gsl::at(m_allocated, index);

                count = 0;
                index += blocks;
                check += blocks;
            }

            if (count >= total)
                return start;

            if (check >= (TS >> BS))
                return mem_pool_used_index;
        }
    }

    uintptr_t total_blocks(uintptr_t size) const noexcept
    {
        uintptr_t total = size >> BS;

        if ((size & ((1 << BS) - 1)) != 0)
            total++;

        return total;
    }

private:

    uintptr_t m_next;
    uintptr_t m_addr;
    uintptr_t m_size;

    std::array < uintptr_t, (TS >> BS) > m_allocated;

    mutable std::mutex m_mutex;
};

#endif
