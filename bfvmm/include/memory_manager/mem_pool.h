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

#include <gsl/gsl>

#include <mutex>
#include <array>

#include <constants.h>

// -----------------------------------------------------------------------------
// Testing Switch
// -----------------------------------------------------------------------------

#ifdef TESTING_MEM_POOL
#define noexcept_testing
#define static_construction_error() throw std::logic_error("static_construction_error")
#else
#define noexcept_testing noexcept
#define static_construction_error() std::terminate()
#endif

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

constexpr const auto mem_pool_used_index = 0xFFFFFFFFFFFFFFFEUL;
constexpr const auto mem_pool_free_index = 0xFFFFFFFFFFFFFFFFUL;

// -----------------------------------------------------------------------------
// Definition
// -----------------------------------------------------------------------------

///
/// *INDENT-OFF*
///

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
/// @param total_size total size in bytes of the memory pool
/// @param block_shift block size in bit shifts (i.e. 8 bytes == 3 bits)
///
template<size_t total_size, size_t block_shift>
class mem_pool
{
    static_assert(total_size > 0, "total size must be larger than 0");
    static_assert(total_size % (1 << block_shift) == 0, "total size must be a multiple of block size");
    static_assert((MAX_PAGE_SHIFT >= block_shift) &&(block_shift > 0), "block shift must be larger than 0");

public:

    using size_type = size_t;
    using shift_type = size_t;
    using integer_pointer = uintptr_t;

    /// Constructor
    ///
    /// Creates a memory pool with the starting virtual address of addr.
    ///
    /// @expects addr != 0
    /// @ensures none
    ///
    /// @param addr the starting address of the memory pool
    mem_pool(integer_pointer addr) noexcept_testing :
        m_addr(addr),
        m_size(total_size >> block_shift)
    {
        if (addr == 0)
            static_construction_error();

        integer_pointer end;
        if (__builtin_uaddl_overflow(m_addr, total_size, &end))
            static_construction_error();

        clear();
    }

    /// Default Destructor
    ///
    ~mem_pool() = default;

    /// Allocate Memory
    ///
    /// Allocates memory from the memory pool whose size is greater than or
    /// equal to size. The memory pool will always be a multiple of
    /// 1 << block_shift. Memory allocated will always have an alignment
    /// equal to block_shift plus the starting address provided when creating
    /// the memory pool. For this reason, if a specific alignment is needed,
    /// ensure the start address has this same alignment when creating the
    /// memory pool
    ///
    /// @expects size > 0
    /// @expects size <= total_size
    /// @ensures ret != nullptr
    ///
    /// @param size the number of bytes to allocate
    /// @return the starting address of the
    ///
    integer_pointer
    alloc(size_type size)
    {
        // [[ensures ret: ret != 0]]
        expects(size > 0);
        expects(size <= total_size);

        std::lock_guard<std::mutex> lock(m_mutex);

        integer_pointer start = 0;
        integer_pointer total = total_blocks(size);

        if ((start = next_search(m_next, total)) != mem_pool_used_index)
        {
            m_next = start + total;
            gsl::at(m_allocated, start) = total;

            return m_addr + (start << block_shift);
        }

        throw std::bad_alloc();
    }

    /// Free Memory
    ///
    /// Free's previously allocated memory.
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param addr the address to free
    ///
    void
    free(integer_pointer addr) noexcept
    {
        if (addr < m_addr)
            return;

        integer_pointer start = (addr - m_addr) >> block_shift;

        if (start >= m_allocated.size())
            return;

        {
            std::lock_guard<std::mutex> lock(m_mutex);
            gsl::at(m_allocated, start) = mem_pool_free_index;
        }
    }

    /// Contains Address
    ///
    /// Returns true if this memory pool contains this address, returns
    /// false otherwise.
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param addr to lookup
    ///
    bool
    contains(integer_pointer addr) const noexcept
    { return (addr >= m_addr && addr < m_addr + total_size); }

    /// Allocation Size
    ///
    /// Locates and returns the size of previously allocated memory from
    /// this pool. Like free, this function will not crash but instead will
    /// return 0 given invalid inputs.
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param addr to lookup
    ///
    size_type
    size(integer_pointer addr) const noexcept
    {
        std::lock_guard<std::mutex> lock(m_mutex);

        if (!contains(addr))
            return 0;

        auto size = gsl::at(m_allocated, (addr - m_addr) >> block_shift);

        if (size == mem_pool_free_index)
            return 0;

        return size << block_shift;
    }

    /// Clear Memory Pool
    ///
    /// This is a very dangerous function, and will effectively run free() on
    /// all memory previously allocated.
    ///
    /// @expects none
    /// @ensures none
    ///
    void
    clear() noexcept
    {
        std::lock_guard<std::mutex> lock(m_mutex);

        m_next = 0;
        __builtin_memset(m_allocated.data(), 0xFF, sizeof(m_allocated));
    }

private:

    integer_pointer
    next_search(integer_pointer initial, integer_pointer total) const
    {
        integer_pointer check = 0;
        integer_pointer count = 0;
        integer_pointer start = 0;
        integer_pointer index = initial;

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

            if (check >= (total_size >> block_shift))
                return mem_pool_used_index;
        }
    }

    integer_pointer
    total_blocks(size_type size) const noexcept
    {
        integer_pointer total = size >> block_shift;

        if ((size & ((1 << block_shift) - 1)) != 0)
            total++;

        return total;
    }

private:

    integer_pointer m_next;
    integer_pointer m_addr;
    integer_pointer m_size;

    mutable std::mutex m_mutex;
    std::array < integer_pointer, (total_size >> block_shift) > m_allocated;

public:

    mem_pool(const mem_pool &) = delete;
    mem_pool &operator=(const mem_pool &) = delete;
    mem_pool(mem_pool &&) noexcept = delete;
    mem_pool &operator=(mem_pool &&) noexcept = delete;
};

///
/// *INDENT-ON*
///

#endif
