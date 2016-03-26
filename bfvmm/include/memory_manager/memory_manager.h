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

#ifndef MEMORY_MANAGER_H
#define MEMORY_MANAGER_H

#include <map>
#include <stddef.h>
#include <stdint.h>
#include <memory.h>

class memory_manager
{
public:

    /// Destructor
    ///
    virtual ~memory_manager() {}

    /// Get Singleton Instance
    ///
    /// Get an instance to the singleton class.
    ///
    static memory_manager *instance();

    /// Free Blocks
    ///
    /// This class can be used to determine the total number of free blocks
    /// that the memory mamnager has left. Using this function, you can
    /// determine how much memory has been allocated, as well as how much
    /// memory is free. Not that that, although this will tell you how much
    /// is free, it cannot tell you if that memory can be allocated, since the
    /// free blocks could be highly fragemented.
    ///
    /// @return number of free blocks.
    ///
    virtual int64_t free_blocks();

    /// Malloc
    ///
    /// Allocates a block of size bytes of memory, returning a pointer to the
    /// beginning of the block. The content of the newly allocated block of
    /// memory is not initialized. If size is 0, this function returns 0. If
    /// the size if equal to MAX_PAGE_SIZE, the memory returned is guaranteed
    /// to be aligned to MAX_PAGE_SIZE. Although this function will accept any
    /// size granularity, the minimum size that will be allocated is always
    /// MAX_CACHE_LINE_SIZE.
    ///
    /// Note that this function generally should not be used directly, but
    /// instead new / delete should be used.
    ///
    /// @param size the number of bytes to allocate
    /// @return a pointer to the starting address of the memory allocated.
    ///
    virtual void *malloc(size_t size);

    /// Malloc Aligned
    ///
    /// Allocates a block of size bytes of memory, returning a pointer to the
    /// beginning of the block. The content of the newly allocated block of
    /// memory is not initialized. If size is 0, this function returns 0.
    /// Although this function will accept any size granularity, the minimum
    /// size that will be allocated is always MAX_CACHE_LINE_SIZE.
    ///
    /// Unlike malloc, this function allows the programmer to specify that
    /// desired alignment of memory. When possible, malloc should be used
    /// instead indirectly by using new / delete as these already provide
    /// MAX_PAGE_SIZE alignment.
    ///
    /// @param size the number of bytes to allocate
    /// @param alignment the desired alignment
    /// @return a pointer to the starting address of the memory allocated.
    ///
    virtual void *malloc_aligned(size_t size, uint64_t alignment);

    /// Free
    ///
    /// Deallocates a block of memory previously allocated by a call to malloc,
    /// making it available again for further allocations. If ptr does not
    /// point to memory that was previously allocated, the call is ignored.
    /// If ptr is 0, the call is also ignored. If ptr points to an offset into
    /// memory that was previously allocated by a call to malloc, this function
    /// will free all of the memory allocated.
    ///
    /// Note that this function generally should not be used directly, but
    /// instead new / delete should be used.
    ///
    /// @param ptr a pointer to memory previously allocated using malloc.
    ///
    virtual void free(void *ptr);

    /// Virtual Address To Physical Address
    ///
    /// Given a virtual address, returns a physical address. If the memory
    /// manager does not have a memory descriptor for the provided address,
    /// or the provided address is 0, 0 is returned.
    ///
    /// @param virt virtual address to convert
    /// @return physical address
    ///
    virtual void *virt_to_phys(void *virt);

    /// Physical Address To Virtual Address
    ///
    /// Given a physical address, returns a virtual address. If the memory
    /// manager does not have a memory descriptor for the provided address,
    /// or the provided address is 0, 0 is returned.
    ///
    /// @param phys physical address to convert
    /// @return virtual address
    ///
    virtual void *phys_to_virt(void *phys);

    /// Adds Memory Descriptor List
    ///
    /// Adds a memory descriptor list to the memory manager. The memory
    /// descriptors are used by the memory manager to do address conversions
    /// and lookup memory access rights. Note that this function should only
    /// by called by the driver entry point prior to initialization.
    ///
    /// @param mdl a pointer to a memory descriptor array
    /// @param num the number of memory descriptors in the array
    ///
    /// @throws invalid_argument_error thrown if mdl == 0 or num == 0
    /// @throws invalid_mdl_error thrown if a memory descriptor in the list
    ///     is not the size of a page, if the virtual address is not page
    ///     aligned, or if the physical address is not page aligned.
    ///
    virtual void add_mdl(memory_descriptor *mdl, int64_t num);

public:

    /// Disable the copy consturctor
    ///
    memory_manager(const memory_manager &) = delete;

    /// Disable the copy operator
    ///
    memory_manager &operator=(const memory_manager &) = delete;

private:

    /// Default Constructor
    ///
    memory_manager();

private:

    virtual void *block_to_virt(int64_t block);
    virtual int64_t virt_to_block(void *virt);

    virtual bool is_block_aligned(int64_t block, int64_t alignment);

private:

    uint32_t m_start;

    std::map<uintptr_t, memory_descriptor> m_virt_to_phys_map;
    std::map<uintptr_t, memory_descriptor> m_phys_to_virt_map;
};

/// Memory Manager Macro
///
/// The following macro can be used to quickly call the memory manager as
/// this class will likely be called by a lot of code. This call is guaranteed
/// to not be NULL
///
#define g_mm memory_manager::instance()

#endif
