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
#include <stdint.h>
#include <memory.h>

/// The memory manager has two specific functions:
/// - alloc / free memory
/// - virt_to_phys / phys_to_virt conversions
///
/// To support alloc / free, the memory manager is given both heap memory
/// and a page pool. If a alloc is requested whose size is a multiple of
/// MAX_PAGE_SIZE, the page pool is used. All other requests come from the
/// heap.
///
/// To support virt / phys mappings, the memory manager has an add_mdl
/// function that is called by the driver entry. Each time the driver entry
/// allocates memory for an ELF module, it must call add_mdl with a list of
/// page mappings that tells the VMM how to convert from virt to phys and back.
/// The memory manager uses this information to provide the VMM with the needed
/// conversions.
///
/// Finally, this module also provides the libc functions that are needed by
/// libc++ for new / delete. For this reason, this module is required to get
/// libc++ working, which is needed by, pretty much the rest of the VMM
/// including the serial code. Therefore, if there are issues with the
/// memory manager, the process of debugging the memory manager is not simple,
/// as you must get rid of all of the other modules, and work with the
/// memory manager directly until it's working as needed (i.e. why unit
/// testing can be very helpful here).
///
class memory_manager
{
public:

    /// Destructor
    ///
    virtual ~memory_manager() = default;

    /// Get Singleton Instance
    ///
    /// Get an instance to the singleton class.
    ///
    static memory_manager *instance() noexcept;

    /// Malloc
    ///
    /// Allocates memory. If the requested size is a multiple of MAX_PAGE_SIZE
    /// the page pool is used to allocate the memory which likely has more
    /// memory, and the resulting addresses are page aligned. All other
    /// requests come from the heap.
    ///
    /// @note that this function generally should not be used directly, but
    /// instead new / delete should be used.
    ///
    /// @note when executing std::make_shared, the alloc is likely to be
    /// larger than the requested amount, as the reference counter is alloc'd
    /// as well. If page alignment is required, first new, and pass the
    /// resulting pointer to std::shared_ptr.
    ///
    /// @param size the number of bytes to allocate
    /// @return a pointer to the starting address of the memory allocated. The
    ///     pointer is page aligned if size is a multiple of MAX_PAGE_SIZE
    ///
    virtual void *alloc(size_t size) noexcept;

    /// Free
    ///
    /// Deallocates a block of memory previously allocated by a call to alloc,
    /// making it available again for further allocations. If ptr does not
    /// point to memory that was previously allocated, the call is ignored.
    /// If ptr == nullptr, the call is also ignored. If ptr points to an offset into
    /// memory that was previously allocated by a call to alloc, this function
    /// will free all of the memory allocated.
    ///
    /// Note that this function generally should not be used directly, but
    /// instead new / delete should be used.
    ///
    /// @param ptr a pointer to memory previously allocated using alloc.
    ///
    virtual void free(void *ptr) noexcept;

    /// Size
    ///
    /// Returns the size of previously allocated memory. If the provided
    /// pointer does not point to memory that has been allocated or is
    /// outside the bounds of the memory pool, this function returns 0.
    ///
    /// @param ptr a pointer to memory previously allocated using alloc.
    ///
    virtual uintptr_t size(void *ptr) const noexcept;

    /// Virtual Address To Physical Address
    ///
    /// Given a virtual address, returns a physical address. If the memory
    /// manager does not have a memory descriptor for the provided address,
    /// or the provided address is 0, 0 is returned.
    ///
    /// @param virt virtual address to convert
    /// @return physical address
    ///
    virtual uintptr_t virtint_to_physint(uintptr_t virt);

    /// Virtual Address To Physical Address
    ///
    /// Given a virtual address, returns a physical address. If the memory
    /// manager does not have a memory descriptor for the provided address,
    /// or the provided address is nullptr, 0 is returned.
    ///
    /// @param virt virtual address to convert
    /// @return physical address
    ///
    virtual uintptr_t virtptr_to_physint(void *virt);

    /// Virtual Address To Physical Address
    ///
    /// Given a virtual address, returns a physical address. If the memory
    /// manager does not have a memory descriptor for the provided address,
    /// or the provided address is 0, nullptr is returned.
    ///
    /// @param virt virtual address to convert
    /// @return physical address
    ///
    virtual void *virtint_to_physptr(uintptr_t virt);

    /// Virtual Address To Physical Address
    ///
    /// Given a virtual address, returns a physical address. If the memory
    /// manager does not have a memory descriptor for the provided address,
    /// or the provided address is nullptr, nullptr is returned.
    ///
    /// @param virt virtual address to convert
    /// @return physical address
    ///
    virtual void *virtptr_to_physptr(void *virt);

    /// Physical Address To Virtual Address
    ///
    /// Given a physical address, returns a virtual address. If the memory
    /// manager does not have a memory descriptor for the provided address,
    /// or the provided address is 0, 0 is returned.
    ///
    /// @param phys physical address to convert
    /// @return virtual address
    ///
    virtual uintptr_t physint_to_virtint(uintptr_t phys);

    /// Physical Address To Virtual Address
    ///
    /// Given a physical address, returns a virtual address. If the memory
    /// manager does not have a memory descriptor for the provided address,
    /// or the provided address is nullptr, 0 is returned.
    ///
    /// @param phys physical address to convert
    /// @return virtual address
    ///
    virtual uintptr_t physptr_to_virtint(void *phys);

    /// Physical Address To Virtual Address
    ///
    /// Given a physical address, returns a virtual address. If the memory
    /// manager does not have a memory descriptor for the provided address,
    /// or the provided address is 0, nullptr is returned.
    ///
    /// @param phys physical address to convert
    /// @return virtual address
    ///
    virtual void *physint_to_virtptr(uintptr_t phys);

    /// Physical Address To Virtual Address
    ///
    /// Given a physical address, returns a virtual address. If the memory
    /// manager does not have a memory descriptor for the provided address,
    /// or the provided address is nullptr, nullptr is returned.
    ///
    /// @param phys physical address to convert
    /// @return virtual address
    ///
    virtual void *physptr_to_virtptr(void *phys);

    /// Adds Memory Descriptor List
    ///
    /// Adds a memory descriptor list to the memory manager. The memory
    /// descriptors are used by the memory manager to do address conversions
    /// and lookup memory access rights. Note that this function should only
    /// by called by the driver entry point prior to initialization.
    ///
    /// @param md a pointer to a memory descriptor
    ///
    /// @throws invalid_argument_error thrown if mdl == 0 or num == 0
    /// @throws invalid_mdl_error thrown if a memory descriptor in the list
    ///     is not the size of a page, if the virtual address is not page
    ///     aligned, or if the physical address is not page aligned.
    ///
    virtual void add_md(memory_descriptor *md);

    /// Get Virt to Phys Map
    ///
    /// @return the entire virtual to physical memory descriptor map
    ///
    virtual const std::map<uintptr_t, memory_descriptor> &virt_to_phys_map() const noexcept
    { return m_virt_to_phys_map; }

    /// Get Phys to Virt Map
    ///
    /// @return the entire physical to virtual memory descriptor map
    ///
    virtual const std::map<uintptr_t, memory_descriptor> &phys_to_virt_map() const noexcept
    { return m_phys_to_virt_map; }

public:

    /// Disable the copy consturctor
    ///
    memory_manager(const memory_manager &) = delete;

    /// Disable the copy operator
    ///
    memory_manager &operator=(const memory_manager &) = delete;

private:

    friend class memory_manager_ut;

private:

    /// Default Constructor
    ///
    memory_manager() noexcept = default;

private:

    std::map<uintptr_t, memory_descriptor> m_virt_to_phys_map;
    std::map<uintptr_t, memory_descriptor> m_phys_to_virt_map;
};

/// Memory Manager Macro
///
/// The following macro can be used to quickly call the memory manager as
/// this class will likely be called by a lot of code. This call is guaranteed
/// to not be nullptr
///
#define g_mm memory_manager::instance()

#endif
