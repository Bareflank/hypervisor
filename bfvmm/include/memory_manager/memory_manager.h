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

#ifndef MEMORY_MANAGER_H
#define MEMORY_MANAGER_H

#include <vector>
#include <unordered_map>

#include <bfmemory.h>
#include <bfconstants.h>

#include "buddy_allocator.h"
#include "object_allocator.h"

// -----------------------------------------------------------------------------
// Exports
// -----------------------------------------------------------------------------

#include <bfexports.h>

#ifndef STATIC_MEMORY_MANAGER
#ifdef SHARED_MEMORY_MANAGER
#define EXPORT_MEMORY_MANAGER EXPORT_SYM
#else
#define EXPORT_MEMORY_MANAGER IMPORT_SYM
#endif
#else
#define EXPORT_MEMORY_MANAGER
#endif

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4251)
#endif

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

namespace bfvmm
{

/// The memory manager has a couple specific functions:
/// - alloc / free memory
/// - virt_to_phys / phys_to_virt conversions
/// - map / unmap memory
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
/// Mapping / unmapping of virtual to physical memory is handled by providing
/// two capabilities. First, the memory manager provides a means to alloc and
/// free memory specific to mapping. This is virtual memory space that has
/// not been consumed by the heap / page pool. Second, a map and unmap function
/// are also provided that add / remove page mappings to the VMM's root page
/// tables. This operation should not be done manually, but instead should
/// be done using unique_map_ptr_x64.
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
/// @todo Once we add ARM support, we need to create an interface for this
///     class to inherit that provides shared APIs for both ARM and Intel. For
///     now the memory manager is Intel specific
///
class EXPORT_MEMORY_MANAGER memory_manager
{
public:

    using pointer = void *;                                         ///< Pointer type
    using integer_pointer = uintptr_t;                              ///< Integer pointer type
    using size_type = std::size_t;                                  ///< Size type
    using attr_type = decltype(memory_descriptor::type);            ///< Attribute type
    using memory_descriptor_list = std::vector<memory_descriptor>;  ///< Memory descriptor list type

    /// Default Destructor
    ///
    /// @expects none
    /// @ensures none
    ///
    virtual ~memory_manager() = default;

    /// Get Singleton Instance
    ///
    /// Get an instance to the singleton class.
    ///
    /// @expects none
    /// @ensures ret != nullptr
    ///
    /// @return a singleton instance of memory_manager
    ///
    static memory_manager *instance() noexcept;

    /// Allocate Memory
    ///
    /// Allocates memory from the SLAB allocator. If the requested memory
    /// is a page or larger, the memory is allocated using the page pool or
    /// huge pool.
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param size the number of bytes to allocate
    /// @return a poinmter to the newly allocated memory.
    ///     Returns 0 otherwise, or on error
    ///
    virtual pointer alloc(
        size_type size) noexcept;

    /// Allocate Page
    ///
    /// Allocates memory from the page pool.
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return a poinmter to the newly allocated memory.
    ///     Returns 0 otherwise, or on error
    ///
    virtual pointer alloc_page() noexcept;

    /// Allocate Map
    ///
    /// Allocates virtual memory to be used for mapping. This memory has no
    /// backing until it has been mapped, so don't attempt to dereference it
    /// until then as that will result in undefined behavior.
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param size the number of bytes to allocate
    /// @return a pointer to the starting address of the memory allocated.
    ///     Returns 0 otherwise, or on error
    ///
    virtual pointer alloc_map(
        size_type size) noexcept;

    /// Free Memory
    ///
    /// Deallocates a block of memory previously allocated by a call to
    /// alloc
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param ptr a pointer to previously allocated memory.
    ///
    virtual void free(
        pointer ptr) noexcept;

    /// Free Page
    ///
    /// Deallocates a block of memory previously allocated by a call to
    /// alloc_page
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param ptr a pointer to previously allocated memory.
    ///
    virtual void free_page(
        pointer ptr) noexcept;

    /// Free Map
    ///
    /// Deallocates a block of memory previously allocated by a call to
    /// alloc_map
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param ptr a pointer to previously allocated memory.
    ///
    virtual void free_map(
        pointer ptr) noexcept;

    /// Size
    ///
    /// Returns the size of previously allocated memory. If the provided
    /// pointer does not point to memory that has been allocated or is
    /// outside the bounds of the memory pool, this function returns 0.
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param ptr a pointer to memory previously allocated using alloc.
    /// @return the size of the pointer
    ///
    virtual size_type size(
        pointer ptr) const noexcept;

    /// Size Page
    ///
    /// Returns the size of previously allocated memory. If the provided
    /// pointer does not point to memory that has been allocated or is
    /// outside the bounds of the memory pool, this function returns 0.
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param ptr a pointer to memory previously allocated using alloc.
    /// @return the size of the pointer
    ///
    virtual size_type size_page(
        pointer ptr) const noexcept;

    /// Size of Map
    ///
    /// Returns the size of previously allocated map memory. If the provided
    /// pointer does not point to memory that has been allocated or is
    /// outside the bounds of the memory pool, this function returns 0.
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param ptr a pointer to memory previously allocated using alloc_map.
    /// @return the size of the pointer
    ///
    virtual size_type size_map(
        pointer ptr) const noexcept;

    /// Virtual Address To Physical Address
    ///
    /// Given a virtual address, returns a physical address.
    ///
    /// @expects virt != 0
    /// @ensures return != 0
    ///
    /// @param virt virtual address to convert
    /// @return physical address
    ///
    virtual integer_pointer virtint_to_physint(
        integer_pointer virt) const;

    /// Virtual Address To Physical Address
    ///
    /// Given a virtual address, returns a physical address.
    ///
    /// @expects virt != nullptr
    /// @ensures return != 0
    ///
    /// @param virt virtual address to convert
    /// @return physical address
    ///
    virtual integer_pointer virtptr_to_physint(
        const pointer virt) const;

    /// Virtual Address To Physical Address
    ///
    /// Given a virtual address, returns a physical address.
    ///
    /// @expects virt != 0
    /// @ensures return != 0
    ///
    /// @param virt virtual address to convert
    /// @return physical address
    ///
    virtual pointer virtint_to_physptr(
        integer_pointer virt) const;

    /// Virtual Address To Physical Address
    ///
    /// Given a virtual address, returns a physical address.
    ///
    /// @expects virt != nullptr
    /// @ensures return != 0
    ///
    /// @param virt virtual address to convert
    /// @return physical address
    ///
    virtual pointer virtptr_to_physptr(
        const pointer virt) const;

    /// Physical Address To Virtual Address
    ///
    /// Given a physical address, returns a virtual address.
    ///
    /// @expects phys != 0
    /// @ensures return != 0
    ///
    /// @param phys physical address to convert
    /// @return virtual address
    ///
    virtual integer_pointer physint_to_virtint(
        integer_pointer phys) const;

    /// Physical Address To Virtual Address
    ///
    /// Given a physical address, returns a virtual address.
    ///
    /// @expects phys != nullptr
    /// @ensures return != 0
    ///
    /// @param phys physical address to convert
    /// @return virtual address
    ///
    virtual integer_pointer physptr_to_virtint(
        const pointer phys) const;

    /// Physical Address To Virtual Address
    ///
    /// Given a physical address, returns a virtual address.
    ///
    /// @expects phys != 0
    /// @ensures return != nullptr
    ///
    /// @param phys physical address to convert
    /// @return virtual address
    ///
    virtual pointer physint_to_virtptr(
        integer_pointer phys) const;

    /// Physical Address To Virtual Address
    ///
    /// Given a physical address, returns a virtual address.
    ///
    /// @expects phys != nullptr
    /// @ensures return != nullptr
    ///
    /// @param phys physical address to convert
    /// @return virtual address
    ///
    virtual pointer physptr_to_virtptr(
        const pointer phys) const;

    /// Adds Memory Descriptor
    ///
    /// Adds a memory descriptor to the memory manager.
    ///
    /// @expects virt != 0
    /// @expects phys != 0
    /// @expects type != 0
    /// @expects virt & (page_size - 1) == 0
    /// @expects phys & (page_size - 1) == 0
    /// @ensures none
    ///
    /// @param virt virtual address to add
    /// @param phys physical address mapped to virt
    /// @param attr how the memory was mapped
    ///
    virtual void add_md(
        integer_pointer virt, integer_pointer phys, attr_type attr);

    /// Remove Memory Descriptor
    ///
    /// Removes a memory descriptor list to the memory manager.
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param virt virtual address to remove
    /// @param phys physical address mapped to virt
    ///
    virtual void remove_md(
        integer_pointer virt, integer_pointer phys);

    /// Descriptor List
    ///
    /// Returns a list of descriptors that have been added to the
    /// memory manager. Note that to limit the amount of memory that is
    /// needed for lookups, this function is expensive has it has to
    /// reconstruct the descriptors currently being stored.
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return memory descriptor list
    ///
    virtual memory_descriptor_list descriptors() const;

private:

    memory_manager() noexcept;

private:

    struct virt_t {
        integer_pointer phys;
        integer_pointer attr;
    };

    struct phys_t {
        integer_pointer virt;
        integer_pointer attr;
    };

    std::unordered_map<integer_pointer, virt_t> m_virt_map;
    std::unordered_map<integer_pointer, phys_t> m_phys_map;

    buddy_allocator g_page_pool;
    buddy_allocator g_huge_pool;
    buddy_allocator g_mem_map_pool;

    basic_object_allocator slab010;
    basic_object_allocator slab020;
    basic_object_allocator slab030;
    basic_object_allocator slab040;
    basic_object_allocator slab080;
    basic_object_allocator slab100;
    basic_object_allocator slab200;
    basic_object_allocator slab400;
    basic_object_allocator slab800;

public:

    /// @cond

    memory_manager(memory_manager &&) noexcept = delete;
    memory_manager &operator=(memory_manager &&) noexcept = delete;

    memory_manager(const memory_manager &) = delete;
    memory_manager &operator=(const memory_manager &) = delete;

    /// @endcond
};

}

/// Memory Manager Macro
///
/// The following macro can be used to quickly call the memory manager as
/// this class will likely be called by a lot of code.
///
/// @expects
/// @ensures g_mm != nullptr
///
#define g_mm bfvmm::memory_manager::instance()

/// Allocate Page
///
/// This function allocates a page of memory directly from the page pool.
///
/// @expects
/// @ensures
///
/// @return Returns a pointer to the newly allocated page
///
extern "C" void *alloc_page();

/// Free Page
///
/// This function frees a previous allocated page of memory from the page pool.
///
/// @expects
/// @ensures
///
/// @param ptr a pointer to the previously allocated page
///
extern "C" void free_page(void *ptr);

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#endif
