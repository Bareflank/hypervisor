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

#ifndef MAP_PTR_H
#define MAP_PTR_H

#include <vector>
#include <utility>
#include <cstdint>
#include <type_traits>

#include <bfgsl.h>
#include <bfmemory.h>
#include <bfexception.h>
#include <bfupperlower.h>

#include "cr3.h"
#include "../../memory_manager.h"

#include <intrinsics.h>

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

namespace bfvmm
{
namespace x64
{

gsl::not_null<bfvmm::x64::cr3::mmap *> mmap();

template <class T>
class unique_map_ptr;

/// Make Unique Map (Single Page)
///
/// This function can be used to map a single virtual memory page to
/// a single physical memory page.
///
/// @b Example: @n
/// @code
/// std::cout << bfvmm::x64::make_unique_map<char>(phys) << '\n';
/// @endcode
///
/// @expects phys != nullptr
/// @expects attr != map_none
/// @ensures ret.get() != nullptr
///
/// @param phys the physical address to map
/// @param attr defines how to map the memory. Defaults to map_read_write
/// @param cache the cache to for the mapping
/// @return resulting unique_map_ptr
///
template<class T>
auto make_unique_map(
    typename unique_map_ptr<T>::pointer phys,
    cr3::mmap::memory_type cache = cr3::mmap::memory_type::write_back)
{
    auto vmap = g_mm->alloc_map(::x64::pt::page_size);

    try {
        return unique_map_ptr<T>(
                   reinterpret_cast<typename unique_map_ptr<T>::integer_pointer>(vmap),
                   reinterpret_cast<typename unique_map_ptr<T>::integer_pointer>(phys),
                   cache
               );
    }
    catch (...) {
        g_mm->free_map(vmap);
        throw;
    }
}

/// Make Unique Map (Single Page)
///
/// This function can be used to map a single virtual memory page to
/// a single physical memory page.
///
/// @b Example: @n
/// @code
/// std::cout << bfvmm::x64::make_unique_map<char>(phys) << '\n';
/// @endcode
///
/// @expects phys != 0
/// @expects attr != map_none
/// @ensures ret.get() != nullptr
///
/// @param phys the physical address to map
/// @param attr defines how to map the memory. Defaults to map_read_write
/// @param cache the cache to for the mapping
/// @return resulting unique_map_ptr
///
template<class T>
auto make_unique_map(
    typename unique_map_ptr<T>::integer_pointer phys,
    cr3::mmap::memory_type cache = cr3::mmap::memory_type::write_back)
{
    auto vmap = g_mm->alloc_map(::x64::pt::page_size);

    try {
        return unique_map_ptr<T>(
                   reinterpret_cast<typename unique_map_ptr<T>::integer_pointer>(vmap),
                   phys, cache
               );
    }
    catch (...) {
        g_mm->free_map(vmap);
        throw;
    }
}

/// Make Unique Map (Physically Contiguous / Non-Contiguous Range)
///
/// This function can be used to map both physically contiguous, and
/// physically non-contiguous memory by providing a list of physical
/// pages to map. The list consists of std::pairs, each containing a
/// physical address, and a size. A physically contiguous memory range
/// would consist of a list of one std::pair contains the physical address
/// and it's size. A physically non-contiguous range would consist of a
/// list of each page range that makes up the memory to be mapped
/// (similar to a Windows MDL). In either case the total number of bytes
/// mapped is equal to the total of each size field in each std::pair
/// in the list provided.
///
/// @b Example: @n
/// @code
/// auto phys_range_1 = std::make_pair(phys1, size1);
/// auto phys_range_2 = std::make_pair(phys2, size2);
/// auto phys_range_3 = std::make_pair(phys3, size3);
/// auto list = {phys_range_1, phys_range_2, phys_range_3};
/// std::cout << bfvmm::x64::make_unique_map<char>(list) << '\n';
/// @endcode
///
/// @expects list.empty() == false
/// @expects list.at(i).first != 0
/// @expects list.at(i).second != 0
/// @expects list.at(i).second & (::x64::pt::page_size - 1) == 0
/// @expects attr != map_none
/// @ensures ret.get() != nullptr
///
/// @param list list of std::pairs, each containing a physical address
///     and a size, defining a physical address range to add to the
///     virtual address mapping
/// @param attr defines how to map the memory. Defaults to map_read_write
/// @return resulting unique_map_ptr
///
/// @todo: currently this requires a std::vector, we should be able to
///     change this to use any sequential container type in the future
///
template<class T>
auto make_unique_map(
    const std::vector<std::pair<typename unique_map_ptr<T>::integer_pointer,
    typename unique_map_ptr<T>::size_type>> &list)
{
    typename unique_map_ptr<T>::size_type size = 0;

    for (const auto &p : list) {
        size += p.second;
    }

    auto vmap = g_mm->alloc_map(size);

    try {
        return unique_map_ptr<T>(
                   reinterpret_cast<typename unique_map_ptr<T>::integer_pointer>(vmap), list
               );
    }
    catch (...) {
        g_mm->free_map(vmap);
        throw;
    }
}

/// Make Unique Map (Physically Contiguous / Non-Contiguous Range With CR3)
///
/// This function can be used to map both physically contiguous, and
/// physically non-contiguous memory by providing an existing virtually
/// contiguous memory range address and size, as well as the CR3 value
/// that defines the existing virtual to physical memory mappings. This
/// is useful when mapping guest memory into VMM, and caution should be
/// taken if mapping executable memory.
///
/// @note since this function must map in the guest's page tables to
///     locate each physical address for each page being mapped, this
///     function is very expensive, and should not be used in time
///     critical operations.
///
/// @b Example: @n
/// @code
/// std::cout << bfvmm::x64::make_unique_map<char>(virt, vmcs::guest_cr3::get(), size) << '\n';
/// @endcode
///
/// @expects virt != 0
/// @expects cr3 != 0
/// @expects size != 0
/// @ensures get() != nullptr
///
/// @param virt the virtual address containing the existing mapping
/// @param cr3 the root page table containing the existing virtual to
///     physical memory mappings
/// @param size the number of bytes to map
/// @return resulting unique_map_ptr
///
template<class T>
auto make_unique_map(
    typename unique_map_ptr<T>::integer_pointer virt,
    typename unique_map_ptr<T>::integer_pointer cr3,
    typename unique_map_ptr<T>::size_type size)
{
    auto vmap = g_mm->alloc_map(size + bfn::lower(virt));

#ifdef ENABLE_BUILD_TEST

    return unique_map_ptr<T> {reinterpret_cast<typename unique_map_ptr<T>::integer_pointer>(vmap), cr3};

#else

    try {
        return unique_map_ptr<T>(
                   reinterpret_cast<typename unique_map_ptr<T>::integer_pointer>(vmap),
                   virt, cr3, size
               );
    }
    catch (...) {
        g_mm->free_map(vmap);
        throw;
    }

#endif
}

/// Virt to Phys with CR3
///
/// Converts a virtual address to a physical address given the
/// CR3 to locate the physical address from. Note that this function
/// has to map / unmap the page table tree as it traverses the tree
/// to locate the physical address. As a result, this is an expensive
/// operation and should not be used in time sensitive operations.
///
/// @note the provided virtual address should be present prior to running
///     this function.
///
/// @expects virt != 0
/// @expects cr3 != 0
/// @ensures none
///
/// @param virt virtual address to convert
/// @param cr3 the CR3 to lookup the physical address from. The virtual address
///     should originate from this CR3, otherwise the resulting physical address
///     could be incorrect, or an exception could be thrown.
/// @return returns the physical address mapped to the provided virtual address
///     located in the provided CR3
///
uintptr_t virt_to_phys_with_cr3(uintptr_t virt, uintptr_t cr3);

/// Map Physically Contiguous / Non-Contiguous Range With CR3
///
/// This function can be used to map both physically contiguous, and
/// physically non-contiguous memory by providing an existing virtually
/// contiguous memory range address and size, as well as the CR3 value
/// that defines the existing virtual to physical memory mappings. This
/// is useful when mapping guest memory into VMM, and caution should be
/// taken if mapping executable memory.
///
/// @note since this function must map in the guest's page tables to
///     locate each physical address for each page being mapped, this
///     function is very expensive, and should not be used in time
///     critical operations.
///
/// @note this function should not be used directly, but instead the
///     unique_map_ptr version should be used instead. This function can
///     however be overloaded to provide custom functionality for mapping
///     guest memory into the VMM.
///
/// @expects vmap != 0
/// @expects vmap & (::x64::pt::page_size - 1) == 0
/// @expects virt != 0
/// @expects cr3 != 0
/// @expects cr3 & (::x64::pt::page_size - 1) == 0
/// @expects size != 0
/// @expects attr != 0
/// @ensures get() != nullptr
///
/// @param vmap the virtual address to map the range to
/// @param virt the virtual address containing the existing mapping
/// @param cr3 the root page table containing the existing virtual to
///     physical memory mappings
/// @param size the number of bytes to map
///
EXPORT_MEMORY_MANAGER
void map_with_cr3(
    uintptr_t vmap, uintptr_t virt, uintptr_t cr3, size_t size
);

/// Unique Map
///
/// Like std::unique_ptr, unique_map_ptr is a smart map that owns and
/// manages the mapping between virtual and physical memory. Memory is mapped
/// when the unique_map_ptr is first created, and unmapped when the
/// unique_map_ptr is destroyed.
///
/// Although this class can be used directly, it should be created using
/// make_unique_map, which allocates the virtual memory for you as shown
/// in this example:
///
/// @b Example: @n
/// @code
/// std::cout << bfvmm::x64::make_unique_map<char>(phys) << '\n';
/// @endcode
///
/// Unlike std::unique_pointer, unique_map_ptr takes additional arguments
/// and doesn't support an array syntax. It should also be noted that this
/// class provides some additional helpers specific to a map including a way
/// to get it's size, as well as a means to flush TLB entries associated
/// with this map if needed (although when the map is created, the local
/// TLB is flushed for you, and thus this should only be needed if you
/// share this map with another core)
///
template <class T>
class unique_map_ptr
{
public:

    using pointer = T*;                         ///< Pointer type
    using integer_pointer = uintptr_t;          ///< Integer pointer type
    using size_type = size_t;                   ///< Size type
    using element_type = T;                     ///< Element type

    /// Default Map
    ///
    /// This constructor can be used to create a default map that maps to
    /// nothing
    ///
    unique_map_ptr() = default;

    /// Invalid Map
    ///
    /// This constructor can be used to create an invalid map that maps to
    /// nothing
    ///
    /// @param donotcare don't care
    unique_map_ptr(std::nullptr_t donotcare)
    { (void) donotcare; }

    /// Map Single Page
    ///
    /// This constructor can be used to map a single virtual memory page to
    /// a single physical memory page.
    ///
    /// @b Example: @n
    /// @code
    /// std::cout << bfvmm::x64::make_unique_map<char>(phys) << '\n';
    /// @endcode
    ///
    /// @expects vmap != 0
    /// @expects vmap & (page_size - 1) == 0
    /// @expects phys != 0
    /// @expects phys & (page_size - 1) == 0
    /// @ensures get() != nullptr
    ///
    /// @param vmap the virtual address to map the physical address to
    /// @param phys the physical address to map
    /// @param cache the cache to for the mapping
    ///
    unique_map_ptr(
        integer_pointer vmap,
        integer_pointer phys,
        cr3::mmap::memory_type cache = cr3::mmap::memory_type::write_back
    ) :
        m_virt(vmap),
        m_size(::x64::pt::page_size),
        m_unaligned_size(::x64::pt::page_size)
    {
        // [[ensures: get() != nullptr]]
        expects(vmap != 0);
        expects(bfn::lower(vmap) == 0);
        expects(phys != 0);
        expects(bfn::lower(phys) == 0);

        mmap()->map_4k(vmap, bfn::upper(phys), cr3::mmap::attr_type::read_write, cache);

        flush();
    }

    /// Map Physically Contiguous / Non-Contiguous Range
    ///
    /// This constructor can be used to map both physically contiguous, and
    /// physically non-contiguous memory by providing a list of physical
    /// pages to map. The list consists of std::pairs, each containing a
    /// physical address, and a size. A physically contiguous memory range
    /// would consist of a list of one std::pair contains the physical address
    /// and it's size. A physically non-contiguous range would consist of a
    /// list of each page range that makes up the memory to be mapped
    /// (similar to a Windows MDL). In either case the total number of bytes
    /// mapped is equal to the total of each size field in each std::pair
    /// in the list provided.
    ///
    /// @note the resulting virtual memory address, like the other
    ///     constructors, will contain the lower bits of the physical address
    ///     so that you can not only get a map, but also receive a map
    ///     somewhere inside of the page if needed.
    ///
    /// @note this function doesn't check to make sure that the physical
    ///     ranges you provide don't overlap as the mapping will succeed
    ///     either way, so unless you want the same physical page being
    ///     mapped to different parts of your virtual range, make sure you
    ///     don't have overlapping ranges. In some cases you might want that,
    ///     the best example being ring buffers.
    ///
    /// @b Example: @n
    /// @code
    /// auto phys_range_1 = std::make_pair(phys1, size1);
    /// auto phys_range_2 = std::make_pair(phys2, size2);
    /// auto phys_range_3 = std::make_pair(phys3, size3);
    /// auto list = {phys_range_1, phys_range_2, phys_range_3};
    /// std::cout << bfvmm::x64::make_unique_map<char>(list) << '\n';
    /// @endcode
    ///
    /// @expects vmap != 0
    /// @expects vmap & (page_size - 1) == 0
    /// @expects list.empty() == false
    /// @expects list.at(i).first != 0
    /// @expects list.at(i).second != 0
    /// @expects list.at(i).second & (page_size - 1) == 0
    /// @ensures get() != nullptr
    ///
    /// @param vmap the virtual address to map the physical address to
    /// @param list list of std::pairs, each containing a physical address
    ///     and a size, defining a physical address range to add to the
    ///     virtual address mapping
    ///
    unique_map_ptr(
        integer_pointer vmap,
        const std::vector<std::pair<integer_pointer, size_type>> &list)
    {
        // [[ensures: get() != nullptr]]
        expects(vmap != 0);
        expects(bfn::lower(vmap) == 0);
        expects(!list.empty());

        for (const auto &p : list) {
            expects(p.first != 0);
            expects(p.second != 0);
            expects(bfn::lower(p.second) == 0);

            m_size += p.second;
            m_unaligned_size += p.second;
        }

        m_virt |= bfn::lower(list.front().first);
        m_virt |= bfn::upper(vmap);

        auto voff = 0UL;
        auto poff = 0UL;

        for (const auto &p : list) {
            auto phys = bfn::upper(p.first);
            auto size = p.second;

            for (poff = 0; poff < size; poff += ::x64::pt::page_size, voff += ::x64::pt::page_size) {
                mmap()->map_4k(vmap + voff, phys + poff, cr3::mmap::attr_type::read_write);
            }
        }

        flush();
    }

    /// Map Physically Contiguous / Non-Contiguous Range With CR3
    ///
    /// This constructor can be used to map both physically contiguous, and
    /// physically non-contiguous memory by providing an existing virtually
    /// contiguous memory range address and size, as well as the CR3 value
    /// that defines the existing virtual to physical memory mappings. This
    /// is useful when mapping guest memory into VMM, and caution should be
    /// taken if mapping executable memory.
    ///
    /// @note since this function must map in the guest's page tables to
    ///     locate each physical address for each page being mapped, this
    ///     function is very expensive, and should not be used in time
    ///     critical operations.
    ///
    /// @b Example: @n
    /// @code
    /// std::cout << bfvmm::x64::make_unique_map<char>(virt, vmcs::guest_cr3::get(), size) << '\n';
    /// @endcode
    ///
    /// @expects vmap != 0
    /// @expects vmap & (page_size - 1) == 0
    /// @expects virt != 0
    /// @expects cr3 != 0
    /// @expects cr3 & (page_size - 1) == 0
    /// @expects size != 0
    /// @ensures get() != nullptr
    ///
    /// @param vmap the virtual address to map the range to
    /// @param virt the virtual address containing the existing mapping
    /// @param cr3 the root page table containing the existing virtual to
    ///     physical memory mappings
    /// @param size the number of bytes to map
    ///
    unique_map_ptr(
        integer_pointer vmap, integer_pointer virt, integer_pointer cr3, size_type size
    ) :
        m_virt(0),
        m_size(size),
        m_unaligned_size(size)
    {
        // [[ensures: get() != nullptr]]

        m_virt |= bfn::lower(virt);
        m_virt |= bfn::upper(vmap);

        m_unaligned_size += bfn::lower(virt);

        map_with_cr3(vmap, virt, cr3, m_unaligned_size);

        flush();
    }

    /// Move Constructor
    ///
    /// Like std::unique_ptr, this is equivalent to
    ///
    /// @b Example: @n
    /// @code
    /// reset(other.release());
    /// @endcode
    ///
    /// The unique_map_ptr provided will no longer be valid, and the new
    /// unique_map_ptr will have the mapping provided. Note that this
    /// should be a fast operation, and no mapping / unmapping occurs. If the
    /// existing mapping is invalid, or already unmapped, the resulting
    /// unique_map_ptr will also be invalid / unmapped.
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param other the unique_map_ptr to move
    ///
    unique_map_ptr(unique_map_ptr &&other) noexcept
    { reset(other.release()); }

    /// Destructor
    ///
    /// Unmaps any existing map this unique_map_ptr holds. Note that if
    /// an occurs while attempting to unmap, exceptions are caught and
    /// execution continues. If this occurs, the results are undefined.
    ///
    /// @expects none
    /// @ensures none
    ///
    virtual ~unique_map_ptr() noexcept
    {
        guard_exceptions([&]
        { cleanup(m_virt, m_unaligned_size); });

        m_virt = 0;
        m_size = 0;
        m_unaligned_size = 0;
    }

    /// Copy Operator
    ///
    /// Like std::unique_ptr, this is equivalent to
    ///
    /// @b Example: @n
    /// @code
    /// reset(other.release());
    /// @endcode
    ///
    /// The unique_map_ptr provided will no longer be valid, and the new
    /// unique_map_ptr will have the mapping provided. Note that this
    /// should be a fast operation, and no mapping / unmapping occurs. If the
    /// existing mapping is invalid, or already unmapped, the resulting
    /// unique_map_ptr will also be invalid / unmapped.
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param other the unique_map_ptr to copy
    /// @return reference to this
    ///
    unique_map_ptr &operator=(unique_map_ptr &&other) noexcept
    {
        reset(other.release());
        return *this;
    }

    /// Copy Operator (reset)
    ///
    /// Like std::unique_ptr, this is equivalent to
    ///
    /// @b Example: @n
    /// @code
    /// reset();
    /// @endcode
    ///
    /// The result of this operation is the current unique_map_ptr will
    /// be unmapped and invalid.
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param dontcare nullptr
    /// @return reference to this
    ///
    unique_map_ptr &operator=(std::nullptr_t dontcare) noexcept
    {
        (void) dontcare;

        reset();
        return *this;
    }

    /// Dereference
    ///
    /// Returns *T. Note that if the map is invalid, this operation will
    /// likely segfault.
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return *T
    ///
    typename std::add_lvalue_reference<T>::type operator*() const
    { return *reinterpret_cast<pointer>(m_virt); }

    /// Dereference
    ///
    /// Returns *T. Note that if the map is invalid, this operation will
    /// likely segfault.
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return *T
    ///
    auto operator->() const noexcept
    { return reinterpret_cast<pointer>(m_virt); }

    /// Get *T
    ///
    /// Returns *T. Note that if the map is invalid, any use of the result
    /// will likely segfault.
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return *T
    ///
    virtual pointer get() const noexcept
    { return reinterpret_cast<pointer>(m_virt); }

    /// Check Validity
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return returns true if the map is valid, false otherwise
    ///
    operator bool() const noexcept
    { return m_virt != 0 && m_size != 0 && m_unaligned_size != 0; }

    /// Size
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return returns the size of the map in bytes. Returns 0 if the map is
    ///     invalid
    ///
    virtual size_type size() const noexcept
    { return m_size; }

    /// Release
    ///
    /// Like std::unique_ptr, this releases the map from this
    /// unique_map_ptr and returns a std::tuple containing the virtual
    /// address and size of the map. It is left to the user of this
    /// function to either deliver the std::tuple to another unique_map_ptr
    /// via reset(), or manually unmap / free the virtual address
    ///
    /// @note use with caution as this is an unsafe operation
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return returns a std::tuple containing the virtual address and size
    ///     of the map. The user must manually unmap / free this memory
    ///
    auto release() noexcept
    {
        auto old_virt = m_virt;
        auto old_size = m_size;
        auto old_unaligned_size = m_unaligned_size;

        m_virt = 0;
        m_size = 0;
        m_unaligned_size = 0;

        return std::make_tuple(reinterpret_cast<pointer>(old_virt), old_size, old_unaligned_size);
    }

    /// Reset
    ///
    /// Like std::unique_ptr, this resets the unique_map_ptr. If no
    /// args are provide, this function unmaps / frees the
    /// unique_map_ptr and the mapped memory becomes invalid. If a
    /// valid virtual address and size are provided, the current
    /// unique_map_ptr is unmapped and freed, and the newly provided
    /// virtual address and size are used in it's place.
    ///
    /// @note use with caution as this is an unsafe operation
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param ptr pointer to virtual memory to use. Defaults to nullptr
    /// @param size the size of the virtual memory provided in bytes. Defaults
    ///     to 0
    /// @param unaligned_size the unaligned size of the virtual memory provided
    ///     in bytes. Defaults to 0. In most cases this is the same thing as
    ///     size, but if your using a map from CR3, and the virtual address
    ///     is not page aligned, you must add lower(virt)
    ///
    void reset(pointer ptr = pointer(), size_type size = size_type(),
               size_type unaligned_size = size_type()) noexcept
    {
        auto old_virt = m_virt;
        auto old_unaligned_size = m_unaligned_size;

        m_virt = reinterpret_cast<integer_pointer>(ptr);
        m_size = size;
        m_unaligned_size = unaligned_size;

        cleanup(old_virt, old_unaligned_size);
    }

    /// Reset
    ///
    /// Like std::unique_ptr, this resets the unique_map_ptr. If no
    /// args are provide, this function unmaps / frees the
    /// unique_map_ptr and the mapped memory becomes invalid. If a
    /// valid virtual address and size are provided, the current
    /// unique_map_ptr is unmapped and freed, and the newly provided
    /// virtual address and size are used in it's place.
    ///
    /// @note use with caution as this is an unsafe operation
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param p std::tuple containing the virtual memory address and size in
    ///     bytes of the new mapping to use.
    ///
    void reset(const std::tuple<pointer, size_type, size_type> &p) noexcept
    { reset(std::get<0>(p), std::get<1>(p), std::get<2>(p)); }

    /// Swap
    ///
    /// Swaps the mappings of one unique_map_ptr with another
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param other the unique_map_ptr to swap with
    ///
    void swap(unique_map_ptr &other) noexcept
    {
        std::swap(m_virt, other.m_virt);
        std::swap(m_size, other.m_size);
        std::swap(m_unaligned_size, other.m_unaligned_size);
    }

    /// Flush
    ///
    /// Flushes the TLB entries associated with the virtual address ranges
    /// this unique_map_ptr holds. This is done automatically when
    /// mapping memory, but might be needed if this map is shared with
    /// another core whose TLB has not been properly flushed.
    ///
    /// @expects none
    /// @ensures none
    ///
    void flush() noexcept
    {
        auto vmap = bfn::upper(m_virt);
        for (auto vadr = vmap; vadr < vmap + m_unaligned_size; vadr += ::x64::pt::page_size) {
            ::x64::tlb::invlpg(reinterpret_cast<pointer>(vadr));
        }
    }

    /// Cache Flush
    ///
    /// Flushes the Cache associated with the virtual address ranges
    /// this unique_map_ptr holds. This is done automatically when
    /// unmapping memory, but might be needed manually by users
    ///
    /// @expects none
    /// @ensures none
    ///
    void cache_flush() noexcept
    {
        auto vmap = bfn::upper(m_virt);
        for (auto vadr = vmap; vadr < vmap + m_unaligned_size; vadr += ::x64::cache_line_size) {
            ::x64::cache::clflush(reinterpret_cast<pointer>(vadr));
        }
    }

private:

    void cleanup(integer_pointer virt, size_type size) noexcept
    {
        if (virt != 0 && size != 0) {
            auto vmap = bfn::upper(virt);
            for (auto vadr = vmap; vadr < vmap + size; vadr += ::x64::pt::page_size) {
                mmap()->unmap(vadr);
            }

            g_mm->free_map(reinterpret_cast<pointer>(vmap));
        }
    }

private:

    integer_pointer m_virt{0};
    size_type m_size{0};
    size_type m_unaligned_size{0};

public:

    /// @cond

    unique_map_ptr(const unique_map_ptr &) = delete;
    unique_map_ptr &operator=(const unique_map_ptr &) = delete;

    /// @endcond
};

/// @cond

template <class T>
void swap(unique_map_ptr<T> &x, unique_map_ptr<T> &y) noexcept
{ x.swap(y); }

template <class T1, class T2>
bool operator==(const unique_map_ptr<T1> &x, const unique_map_ptr<T2> &y)
{ return x.get() == y.get(); }

template <class T1, class T2>
bool operator!=(const unique_map_ptr<T1> &x, const unique_map_ptr<T2> &y)
{ return x.get() != y.get(); }

template <class T1, class T2>
bool operator<(const unique_map_ptr<T1> &x, const unique_map_ptr<T2> &y)
{ return x.get() < y.get(); }

template <class T1, class T2>
bool operator<=(const unique_map_ptr<T1> &x, const unique_map_ptr<T2> &y)
{ return x.get() <= y.get(); }

template <class T1, class T2>
bool operator>(const unique_map_ptr<T1> &x, const unique_map_ptr<T2> &y)
{ return x.get() > y.get(); }

template <class T1, class T2>
bool operator>=(const unique_map_ptr<T1> &x, const unique_map_ptr<T2> &y)
{ return x.get() >= y.get(); }

template <class T>
bool operator==(const unique_map_ptr<T> &x, std::nullptr_t dontcare) noexcept
{ (void) dontcare; return !x; }

template <class T>
bool operator==(std::nullptr_t dontcare, const unique_map_ptr<T> &y) noexcept
{ (void) dontcare; return !y; }

template <class T>
bool operator!=(const unique_map_ptr<T> &x, std::nullptr_t dontcare) noexcept
{ (void) dontcare; return x; }

template <class T>
bool operator!=(std::nullptr_t dontcare, const unique_map_ptr<T> &y) noexcept
{ (void) dontcare; return y; }

/// @endcond

inline uintptr_t
virt_to_phys_with_cr3(
    uintptr_t virt, uintptr_t cr3)
{
    uintptr_t from;

    expects(cr3 != 0);
    expects(virt != 0);

    from = ::x64::pml4::from;
    auto pml4_idx = ::x64::pml4::index(virt);
    auto pml4_map = make_unique_map<uintptr_t>(bfn::upper(cr3));
    auto pml4_pte = pml4_map.get()[pml4_idx];

    expects(::x64::pml4::entry::phys_addr::get(pml4_pte) != 0);
    expects(::x64::pml4::entry::present::is_enabled(pml4_pte));

    from = ::x64::pdpt::from;
    auto pdpt_idx = ::x64::pdpt::index(virt);
    auto pdpt_map = make_unique_map<uintptr_t>(::x64::pml4::entry::phys_addr::get(pml4_pte));
    auto pdpt_pte = pdpt_map.get()[pdpt_idx];

    expects(::x64::pdpt::entry::phys_addr::get(pdpt_pte) != 0);
    expects(::x64::pdpt::entry::present::is_enabled(pdpt_pte));

    if (::x64::pdpt::entry::ps::is_enabled(pdpt_pte)) {
        return bfn::upper(::x64::pdpt::entry::phys_addr::get(pdpt_pte), from) |
               bfn::lower(virt, from);
    }

    from = ::x64::pd::from;
    auto pd_idx = ::x64::pd::index(virt);
    auto pd_map = make_unique_map<uintptr_t>(::x64::pdpt::entry::phys_addr::get(pdpt_pte));
    auto pd_pte = pd_map.get()[pd_idx];

    expects(::x64::pd::entry::phys_addr::get(pd_pte) != 0);
    expects(::x64::pd::entry::present::is_enabled(pd_pte));

    if (::x64::pd::entry::ps::is_enabled(pd_pte)) {
        return bfn::upper(::x64::pd::entry::phys_addr::get(pd_pte), from) |
               bfn::lower(virt, from);
    }

    from = ::x64::pt::from;
    auto pt_idx = ::x64::pt::index(virt);
    auto pt_map = make_unique_map<uintptr_t>(::x64::pd::entry::phys_addr::get(pd_pte));
    auto pt_pte = pt_map.get()[pt_idx];

    expects(::x64::pt::entry::phys_addr::get(pt_pte) != 0);
    expects(::x64::pt::entry::present::is_enabled(pt_pte));

    return bfn::upper(::x64::pt::entry::phys_addr::get(pt_pte), from) |
           bfn::lower(virt, from);
}

inline uintptr_t
virt_to_phys_with_cr3(
    void *virt, uintptr_t cr3)
{ return virt_to_phys_with_cr3(reinterpret_cast<uintptr_t>(virt), cr3); }

inline void
map_with_cr3(
    uintptr_t vmap, uintptr_t virt, uintptr_t cr3, size_t size)
{
    uintptr_t pml4_addr = bfn::upper(cr3);

    expects(vmap != 0);
    expects(bfn::lower(vmap) == 0);
    expects(virt != 0);
    expects(pml4_addr != 0);
    expects(size != 0);

    for (auto offset = 0UL; offset < size; offset += ::x64::pt::page_size) {
        uintptr_t from;
        uintptr_t phys;
        uintptr_t current_virt = virt + offset;

        while (true) {
            from = ::x64::pml4::from;
            auto pml4_idx = ::x64::pml4::index(current_virt);
            auto pml4_map = make_unique_map<uintptr_t>(pml4_addr);
            auto pml4_pte = pml4_map.get()[pml4_idx];

            expects(::x64::pml4::entry::phys_addr::get(pml4_pte) != 0);
            expects(::x64::pml4::entry::present::is_enabled(pml4_pte));

            from = ::x64::pdpt::from;
            auto pdpt_idx = ::x64::pdpt::index(current_virt);
            auto pdpt_map = make_unique_map<uintptr_t>(::x64::pml4::entry::phys_addr::get(pml4_pte));
            auto pdpt_pte = pdpt_map.get()[pdpt_idx];

            expects(::x64::pdpt::entry::phys_addr::get(pdpt_pte) != 0);
            expects(::x64::pdpt::entry::present::is_enabled(pdpt_pte));

            if (::x64::pdpt::entry::ps::is_enabled(pdpt_pte)) {
                phys = ::x64::pdpt::entry::phys_addr::get(pdpt_pte);
                break;
            }

            from = ::x64::pd::from;
            auto pd_idx = ::x64::pd::index(current_virt);
            auto pd_map = make_unique_map<uintptr_t>(::x64::pdpt::entry::phys_addr::get(pdpt_pte));
            auto pd_pte = pd_map.get()[pd_idx];

            expects(::x64::pd::entry::phys_addr::get(pd_pte) != 0);
            expects(::x64::pd::entry::present::is_enabled(pd_pte));

            if (::x64::pd::entry::ps::is_enabled(pd_pte)) {
                phys = ::x64::pd::entry::phys_addr::get(pd_pte);
                break;
            }

            from = ::x64::pt::from;
            auto pt_idx = ::x64::pt::index(current_virt);
            auto pt_map = make_unique_map<uintptr_t>(::x64::pd::entry::phys_addr::get(pd_pte));
            auto pt_pte = pt_map.get()[pt_idx];

            expects(::x64::pt::entry::phys_addr::get(pt_pte) != 0);
            expects(::x64::pt::entry::present::is_enabled(pt_pte));

            phys = ::x64::pt::entry::phys_addr::get(pt_pte);
            break;
        }

        auto vadr = vmap + offset;
        auto padr = bfn::upper(phys, from) | bfn::lower(current_virt, from);

        mmap()->map_4k(vadr, bfn::upper(padr), cr3::mmap::attr_type::read_write);
    }
}

}
}

#endif
