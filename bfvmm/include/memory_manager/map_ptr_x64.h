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

#ifndef MAP_PTR_H
#define MAP_PTR_H

#include <gsl/gsl>

#include <vector>
#include <utility>
#include <cstdint>
#include <type_traits>

#include <memory.h>
#include <guard_exceptions.h>
#include <memory_manager/memory_manager_x64.h>
#include <memory_manager/root_page_table_x64.h>

#include <intrinsics/x64.h>
#include <intrinsics/tlb_x64.h>

using namespace x64;

// -----------------------------------------------------------------------------
// Definition
// -----------------------------------------------------------------------------

namespace bfn
{

template <class T>
class unique_map_ptr_x64;

/// Make Unique Map (Single Page)
///
/// This function can be used to map a single virtual memory page to
/// a single physical memory page.
///
/// @b Example: @n
/// @code
/// std::cout << bfn::make_unique_map_x64<char>(phys) << '\n';
/// @endcode
///
/// @expects phys != nullptr
/// @expects attr != map_none
/// @ensures ret.get() != nullptr
///
/// @param phys the physical address to map
/// @param attr defines how to map the memory. Defaults to map_read_write
/// @return resulting unique_map_ptr_x64
///
template<class T>
auto make_unique_map_x64(typename unique_map_ptr_x64<T>::pointer phys,
                         typename unique_map_ptr_x64<T>::attr_type attr = unique_map_ptr_x64<T>::map_read_write)
{
    auto &&vmap = g_mm->alloc_map(page_size);

    try
    {
        return unique_map_ptr_x64<T>(reinterpret_cast<typename unique_map_ptr_x64<T>::integer_pointer>(vmap),
                                     reinterpret_cast<typename unique_map_ptr_x64<T>::integer_pointer>(phys),
                                     attr);
    }
    catch (...)
    {
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
/// std::cout << bfn::make_unique_map_x64<char>(phys) << '\n';
/// @endcode
///
/// @expects phys != 0
/// @expects attr != map_none
/// @ensures ret.get() != nullptr
///
/// @param phys the physical address to map
/// @param attr defines how to map the memory. Defaults to map_read_write
/// @return resulting unique_map_ptr_x64
///
template<class T>
auto make_unique_map_x64(typename unique_map_ptr_x64<T>::integer_pointer phys,
                         typename unique_map_ptr_x64<T>::attr_type attr = unique_map_ptr_x64<T>::map_read_write)
{
    auto &&vmap = g_mm->alloc_map(page_size);

    try
    {
        return unique_map_ptr_x64<T>(reinterpret_cast<typename unique_map_ptr_x64<T>::integer_pointer>(vmap),
                                     phys, attr);
    }
    catch (...)
    {
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
/// std::cout << bfn::make_unique_map_x64<char>(list) << '\n';
/// @endcode
///
/// @expects list.empty() == false
/// @expects list.at(i).first != 0
/// @expects list.at(i).second != 0
/// @expects list.at(i).second & (page_size - 1) == 0
/// @expects attr != map_none
/// @ensures ret.get() != nullptr
///
/// @param list list of std::pairs, each containing a physical address
///     and a size, defining a physical address range to add to the
///     virtual address mapping
/// @param attr defines how to map the memory. Defaults to map_read_write
/// @return resulting unique_map_ptr_x64
///
/// @todo: currently this requires a std::vector, we should be able to
///     change this to use any sequential container type in the future
///
template<class T>
auto make_unique_map_x64(const std::vector<std::pair<typename unique_map_ptr_x64<T>::integer_pointer, typename unique_map_ptr_x64<T>::size_type>> &list,
                         typename unique_map_ptr_x64<T>::attr_type attr = unique_map_ptr_x64<T>::map_read_write)
{
    typename unique_map_ptr_x64<T>::size_type size = 0;

    for (const auto &p : list)
        size += p.second;

    auto &&vmap = g_mm->alloc_map(size);

    try
    {
        return unique_map_ptr_x64<T>(reinterpret_cast<typename unique_map_ptr_x64<T>::integer_pointer>(vmap),
                                     list, attr);
    }
    catch (...)
    {
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
/// std::cout << bfn::make_unique_map_x64<char>(virt, vmcs::guest_cr3::get(), size) << '\n';
/// @endcode
///
/// @expects virt != 0
/// @expects cr3 != 0
/// @expects size != 0
/// @expects attr != map_none
/// @ensures get() != nullptr
///
/// @param virt the virtual address containing the existing mapping
/// @param cr3 the root page table containing the existing virtual to
///     physical memory mappings
/// @param size the number of bytes to map
/// @param attr defines how to map the memory. Defaults to map_read_write
/// @return resulting unique_map_ptr_x64
///
template<class T>
auto make_unique_map_x64(typename unique_map_ptr_x64<T>::integer_pointer virt,
                         typename unique_map_ptr_x64<T>::integer_pointer cr3,
                         typename unique_map_ptr_x64<T>::size_type size,
                         typename unique_map_ptr_x64<T>::attr_type attr = unique_map_ptr_x64<T>::map_read_write)
{
    auto &&vmap = g_mm->alloc_map(page_size);

#ifdef MAP_PTR_TESTING

    (void) cr3;
    (void) attr;

    expects(virt != 0xDEADBEEF);
    return unique_map_ptr_x64<T> {reinterpret_cast<typename unique_map_ptr_x64<T>::integer_pointer>(vmap), size};

#else

    try
    {
        return unique_map_ptr_x64<T>(reinterpret_cast<typename unique_map_ptr_x64<T>::integer_pointer>(vmap),
                                     virt, cr3, size, attr);
    }
    catch (...)
    {
        g_mm->free_map(vmap);
        throw;
    }

    return unique_map_ptr_x64<T>();

#endif
}

/// Unique Map
///
/// Like std::unique_ptr, unique_map_ptr_x64 is a smart map that owns and
/// manages the mapping between virtual and physical memory. Memory is mapped
/// when the unique_map_ptr_x64 is first created, and unmapped when the
/// unique_map_ptr_x64 is destroyed.
///
/// Although this class can be used directly, it should be created using
/// make_unique_map_x64, which allocates the virtual memory for you as shown
/// in this example:
///
/// @b Example: @n
/// @code
/// std::cout << bfn::make_unique_map_x64<char>(phys) << '\n';
/// @endcode
///
/// Unlike std::unique_pointer, unique_map_ptr_x64 takes additional arguments
/// and doesn't support an array syntax. It should also be noted that this
/// class provides some additional helpers specific to a map including a way
/// to get it's size, as well as a means to flush TLB entries associated
/// with this map if needed (although when the map is created, the local
/// TLB is flushed for you, and thus this should only be needed if you
/// share this map with another core)
///
template <class T>
class unique_map_ptr_x64
{
public:

    using pointer = T*;
    using integer_pointer = uintptr_t;
    using size_type = size_t;
    using element_type = T;

    enum attr_type
    {
        map_none = 0,
        map_read_write = MEMORY_TYPE_R | MEMORY_TYPE_W
    };

    /// Default Map
    ///
    /// This constructor can be used to create a default map that maps to
    /// nothing
    ///
    unique_map_ptr_x64() :
        m_virt(0),
        m_size(0)
    { }

    /// Invalid Map
    ///
    /// This constructor can be used to create an invalid map that maps to
    /// nothing
    ///
    unique_map_ptr_x64(std::nullptr_t donotcare) :
        m_virt(0),
        m_size(0)
    { (void) donotcare; }

    /// Release Map
    ///
    /// This constructor can be used to create a map that maps to
    /// an exist virtual address and size. Note that this should be used
    /// with case as the original map must be released. Otherwise you will
    /// have two owners.
    ///
    unique_map_ptr_x64(integer_pointer virt, size_type size) :
        m_virt(virt),
        m_size(size)
    { }

    /// Map Single Page
    ///
    /// This constructor can be used to map a single virtual memory page to
    /// a single physical memory page.
    ///
    /// @b Example: @n
    /// @code
    /// std::cout << bfn::make_unique_map_x64<char>(phys) << '\n';
    /// @endcode
    ///
    /// @expects vmap != 0
    /// @expects vmap & (page_size - 1) == 0
    /// @expects phys != 0
    /// @expects attr != 0
    /// @ensures get() != nullptr
    ///
    /// @param vmap the virtual address to map the physical address to
    /// @param phys the physical address to map
    /// @param attr defines how to map the memory. Defaults to map_read_write
    ///
    unique_map_ptr_x64(integer_pointer vmap, integer_pointer phys, attr_type attr) :
        m_virt(0),
        m_size(page_size)
    {
        // [[ensures: get() != nullptr]]
        expects(vmap != 0);
        expects(lower(vmap) == 0);
        expects(phys != 0);
        expects(attr != map_none);

        m_virt |= lower(phys);
        m_virt |= upper(vmap);

        g_pt->map(vmap, upper(phys), attr);

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
    /// std::cout << bfn::make_unique_map_x64<char>(list) << '\n';
    /// @endcode
    ///
    /// @expects vmap != 0
    /// @expects vmap & (page_size - 1) == 0
    /// @expects list.empty() == false
    /// @expects list.at(i).first != 0
    /// @expects list.at(i).second != 0
    /// @expects list.at(i).second & (page_size - 1) == 0
    /// @expects attr != 0
    /// @ensures get() != nullptr
    ///
    /// @param vmap the virtual address to map the physical address to
    /// @param list list of std::pairs, each containing a physical address
    ///     and a size, defining a physical address range to add to the
    ///     virtual address mapping
    /// @param attr defines how to map the memory. Defaults to map_read_write
    ///
    unique_map_ptr_x64(integer_pointer vmap, const std::vector<std::pair<integer_pointer, size_type>> &list, attr_type attr) :
        m_virt(0),
        m_size(0)
    {
        // [[ensures: get() != nullptr]]
        expects(vmap != 0);
        expects(lower(vmap) == 0);
        expects(!list.empty());
        expects(attr != map_none);

        for (const auto &p : list)
        {
            expects(p.first != 0);
            expects(p.second != 0);
            expects(lower(p.second) == 0);

            m_size += p.second;
        }

        m_virt |= lower(list.front().first);
        m_virt |= upper(vmap);

        auto voff = 0UL;
        auto poff = 0UL;

        for (const auto &p : list)
        {
            auto phys = upper(p.first);
            auto size = p.second;

            for (poff = 0; poff < size; poff += page_size, voff += page_size)
                g_pt->map(vmap + voff, phys + poff, attr);
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
    /// std::cout << bfn::make_unique_map_x64<char>(virt, vmcs::guest_cr3::get(), size) << '\n';
    /// @endcode
    ///
    /// @expects vmap != 0
    /// @expects vmap & (page_size - 1) == 0
    /// @expects virt != 0
    /// @expects cr3 != 0
    /// @expects cr3 & (page_size - 1) == 0
    /// @expects size != 0
    /// @expects attr != 0
    /// @ensures get() != nullptr
    ///
    /// @param vmap the virtual address to map the range to
    /// @param virt the virtual address containing the existing mapping
    /// @param cr3 the root page table containing the existing virtual to
    ///     physical memory mappings
    /// @param size the number of bytes to map
    /// @param attr defines how to map the memory. Defaults to map_read_write
    ///
    unique_map_ptr_x64(integer_pointer vmap, integer_pointer virt, integer_pointer cr3, size_type size, attr_type attr) :
        m_virt(0),
        m_size(size)
    {
        // [[ensures: get() != nullptr]]
        expects(vmap != 0);
        expects(lower(vmap) == 0);
        expects(virt != 0);
        expects(cr3 != 0);
        expects(lower(cr3) == 0);
        expects(size != 0);
        expects(attr != map_none);

        m_virt |= lower(virt);
        m_virt |= upper(vmap);

        if (lower(virt) != 0)
            m_size += page_size;

        for (auto offset = 0UL; offset < m_size; offset += page_size)
        {
            auto vadr = vmap + offset;
            auto padr = virt_to_phys_with_cr3(upper(virt) + offset, cr3);

            g_pt->map(vadr, padr, attr);
        }

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
    /// The unique_map_ptr_x64 provided will no longer be valid, and the new
    /// unique_map_ptr_x64 will have the mapping provided. Note that this
    /// should be a fast operation, and no mapping / unmapping occurs. If the
    /// existing mapping is invalid, or already unmapped, the resulting
    /// unique_map_ptr_x64 will also be invalid / unmapped.
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param other the unique_map_ptr_x64 to move
    ///
    unique_map_ptr_x64(unique_map_ptr_x64 &&other) noexcept :
        m_virt(0),
        m_size(0)
    { reset(other.release()); }

    /// Destructor
    ///
    /// Unmaps any existing map this unique_map_ptr_x64 holds. Note that if
    /// an occurs while attempting to unmap, exceptions are caught and
    /// execution continues. If this occurs, the results are undefined.
    ///
    /// @expects none
    /// @ensures none
    ///
    virtual ~unique_map_ptr_x64() noexcept
    {
        guard_exceptions([&]
        { cleanup(m_virt, m_size); });

        m_virt = 0;
        m_size = 0;
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
    /// The unique_map_ptr_x64 provided will no longer be valid, and the new
    /// unique_map_ptr_x64 will have the mapping provided. Note that this
    /// should be a fast operation, and no mapping / unmapping occurs. If the
    /// existing mapping is invalid, or already unmapped, the resulting
    /// unique_map_ptr_x64 will also be invalid / unmapped.
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param other the unique_map_ptr_x64 to copy
    /// @return reference to this
    ///
    unique_map_ptr_x64 &operator=(unique_map_ptr_x64 &&other) noexcept
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
    /// The result of this operation is the current unique_map_ptr_x64 will
    /// be unmapped and invalid.
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param dontcare nullptr
    /// @return reference to this
    ///
    unique_map_ptr_x64 &operator=(std::nullptr_t dontcare) noexcept
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
    { return m_virt != 0 && m_size != 0; }

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
    /// unique_map_ptr_x64 and returns a std::pair containing the virtual
    /// address and size of the map. It is left to the user of this
    /// function to either deliver the std::pair to another unique_map_ptr_x64
    /// via reset(), or manually unmap / free the virtual address
    ///
    /// @note use with caution as this is an unsafe operation
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return returns a std::pair containing the virtual address and size
    ///     of the map. The user must manually unmap / free this memory
    ///
    auto release() noexcept
    {
        auto old_virt = m_virt;
        auto old_size = m_size;

        m_virt = 0;
        m_size = 0;

        return std::make_pair(reinterpret_cast<pointer>(old_virt), old_size);
    }

    /// Reset
    ///
    /// Like std::unique_ptr, this resets the unique_map_ptr_x64. If no
    /// args are provide, this function unmaps / frees the
    /// unique_map_ptr_x64 and the mapped memory becomes invalid. If a
    /// valid virtual address and size are provided, the current
    /// unique_map_ptr_x64 is unmapped and freed, and the newly provided
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
    ///
    void reset(pointer ptr = pointer(), size_type size = size_type()) noexcept
    {
        auto old_virt = m_virt;
        auto old_size = m_size;

        m_virt = reinterpret_cast<integer_pointer>(ptr);
        m_size = size;

        cleanup(old_virt, old_size);
    }

    /// Reset
    ///
    /// Like std::unique_ptr, this resets the unique_map_ptr_x64. If no
    /// args are provide, this function unmaps / frees the
    /// unique_map_ptr_x64 and the mapped memory becomes invalid. If a
    /// valid virtual address and size are provided, the current
    /// unique_map_ptr_x64 is unmapped and freed, and the newly provided
    /// virtual address and size are used in it's place.
    ///
    /// @note use with caution as this is an unsafe operation
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param p std::pair containing the virtual memory address and size in
    ///     bytes of the new mapping to use.
    ///
    void reset(const std::pair<pointer, size_type> &p) noexcept
    { reset(p.first, p.second); }

    /// Swap
    ///
    /// Swaps the mappings of one unique_map_ptr_x64 with another
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param other the unique_map_ptr_x64 to swap with
    ///
    void swap(unique_map_ptr_x64 &other) noexcept
    {
        std::swap(m_virt, other.m_virt);
        std::swap(m_size, other.m_size);
    }

    /// Flush
    ///
    /// Flushes the TLB entries associated with the virtual address ranges
    /// this unique_map_ptr_x64 holds. This is done automatically when
    /// mapping memory, but might be needed if this map is shared with
    /// another core whose TLB has not been properly flushed.
    ///
    /// @expects none
    /// @ensures none
    ///
    void flush() noexcept
    {
        auto &&vmap = upper(m_virt);
        for (auto vadr = vmap; vadr < vmap + m_size; vadr += page_size)
            tlb::invlpg(reinterpret_cast<pointer>(vadr));
    }

private:

    void cleanup(integer_pointer virt, size_type size) noexcept
    {
        if (virt != 0 && size != 0)
        {
            auto &&vmap = upper(virt);
            for (auto vadr = vmap; vadr < vmap + size; vadr += page_size)
                g_pt->unmap(vadr);

            g_mm->free_map(reinterpret_cast<pointer>(vmap));
        }
    }

    integer_pointer
    virt_to_phys_with_cr3(integer_pointer virt, integer_pointer phys)
    {
        auto from = page_table::pml4::from;

        for (; from >= page_table::pt::from; from -= page_table::pt::size)
        {
            auto map = bfn::make_unique_map_x64<memory_manager_x64::integer_pointer>(phys);
            auto map_view = gsl::make_span(map.get(), x64::page_table::num_entries);

            auto pte = page_table_entry_x64{&map_view.at(page_table::index(virt, from))};
            phys = pte.phys_addr();

            expects(phys != 0);
            expects(pte.present());

            if ((from == page_table::pt::from) || (pte.ps() == true))
                break;
        }

        return upper(phys, from) | lower(virt, from);
    }

    auto lower(integer_pointer ptr) const noexcept
    { return ptr & (page_size - 1); }

    auto lower(integer_pointer ptr, integer_pointer from) const noexcept
    { return ptr & ((0x1UL << from) - 1); }

    auto upper(integer_pointer ptr) const noexcept
    { return ptr & ~(page_size - 1); }

    auto upper(integer_pointer ptr, integer_pointer from) const noexcept
    { return ptr & ~((0x1UL << from) - 1); }

private:

    integer_pointer m_virt;
    size_type m_size;

public:

    unique_map_ptr_x64(const unique_map_ptr_x64 &) = delete;
    unique_map_ptr_x64 &operator=(const unique_map_ptr_x64 &) = delete;
};

template <class T>
void swap(unique_map_ptr_x64<T> &x, unique_map_ptr_x64<T> &y) noexcept
{ x.swap(y); }

template <class T1, class T2>
bool operator==(const unique_map_ptr_x64<T1> &x, const unique_map_ptr_x64<T2> &y)
{ return x.get() == y.get(); }

template <class T1, class T2>
bool operator!=(const unique_map_ptr_x64<T1> &x, const unique_map_ptr_x64<T2> &y)
{ return x.get() != y.get(); }

template <class T1, class T2>
bool operator<(const unique_map_ptr_x64<T1> &x, const unique_map_ptr_x64<T2> &y)
{ return x.get() < y.get(); }

template <class T1, class T2>
bool operator<=(const unique_map_ptr_x64<T1> &x, const unique_map_ptr_x64<T2> &y)
{ return x.get() <= y.get(); }

template <class T1, class T2>
bool operator>(const unique_map_ptr_x64<T1> &x, const unique_map_ptr_x64<T2> &y)
{ return x.get() > y.get(); }

template <class T1, class T2>
bool operator>=(const unique_map_ptr_x64<T1> &x, const unique_map_ptr_x64<T2> &y)
{ return x.get() >= y.get(); }

template <class T>
bool operator==(const unique_map_ptr_x64<T> &x, std::nullptr_t dontcare) noexcept
{ (void) dontcare; return !x; }

template <class T>
bool operator==(std::nullptr_t dontcare, const unique_map_ptr_x64<T> &y) noexcept
{ (void) dontcare; return !y; }

template <class T>
bool operator!=(const unique_map_ptr_x64<T> &x, std::nullptr_t dontcare) noexcept
{ (void) dontcare; return x; }

template <class T>
bool operator!=(std::nullptr_t dontcare, const unique_map_ptr_x64<T> &y) noexcept
{ (void) dontcare; return y; }

}

#endif
