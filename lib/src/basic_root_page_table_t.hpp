/// @copyright
/// Copyright (C) 2020 Assured Information Security, Inc.
///
/// @copyright
/// Permission is hereby granted, free of charge, to any person obtaining a copy
/// of this software and associated documentation files (the "Software"), to deal
/// in the Software without restriction, including without limitation the rights
/// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
/// copies of the Software, and to permit persons to whom the Software is
/// furnished to do so, subject to the following conditions:
///
/// @copyright
/// The above copyright notice and this permission notice shall be included in
/// all copies or substantial portions of the Software.
///
/// @copyright
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
/// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
/// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
/// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
/// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
/// SOFTWARE.

#ifndef BASIC_ROOT_PAGE_TABLE_T_HPP
#define BASIC_ROOT_PAGE_TABLE_T_HPP

#include <basic_alloc_page_t.hpp>
#include <basic_entries_t.hpp>
#include <basic_entry_status_t.hpp>
#include <basic_lock_guard_t.hpp>
#include <basic_map_page_flags.hpp>
#include <basic_page_1g_t.hpp>
#include <basic_page_2m_t.hpp>
#include <basic_page_4k_t.hpp>
#include <basic_page_table_t.hpp>
#include <basic_spinlock_t.hpp>
#include <basic_tlb_flush_type_t.hpp>

#include <bsl/construct_at.hpp>
#include <bsl/convert.hpp>
#include <bsl/debug.hpp>
#include <bsl/ensures.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/expects.hpp>
#include <bsl/finally.hpp>
#include <bsl/is_one_of.hpp>
#include <bsl/is_same.hpp>
#include <bsl/remove_const.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/touch.hpp>
#include <bsl/unlikely.hpp>

namespace lib
{
    /// @class lib::basic_root_page_table_t
    ///
    /// <!-- description -->
    ///   @brief Implements an interface to a root page table. The root page
    ///     table (RPT) is the highest level page table, and provides an
    ///     interface for mapping and unmapping memory in the page tables
    ///     managed by the RPT. Bareflank currently only supports 4-level
    ///     paging.
    ///
    ///     All tables must use the following naming scheme, not matter what
    ///     the architecture is:
    ///     - l0t_t: a pt on x86, the l3 table on ARM
    ///     - l0e_t: a pt entry on x86, the l3 table entry on ARM
    ///     - l1t_t: a pdt on x86, the l2 table on ARM
    ///     - l1e_t: a pdt entry on x86, the l2 table entry on ARM
    ///     - l2t_t: a pdpt on x86, the l1 table on ARM
    ///     - l2e_t: a pdpt entry on x86, the l1 table entry on ARM
    ///     - l3t_t: a pml4t on x86, the l0 table on ARM
    ///     - l3e_t: a pml4t entry on x86, the l0 table entry on ARM
    ///
    ///     You will notice that on ARM, the numbers are in reverse order.
    ///     This is to help deal with 5-level paging in the future. On ARM
    ///     you end up with negative numbers which is absurd. We also don't
    ///     use Intel's naming scheme which is also equally as horrible.
    ///
    ///     There are also a couple of definitions that are important to
    ///     understand:
    ///     - block: Also called a page, the actual memory that is mapped.
    ///       It can be 4K, 2MB or 1G in size. We call this a block to simplify
    ///       things as ARM also uses the block name (sort of).
    ///     - entry: Also called a page table entry, points to either a block
    ///       or a table. If the entry points to a block, it is a leaf in the
    ///       table, and the points_to_block bit is set. If the entry
    ///       points to a table, the points_to_block bit is not set, and
    ///       translations must continue to the table and repeat until a
    ///       block is found. The points_to_block bit is defined below.
    ///     - table: Also called a page table, contains a list of entries.
    ///
    ///     The root page table for 4-level paging is a pointer to an l3t_t.
    ///     Every table contains entries that either point to another table
    ///     or a block. If traversal stops a level 2 (i.e., the L2E_TYPE has the
    ///     points_to_block set), the table entry points to a 1G block of
    ///     memory. If traversal stops a level 1 (i.e., the L1E_TYPE has the
    ///     points_to_block set), the table entry points to a 2M block of
    ///     memory. If traversal stops a level 0 (i.e., the L0E_TYPE has the
    ///     points_to_block set), the table entry points to a 4K block of
    ///     memory.
    ///
    ///     We do require some "software available bits" in the each entry.
    ///     The following is required:
    ///     - a 1bit auto_release field, which is used to determine if memory
    ///       should be auto_released by the RPT when a page is unmapped. We
    ///       only support this bit with 4k pages.
    ///     - a 1bit points_to_block field, which tells the RPT when to stop
    ///       traversing tables because a block has been found. If this bit
    ///       is 1, the entry points to a block. If this bit is 0, the entry
    ///       points to a table. On some architectures, this bit might already
    ///       exist with the same 0/1 definition, in which case it simply needs
    ///       to be renamed to "points_to_block". On other systems like x86,
    ///       it is not that simple which is why we have our own version of
    ///       this bit.
    ///     - a 1bit alias field, which tells the RPT that the entry points
    ///       to a table owned by a different RPT. If this bit is set, when
    ///       the RPT is released, it will not deallocate page tables with
    ///       the alias bit set.
    ///     - a 1bit require_explicit_unmap field, which tells the RPT that
    ///       the map must be explicitly unmapped before the RPT can be
    ///       released. For example, if you allocate memory and then use
    ///       the map function, you will likely want to set this flag to
    ///       true. If however, you are simply mapping a virtual address that
    ///       has no need for a physical page to back it, as would be the
    ///       case with the direct map, or with second level paging, you
    ///       would set this flag to false (which is the default).
    ///
    ///     Also, every entry must also have a "phys" field that represents
    ///     the physical address of the table or block the entry points to.
    ///     This phys field must be 40 bits in size (meaning we only support
    ///     52 bits of addressable physical memory, which is the case for most
    ///     64bit architectures). For 2M and 1G maps, the phys field must still
    ///     be 40 bits in size. What this means is that any physical address
    ///     that is mapped to 1G or 2M, will only have it's bits shifted by
    ///     12 (or the equivalent of a 4k page). This is because entries can
    ///     either point to a block or a table. In the case of a block, a 1G
    ///     or 2M physical address must have bits 29:12 and 20:12 set to 0.
    ///     In the case of a table however, for which we only support 4k
    ///     aligned tables, bits 29:12 and 20:12 still have meaning. On some
    ///     architectures like x86, some of these bits that would always be 0
    ///     are repurposed and have special meaning. This is still supported,
    ///     but the helper functions will have to use a bit mask on the phys
    ///     field instead of setting a bit directly as, again, the phys field
    ///     must be 40 bits, and these special bits for 1G and 2M will be set
    ///     to 0 by the map functions.
    ///
    ///     The idea is this one RPT implementation should be useable for
    ///     all architectures, as well as any second level paging needs that
    ///     extensions might have, which means this needs to be useable with
    ///     nested paging on AMD, extended paging on Intel and stage 2 paging
    ///     on ARM.
    ///
    ///     TODO:
    ///     - In the future we need to add 5-level paging support. This should
    ///       simply require that a template argument is added so that the
    ///       code knows whether to use 4-level or 5-level. This would also
    ///       add an l4t_t and an l4e_t. The bsl::bool_constant class can be
    ///       used below to determine (based on a template parameter), whether
    ///       the root page table should use an l3t_t or an l4t_t. From there,
    ///       the map and unmap functions will need an if constexpr () to
    ///       add support for the 5th level of paging if needed. Everything
    ///       else is recursive so it should work fine.
    ///
    /// <!-- template parameters -->
    ///   @tparam TLS_TYPE the type of TLS block to use
    ///   @tparam PAGE_POOL_TYPE the type page_pool_t to use
    ///   @tparam INTRINSIC_TYPE the type intrinsic_t to use
    ///   @tparam L3E_TYPE the level-3 page table entry to use
    ///   @tparam L2E_TYPE the level-2 page table entry to use
    ///   @tparam L1E_TYPE the level-1 page table entry to use
    ///   @tparam L0E_TYPE the level-0 page table entry to use
    ///
    template<
        typename TLS_TYPE,
        typename PAGE_POOL_TYPE,
        typename INTRINSIC_TYPE,
        typename L3E_TYPE,
        typename L2E_TYPE,
        typename L1E_TYPE,
        typename L0E_TYPE>
    class basic_root_page_table_t final
    {
        /// @brief define the type for a level-0 page table
        using l0t_t = basic_page_table_t<L0E_TYPE>;
        /// @brief define the type for a level-1 page table
        using l1t_t = basic_page_table_t<L1E_TYPE>;
        /// @brief define the type for a level-2 page table
        using l2t_t = basic_page_table_t<L2E_TYPE>;
        /// @brief define the type for a level-3 page table
        using l3t_t = basic_page_table_t<L3E_TYPE>;
        /// @brief define the type entries_t to use
        using entries_t = basic_entries_t<L3E_TYPE, L2E_TYPE, L1E_TYPE, L0E_TYPE>;

        /// @brief stores a pointer to the l3t
        l3t_t *m_l3t{};
        /// @brief stores the physical address of the l3t
        bsl::safe_umx m_l3t_phys{};
        /// @brief safe guards operations on the RPT.
        mutable basic_spinlock_t m_lock{};

        /// <!-- description -->
        ///   @brief Returns the level-3 table (L3T) offset given a
        ///     virtual address.
        ///
        /// <!-- inputs/outputs -->
        ///   @param virt the virtual address to get the offset from.
        ///   @return the resulting offset from the virtual address
        ///
        [[nodiscard]] static constexpr auto
        virt_to_l3to(bsl::safe_u64 const &virt) noexcept -> bsl::safe_idx
        {
            constexpr auto mask{0x1FF_u64};
            constexpr auto shft{39_u64};
            return bsl::to_idx((virt >> shft) & mask);
        }

        /// <!-- description -->
        ///   @brief Returns the level-2 table (L2T) offset given a
        ///     virtual address.
        ///
        /// <!-- inputs/outputs -->
        ///   @param virt the virtual address to get the offset from.
        ///   @return the resulting offset from the virtual address
        ///
        [[nodiscard]] static constexpr auto
        virt_to_l2to(bsl::safe_u64 const &virt) noexcept -> bsl::safe_idx
        {
            constexpr auto mask{0x1FF_u64};
            constexpr auto shft{30_u64};
            return bsl::to_idx((virt >> shft) & mask);
        }

        /// <!-- description -->
        ///   @brief Returns the level-1 table (L1T) offset given a
        ///     virtual address.
        ///
        /// <!-- inputs/outputs -->
        ///   @param virt the virtual address to get the offset from.
        ///   @return the resulting offset from the virtual address
        ///
        [[nodiscard]] static constexpr auto
        virt_to_l1to(bsl::safe_u64 const &virt) noexcept -> bsl::safe_idx
        {
            constexpr auto mask{0x1FF_u64};
            constexpr auto shft{21_u64};
            return bsl::to_idx((virt >> shft) & mask);
        }

        /// <!-- description -->
        ///   @brief Returns the level-0 table (L0T) offset given a
        ///     virtual address.
        ///
        /// <!-- inputs/outputs -->
        ///   @param virt the virtual address to get the offset from.
        ///   @return the resulting offset from the virtual address
        ///
        [[nodiscard]] static constexpr auto
        virt_to_l0to(bsl::safe_u64 const &virt) noexcept -> bsl::safe_idx
        {
            constexpr auto mask{0x1FF_u64};
            constexpr auto shft{12_u64};
            return bsl::to_idx((virt >> shft) & mask);
        }

        /// <!-- description -->
        ///   @brief Returns true if the provided address is 1g page aligned.
        ///     Returns false otherwise.
        ///
        /// <!-- inputs/outputs -->
        ///   @param addr the address to query
        ///   @return Returns true if the provided address is 1g page aligned.
        ///     Returns false otherwise.
        ///
        [[nodiscard]] static constexpr auto
        is_page_1g_aligned(bsl::safe_u64 const &addr) noexcept -> bool
        {
            return (addr & BASIC_PAGE_1G_T_MASK).is_zero();
        }

        /// <!-- description -->
        ///   @brief Returns true if the provided address is 2m page aligned.
        ///     Returns false otherwise.
        ///
        /// <!-- inputs/outputs -->
        ///   @param addr the address to query
        ///   @return Returns true if the provided address is 2m page aligned.
        ///     Returns false otherwise.
        ///
        [[nodiscard]] static constexpr auto
        is_page_2m_aligned(bsl::safe_u64 const &addr) noexcept -> bool
        {
            return (addr & BASIC_PAGE_2M_T_MASK).is_zero();
        }

        /// <!-- description -->
        ///   @brief Returns true if the provided address is 4k page aligned.
        ///     Returns false otherwise.
        ///
        /// <!-- inputs/outputs -->
        ///   @param addr the address to query
        ///   @return Returns true if the provided address is 4k page aligned.
        ///     Returns false otherwise.
        ///
        [[nodiscard]] static constexpr auto
        is_page_4k_aligned(bsl::safe_u64 const &addr) noexcept -> bool
        {
            return (addr & BASIC_PAGE_4K_T_MASK).is_zero();
        }

        /// <!-- description -->
        ///   @brief Returns the 1g page aligned version of addr.
        ///
        /// <!-- inputs/outputs -->
        ///   @param addr the address to page align
        ///   @return Returns the 1g page aligned version of addr
        ///
        [[nodiscard]] static constexpr auto
        page_1g_aligned(bsl::safe_u64 const &addr) noexcept -> bsl::safe_u64
        {
            return (addr & (~BASIC_PAGE_1G_T_MASK));
        }

        /// <!-- description -->
        ///   @brief Returns the 2m page aligned version of addr.
        ///
        /// <!-- inputs/outputs -->
        ///   @param addr the address to page align
        ///   @return Returns the 2m page aligned version of addr
        ///
        [[nodiscard]] static constexpr auto
        page_2m_aligned(bsl::safe_u64 const &addr) noexcept -> bsl::safe_u64
        {
            return (addr & (~BASIC_PAGE_2M_T_MASK));
        }

        /// <!-- description -->
        ///   @brief Returns the 4k page aligned version of addr.
        ///
        /// <!-- inputs/outputs -->
        ///   @param addr the address to page align
        ///   @return Returns the 4k page aligned version of addr
        ///
        [[nodiscard]] static constexpr auto
        page_4k_aligned(bsl::safe_u64 const &addr) noexcept -> bsl::safe_u64
        {
            return (addr & (~BASIC_PAGE_4K_T_MASK));
        }

        /// <!-- description -->
        ///   @brief Returns the virtual address of a basic_page_4k_t given a
        ///     table entry.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam E the type of entry to query
        ///   @param page_pool the page_pool_t to use
        ///   @param pmut_entry the entry to query
        ///   @return Returns the virtual address of a basic_page_4k_t given a
        ///     table entry.
        ///
        template<typename E>
        [[nodiscard]] static constexpr auto
        // NOLINTNEXTLINE(bsl-auto-type-usage)
        entry_to_block(PAGE_POOL_TYPE const &page_pool, E *const pmut_entry) noexcept -> auto
        {
            static_assert(bsl::is_one_of<bsl::remove_const_t<E>, L0E_TYPE>::value);

            if constexpr (bsl::is_same<bsl::remove_const_t<E>, L0E_TYPE>::value) {
                return page_pool.template phys_to_virt<basic_page_4k_t>(
                    pmut_entry->phys << BASIC_PAGE_4K_T_SHFT);
            }
        }

        /// <!-- description -->
        ///   @brief Returns the virtual address of a l2t_t, l1t_t, or l0t_t
        ///     given a table entry.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam E the type of entry to query
        ///   @param page_pool the page_pool_t to use
        ///   @param pmut_entry the entry to convert
        ///   @return Returns the virtual address of a l2t_t, l1t_t, or l0t_t
        ///     given a table entry.
        ///
        template<typename E>
        [[nodiscard]] static constexpr auto
        // NOLINTNEXTLINE(bsl-auto-type-usage)
        entry_to_table(PAGE_POOL_TYPE const &page_pool, E *const pmut_entry) noexcept -> auto
        {
            static_assert(
                bsl::is_one_of<bsl::remove_const_t<E>, L3E_TYPE, L2E_TYPE, L1E_TYPE>::value);

            if constexpr (bsl::is_same<bsl::remove_const_t<E>, L3E_TYPE>::value) {
                return page_pool.template phys_to_virt<l2t_t>(
                    pmut_entry->phys << BASIC_PAGE_4K_T_SHFT);
            }

            if constexpr (bsl::is_same<bsl::remove_const_t<E>, L2E_TYPE>::value) {
                return page_pool.template phys_to_virt<l1t_t>(
                    pmut_entry->phys << BASIC_PAGE_4K_T_SHFT);
            }

            if constexpr (bsl::is_same<bsl::remove_const_t<E>, L1E_TYPE>::value) {
                return page_pool.template phys_to_virt<l0t_t>(
                    pmut_entry->phys << BASIC_PAGE_4K_T_SHFT);
            }
        }

        /// <!-- description -->
        ///   @brief Returns a pointer to a newly allocated table. On failure
        ///     returns a nullptr.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam E the type of entry to allocate a table for
        ///   @param mut_tls the current TLS block
        ///   @param mut_page_pool the page_pool_t to use
        ///   @return Returns a pointer to a newly allocated table. On failure
        ///     returns a nullptr.
        ///
        template<typename E>
        [[nodiscard]] static constexpr auto
        // NOLINTNEXTLINE(bsl-auto-type-usage)
        allocate_table(TLS_TYPE &mut_tls, PAGE_POOL_TYPE &mut_page_pool) noexcept -> auto
        {
            static_assert(bsl::is_one_of<E, L3E_TYPE, L2E_TYPE, L1E_TYPE>::value);

            if constexpr (bsl::is_same<bsl::remove_const_t<E>, L3E_TYPE>::value) {
                return mut_page_pool.template allocate<l2t_t>(mut_tls);
            }

            if constexpr (bsl::is_same<bsl::remove_const_t<E>, L2E_TYPE>::value) {
                return mut_page_pool.template allocate<l1t_t>(mut_tls);
            }

            if constexpr (bsl::is_same<bsl::remove_const_t<E>, L1E_TYPE>::value) {
                return mut_page_pool.template allocate<l0t_t>(mut_tls);
            }
        }

        /// <!-- description -->
        ///   @brief Creates a table, and tells the provided entry to point
        ///     to this newly created table.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam E the type of entry to add the table to
        ///   @param mut_tls the current TLS block
        ///   @param mut_page_pool the page_pool_t to use
        ///   @param pmut_entry the entry to configure to point to the newly
        ///     created table
        ///   @return Returns a pointer to the newly created table on success.
        ///     Returns nullptr on failure.
        ///
        template<typename E>
        [[nodiscard]] static constexpr auto
        add_table(TLS_TYPE &mut_tls, PAGE_POOL_TYPE &mut_page_pool, E *const pmut_entry) noexcept
            -> decltype(allocate_table<E>(mut_tls, mut_page_pool))
        {
            auto *const pmut_table{allocate_table<E>(mut_tls, mut_page_pool)};
            if (bsl::unlikely(nullptr == pmut_table)) {
                bsl::print<bsl::V>() << bsl::here();
                return nullptr;
            }

            auto mut_table_phys{mut_page_pool.virt_to_phys(pmut_table)};
            bsl::expects(mut_table_phys.is_valid_and_checked());
            bsl::expects(mut_table_phys.is_pos());

            pmut_entry->auto_release = bsl::safe_u64::magic_0().get();
            pmut_entry->points_to_block = bsl::safe_u64::magic_0().get();
            pmut_entry->alias = bsl::safe_u64::magic_0().get();
            pmut_entry->phys = (mut_table_phys >> BASIC_PAGE_4K_T_SHFT).get();
            pmut_entry->require_explicit_unmap = bsl::safe_u64::magic_0().get();
            helpers::configure_entry_as_ptr_to_table(pmut_entry);

            return pmut_table;
        }

        /// <!-- description -->
        ///   @brief Given a table, recursively deallocates the table.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam T the type of table to release
        ///   @param mut_tls the current TLS block
        ///   @param mut_page_pool the page_pool_t to use
        ///   @param pmut_table the table to release
        ///   @return Returns true if the table is empty. Returns
        ///     false otherwise.
        ///
        template<typename T>
        [[maybe_unused]] static constexpr auto
        release_table(
            TLS_TYPE &mut_tls, PAGE_POOL_TYPE &mut_page_pool, T *const pmut_table) noexcept -> bool
        {
            bool mut_empty{true};

            for (bsl::safe_idx mut_i{}; mut_i < pmut_table->entries.size(); ++mut_i) {
                auto *const pmut_entry{pmut_table->entries.at_if(mut_i)};
                if (!release_entry(mut_tls, mut_page_pool, pmut_entry)) {
                    mut_empty = false;
                }
                else {
                    bsl::touch();
                }
            }

            if (!mut_empty) {
                return false;
            }

            mut_page_pool.deallocate(mut_tls, pmut_table);
            return true;
        }

        /// <!-- description -->
        ///   @brief Given an entry, calls release_block if the entry points
        ///     to a block and calls release_table if the entry points to a
        ///     table.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam E the type of entry to release the table from
        ///   @param mut_tls the current TLS block
        ///   @param mut_page_pool the page_pool_t to use
        ///   @param pmut_entry the entry that points to the table to release
        ///   @return Returns true if the entry points to an empty block
        ///     or table. Returns false otherwise.
        ///
        template<typename E>
        [[maybe_unused]] static constexpr auto
        release_entry(
            TLS_TYPE &mut_tls, PAGE_POOL_TYPE &mut_page_pool, E *const pmut_entry) noexcept -> bool
        {
            bool mut_empty{};

            if (helpers::entry_status(pmut_entry) != basic_entry_status_t::present) {
                return true;
            }

            if (bsl::safe_u64::magic_1() == pmut_entry->alias) {
                return true;
            }

            if (bsl::safe_u64::magic_1() == pmut_entry->points_to_block) {
                if constexpr (bsl::is_same<E, L0E_TYPE>::value) {
                    if (bsl::safe_u64::magic_1() == pmut_entry->auto_release) {
                        mut_page_pool.deallocate(
                            mut_tls, entry_to_block(mut_page_pool, pmut_entry));
                    }
                    else {
                        bsl::touch();
                    }
                }

                mut_empty = (bsl::safe_u64::magic_1() != pmut_entry->require_explicit_unmap);
            }
            else {
                if constexpr (bsl::is_same<E, L3E_TYPE>::value) {
                    mut_empty = release_table(
                        mut_tls, mut_page_pool, entry_to_table(mut_page_pool, pmut_entry));
                }

                if constexpr (bsl::is_same<E, L2E_TYPE>::value) {
                    mut_empty = release_table(
                        mut_tls, mut_page_pool, entry_to_table(mut_page_pool, pmut_entry));
                }

                if constexpr (bsl::is_same<E, L1E_TYPE>::value) {
                    mut_empty = release_table(
                        mut_tls, mut_page_pool, entry_to_table(mut_page_pool, pmut_entry));
                }
            }

            if (!mut_empty) {
                return false;
            }

            *pmut_entry = {};
            return true;
        }

        /// <!-- description -->
        ///   @brief Returns all of the entries that are identified during the
        ///     translation of the provided virtual address.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam E the entry type requested. For example, if a 1G
        ///     map/unmap request is made, E should be L2E_TYPE.
        ///   @tparam MAP_OP if true, this function will add tables to the
        ///     heirarchy as needed. If false, when a non-present entry is
        ///     encountered, a nullptr will be returned instead. MAP_OP
        ///     should be set to true for all map style functions, while
        ///     MAP_OP should be set to false when modifying an existing
        ///     map, or unmapping a previously mapped virtual address.
        ///   @param mut_tls the current TLS block
        ///   @param mut_page_pool the page_pool_t to use
        ///   @param page_virt the virtual address to decode
        ///   @return Returns all of the entries that are identified during the
        ///     translation of the provided virtual address.
        ///
        template<typename E, bool MAP_OP = true>
        [[nodiscard]] constexpr auto
        get_entries(
            TLS_TYPE &mut_tls,
            PAGE_POOL_TYPE &mut_page_pool,
            bsl::safe_u64 const &page_virt) noexcept -> entries_t
        {
            entries_t mut_ret{};
            l2t_t *pmut_mut_l2t{};
            l1t_t *pmut_mut_l1t{};
            l0t_t *pmut_mut_l0t{};

            bsl::finally mut_release_l2t_on_error{
                bsl::dormant, [&mut_tls, &mut_page_pool, &mut_ret]() noexcept -> void {
                    if constexpr (MAP_OP) {
                        release_entry(mut_tls, mut_page_pool, mut_ret.l3e);
                    }
                    else {
                        bsl::discard(mut_tls);
                        bsl::discard(mut_page_pool);
                        bsl::discard(mut_ret);
                    }
                }};

            bsl::finally mut_release_l1t_on_error{
                bsl::dormant, [&mut_tls, &mut_page_pool, &mut_ret]() noexcept -> void {
                    if constexpr (MAP_OP) {
                        release_entry(mut_tls, mut_page_pool, mut_ret.l2e);
                    }
                    else {
                        bsl::discard(mut_tls);
                        bsl::discard(mut_page_pool);
                        bsl::discard(mut_ret);
                    }
                }};

            bsl::finally mut_release_l0t_on_error{
                bsl::dormant, [&mut_tls, &mut_page_pool, &mut_ret]() noexcept -> void {
                    if constexpr (MAP_OP) {
                        release_entry(mut_tls, mut_page_pool, mut_ret.l1e);
                    }
                    else {
                        bsl::discard(mut_tls);
                        bsl::discard(mut_page_pool);
                        bsl::discard(mut_ret);
                    }
                }};

            mut_ret.l3e = m_l3t->entries.at_if(virt_to_l3to(page_virt));
            switch (helpers::entry_status(mut_ret.l3e)) {
                case basic_entry_status_t::not_present: {
                    if constexpr (MAP_OP) {
                        if constexpr (bsl::is_same<E, L2E_TYPE>::value) {
                            return mut_ret;
                        }

                        pmut_mut_l2t = add_table(mut_tls, mut_page_pool, mut_ret.l3e);
                        if (bsl::unlikely(nullptr == pmut_mut_l2t)) {
                            bsl::print<bsl::V>() << bsl::here();
                            return {};
                        }

                        mut_release_l2t_on_error.activate();
                    }
                    else {
                        bsl::error() << "l3t_t entry for the virtual address "    // --
                                     << bsl::hex(page_virt)                       // --
                                     << " is not marked present"                  // --
                                     << bsl::endl                                 // --
                                     << bsl::here();                              // --

                        return {};
                    }

                    break;
                }

                case basic_entry_status_t::present: {
                    if (bsl::safe_u64::magic_1() == mut_ret.l3e->points_to_block) {
                        return mut_ret;
                    }

                    pmut_mut_l2t = entry_to_table(mut_page_pool, mut_ret.l3e);
                    break;
                }

                case basic_entry_status_t::reserved: {
                    bsl::error() << "l3t_t entry for the virtual address "             // --
                                 << bsl::hex(page_virt)                                // --
                                 << " is not marked reserved and cannot be queried"    // --
                                 << bsl::endl                                          // --
                                 << bsl::here();                                       // --

                    return {};
                }
            }

            mut_ret.l2e = pmut_mut_l2t->entries.at_if(virt_to_l2to(page_virt));
            switch (helpers::entry_status(mut_ret.l2e)) {
                case basic_entry_status_t::not_present: {
                    if constexpr (MAP_OP) {
                        if constexpr (bsl::is_same<E, L2E_TYPE>::value) {
                            mut_release_l2t_on_error.ignore();
                            return mut_ret;
                        }

                        pmut_mut_l1t = add_table(mut_tls, mut_page_pool, mut_ret.l2e);
                        if (bsl::unlikely(nullptr == pmut_mut_l1t)) {
                            bsl::print<bsl::V>() << bsl::here();
                            return {};
                        }

                        mut_release_l1t_on_error.activate();
                    }
                    else {
                        bsl::error() << "l2t_t entry for the virtual address "    // --
                                     << bsl::hex(page_virt)                       // --
                                     << " is not marked present"                  // --
                                     << bsl::endl                                 // --
                                     << bsl::here();                              // --

                        return {};
                    }

                    break;
                }

                case basic_entry_status_t::present: {
                    if (bsl::safe_u64::magic_1() == mut_ret.l2e->points_to_block) {
                        if constexpr (MAP_OP) {
                            mut_release_l2t_on_error.ignore();
                        }

                        return mut_ret;
                    }

                    pmut_mut_l1t = entry_to_table(mut_page_pool, mut_ret.l2e);
                    break;
                }

                case basic_entry_status_t::reserved: {
                    bsl::error() << "l2t_t entry for the virtual address "             // --
                                 << bsl::hex(page_virt)                                // --
                                 << " is not marked reserved and cannot be queried"    // --
                                 << bsl::endl                                          // --
                                 << bsl::here();                                       // --

                    return {};
                }
            }

            mut_ret.l1e = pmut_mut_l1t->entries.at_if(virt_to_l1to(page_virt));
            switch (helpers::entry_status(mut_ret.l1e)) {
                case basic_entry_status_t::not_present: {
                    if constexpr (MAP_OP) {
                        if constexpr (bsl::is_same<E, L1E_TYPE>::value) {
                            mut_release_l1t_on_error.ignore();
                            mut_release_l2t_on_error.ignore();
                            return mut_ret;
                        }

                        pmut_mut_l0t = add_table(mut_tls, mut_page_pool, mut_ret.l1e);
                        if (bsl::unlikely(nullptr == pmut_mut_l0t)) {
                            bsl::print<bsl::V>() << bsl::here();
                            return {};
                        }

                        mut_release_l0t_on_error.activate();
                    }
                    else {
                        bsl::error() << "l1t_t entry for the virtual address "    // --
                                     << bsl::hex(page_virt)                       // --
                                     << " is not marked present"                  // --
                                     << bsl::endl                                 // --
                                     << bsl::here();                              // --

                        return {};
                    }

                    break;
                }

                case basic_entry_status_t::present: {
                    if (bsl::safe_u64::magic_1() == mut_ret.l1e->points_to_block) {
                        if constexpr (MAP_OP) {
                            mut_release_l1t_on_error.ignore();
                            mut_release_l2t_on_error.ignore();
                        }

                        return mut_ret;
                    }

                    pmut_mut_l0t = entry_to_table(mut_page_pool, mut_ret.l1e);
                    break;
                }

                case basic_entry_status_t::reserved: {
                    bsl::error() << "l1t_t entry for the virtual address "             // --
                                 << bsl::hex(page_virt)                                // --
                                 << " is not marked reserved and cannot be queried"    // --
                                 << bsl::endl                                          // --
                                 << bsl::here();                                       // --

                    return {};
                }
            }

            mut_ret.l0e = pmut_mut_l0t->entries.at_if(virt_to_l0to(page_virt));
            switch (helpers::entry_status(mut_ret.l0e)) {
                case basic_entry_status_t::not_present: {
                    mut_release_l0t_on_error.ignore();
                    mut_release_l1t_on_error.ignore();
                    mut_release_l2t_on_error.ignore();
                    return mut_ret;
                }

                case basic_entry_status_t::present: {
                    mut_release_l0t_on_error.ignore();
                    mut_release_l1t_on_error.ignore();
                    mut_release_l2t_on_error.ignore();
                    return mut_ret;
                }

                case basic_entry_status_t::reserved: {
                    bsl::error() << "l1t_t entry for the virtual address "             // --
                                 << bsl::hex(page_virt)                                // --
                                 << " is not marked reserved and cannot be queried"    // --
                                 << bsl::endl                                          // --
                                 << bsl::here();                                       // --

                    return {};
                }
            }
        }

        /// <!-- description -->
        ///   @brief Returns the requested entry from the provided entries.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam E the entry to get from an entries_t
        ///   @param ents the entries to get the requested entry from
        ///   @return Returns the requested entry from the provided entries
        ///
        template<typename E>
        [[nodiscard]] static constexpr auto
        // NOLINTNEXTLINE(bsl-auto-type-usage)
        get_entry_from_entries(entries_t const &ents) noexcept -> auto
        {
            static_assert(bsl::is_one_of<E, L2E_TYPE, L1E_TYPE, L0E_TYPE>::value);

            if constexpr (bsl::is_same<bsl::remove_const_t<E>, L2E_TYPE>::value) {
                return ents.l2e;
            }

            if constexpr (bsl::is_same<bsl::remove_const_t<E>, L1E_TYPE>::value) {
                return ents.l1e;
            }

            if constexpr (bsl::is_same<bsl::remove_const_t<E>, L0E_TYPE>::value) {
                return ents.l0e;
            }
        }

    public:
        /// <!-- description -->
        ///   @brief Initializes this basic_root_page_table_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param mut_page_pool the page_pool_t to use
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        initialize(TLS_TYPE &mut_tls, PAGE_POOL_TYPE &mut_page_pool) noexcept -> bsl::errc_type
        {
            bsl::expects(nullptr == m_l3t);

            m_l3t = mut_page_pool.template allocate<l3t_t>(mut_tls);
            if (bsl::unlikely(nullptr == m_l3t)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            m_l3t_phys = mut_page_pool.virt_to_phys(m_l3t);
            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Releases all of the resources used by the RPT.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param mut_page_pool the page_pool_t to use
        ///
        constexpr void
        release(TLS_TYPE &mut_tls, PAGE_POOL_TYPE &mut_page_pool) noexcept
        {
            if (bsl::unlikely(nullptr == m_l3t)) {
                return;
            }

            this->release_table(mut_tls, mut_page_pool, m_l3t);

            m_l3t_phys = {};
            m_l3t = {};
        }

        /// <!-- description -->
        ///   @brief Returns true if this RPT is initialized.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if this RPT is initialized.
        ///
        [[nodiscard]] constexpr auto
        is_initialized() const noexcept -> bool
        {
            return nullptr != m_l3t;
        }

        /// <!-- description -->
        ///   @brief Sets the current root page table to this root page table.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param mut_intrinsic the intrinsic_t to use
        ///
        constexpr void
        activate(TLS_TYPE &mut_tls, INTRINSIC_TYPE &mut_intrinsic) noexcept
        {
            bsl::expects(nullptr != m_l3t);

            mut_tls.active_rpt = this;
            mut_intrinsic.set_rpt(m_l3t_phys);
        }

        /// <!-- description -->
        ///   @brief Returns false if this RPT is the active RPT.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @return Returns false if this RPT is the active RPT.
        ///
        [[nodiscard]] constexpr auto
        is_inactive(TLS_TYPE const &tls) const noexcept -> bool
        {
            return this != tls.active_rpt;
        }

        /// <!-- description -->
        ///   @brief Maps a 1g page into the root page table
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam E the entry type to use. Valid inputs are L2E_TYPE, L1E_TYPE
        ///     and L0E_TYPE. If L2E_TYPE is provided, a 1G map is requested. If
        ///     L1E_TYPE is provided, a 2M map is requested. If L0E_TYPE is provided,
        ///     a 4K map is requested. Defaults to L0E_TYPE (i.e. 4k).
        ///   @param mut_tls the current TLS block
        ///   @param mut_page_pool the page_pool_t to use
        ///   @param page_virt the virtual address to map the physical
        ///     address to
        ///   @param page_phys the physical address to map
        ///   @param page_flgs defines how memory should be mapped
        ///   @param require_explicit_unmap tells the RPT that the virtual
        ///     address must be explicitly unmapped before the RPT can be
        ///     released. Otherwise the release will fail.
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        template<typename E = L0E_TYPE>
        [[nodiscard]] constexpr auto
        map_page(
            TLS_TYPE &mut_tls,
            PAGE_POOL_TYPE &mut_page_pool,
            bsl::safe_u64 const &page_virt,
            bsl::safe_u64 const &page_phys,
            bsl::safe_u64 const &page_flgs,
            bool const require_explicit_unmap = false) noexcept -> bsl::errc_type
        {
            static_assert(bsl::is_one_of<E, L2E_TYPE, L1E_TYPE, L0E_TYPE>::value);

            bsl::expects(nullptr != m_l3t);
            bsl::expects(page_virt.is_valid_and_checked());
            bsl::expects(page_virt.is_pos());
            bsl::expects(page_phys.is_valid_and_checked());
            bsl::expects(page_phys.is_pos());
            bsl::expects(page_flgs.is_valid_and_checked());
            bsl::expects(page_flgs.is_pos());

            if constexpr (bsl::is_same<E, L2E_TYPE>::value) {
                bsl::expects(is_page_1g_aligned(page_virt));
                bsl::expects(is_page_1g_aligned(page_phys));
            }

            if constexpr (bsl::is_same<E, L1E_TYPE>::value) {
                bsl::expects(is_page_2m_aligned(page_virt));
                bsl::expects(is_page_1g_aligned(page_phys));
            }

            if constexpr (bsl::is_same<E, L0E_TYPE>::value) {
                bsl::expects(is_page_4k_aligned(page_virt));
                bsl::expects(is_page_1g_aligned(page_phys));
            }

            basic_lock_guard_t mut_lock{mut_tls, m_lock};

            auto *const pmut_entry{
                get_entry_from_entries<E>(this->get_entries<E>(mut_tls, mut_page_pool, page_virt))};

            if (bsl::unlikely(nullptr == pmut_entry)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            if (helpers::entry_status(pmut_entry) == basic_entry_status_t::present) {
                if (bsl::unlikely(bsl::safe_u64::magic_0() == pmut_entry->points_to_block)) {
                    bsl::error() << "the virtual address "                  // --
                                 << bsl::hex(page_virt)                     // --
                                 << " is already mapped to a table"         // --
                                 << " and cannot be remapped to a block"    // --
                                 << bsl::endl                               // --
                                 << bsl::here();                            // --

                    return bsl::errc_failure;
                }

                return bsl::errc_already_exists;
            }

            if (require_explicit_unmap) {
                pmut_entry->require_explicit_unmap = bsl::safe_u64::magic_1().get();
            }
            else {
                pmut_entry->require_explicit_unmap = bsl::safe_u64::magic_0().get();
            }

            pmut_entry->auto_release = bsl::safe_u64::magic_0().get();
            pmut_entry->points_to_block = bsl::safe_u64::magic_1().get();
            pmut_entry->alias = bsl::safe_u64::magic_0().get();
            pmut_entry->phys = (page_phys >> BASIC_PAGE_4K_T_SHFT).get();
            helpers::configure_entry_as_ptr_to_block(pmut_entry, page_flgs);

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Allocates a basic_page_4k_t from the provided page pool and maps
        ///     it into the root page table with auto_release set to true.
        ///     Returns a pointer to the newly allocated basic_page_4k_t as a type
        ///     T *, or a nullptr on failure.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam T the type of virtual address to return
        ///   @param mut_tls the current TLS block
        ///   @param mut_page_pool the page_pool_t to use
        ///   @param page_virt the virtual address to map the allocated
        ///     basic_page_4k_t to
        ///   @param page_flgs defines how memory should be mapped
        ///   @return Returns a pointer to the newly allocated basic_page_4k_t as
        ///     a type T *, or a nullptr on failure.
        ///
        template<typename T>
        [[nodiscard]] constexpr auto
        allocate_page(
            TLS_TYPE &mut_tls,
            PAGE_POOL_TYPE &mut_page_pool,
            bsl::safe_u64 const &page_virt,
            bsl::safe_u64 const &page_flgs) noexcept -> T *
        {
            static_assert(bsl::is_pod<T>::value);
            static_assert(sizeof(T) == sizeof(basic_page_4k_t));

            bsl::expects(nullptr != m_l3t);
            bsl::expects(page_virt.is_valid_and_checked());
            bsl::expects(page_virt.is_pos());
            bsl::expects(is_page_4k_aligned(page_virt));
            bsl::expects(page_flgs.is_valid_and_checked());
            bsl::expects(page_flgs.is_pos());

            basic_lock_guard_t mut_lock{mut_tls, m_lock};

            auto *const pmut_ptr{mut_page_pool.template allocate<basic_page_4k_t>(mut_tls)};
            if (bsl::unlikely(nullptr == pmut_ptr)) {
                bsl::print<bsl::V>() << bsl::here();
                return nullptr;
            }

            bsl::finally mut_deallocate_on_error{
                [&mut_tls, &mut_page_pool, &pmut_ptr]() noexcept -> void {
                    mut_page_pool.deallocate(mut_tls, pmut_ptr);
                }};

            auto *const pmut_entry{get_entry_from_entries<L0E_TYPE>(
                this->get_entries<L0E_TYPE>(mut_tls, mut_page_pool, page_virt))};

            if (bsl::unlikely(nullptr == pmut_entry)) {
                bsl::print<bsl::V>() << bsl::here();
                return nullptr;
            }

            if (bsl::unlikely(helpers::entry_status(pmut_entry) == basic_entry_status_t::present)) {
                bsl::error() << "the virtual address "             // --
                             << bsl::hex(page_virt)                // --
                             << " is already mapped to a block"    // --
                             << " and cannot be remapped"          // --
                             << bsl::endl                          // --
                             << bsl::here();                       // --

                return nullptr;
            }

            pmut_entry->auto_release = bsl::safe_u64::magic_1().get();
            pmut_entry->points_to_block = bsl::safe_u64::magic_1().get();
            pmut_entry->alias = bsl::safe_u64::magic_0().get();
            pmut_entry->phys = (mut_page_pool.virt_to_phys(pmut_ptr) >> BASIC_PAGE_4K_T_SHFT).get();
            pmut_entry->require_explicit_unmap = bsl::safe_u64::magic_0().get();
            helpers::configure_entry_as_ptr_to_block(pmut_entry, page_flgs);

            mut_deallocate_on_error.ignore();
            return bsl::construct_at<T>(pmut_ptr);
        }

        /// <!-- description -->
        ///   @brief Allocates a basic_page_4k_t from the provided page pool and maps
        ///     it into the root page table with auto_release set to true.
        ///     The address is mapped to OFFSET + the allocated page's physical
        ///     address using BASIC_MAP_PAGE_RW. This function can be used to
        ///     allocate memory for direct maps.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam OFFSET the offset to map the allocate page to
        ///   @param mut_tls the current TLS block
        ///   @param mut_page_pool the page_pool_t to use
        ///   @return Returns a basic_alloc_page_t containing the virtual address
        ///     and physical address that was allocated and mapped using
        ///     OFFSET.
        ///
        template<bsl::uintmx OFFSET>
        [[nodiscard]] constexpr auto
        allocate_page(TLS_TYPE &mut_tls, PAGE_POOL_TYPE &mut_page_pool) noexcept
            -> basic_alloc_page_t
        {
            bsl::expects(nullptr != m_l3t);
            basic_lock_guard_t mut_lock{mut_tls, m_lock};

            auto *const pmut_ptr{mut_page_pool.template allocate<basic_page_4k_t>(mut_tls)};
            if (bsl::unlikely(nullptr == pmut_ptr)) {
                bsl::print<bsl::V>() << bsl::here();
                return {bsl::safe_umx::failure(), bsl::safe_umx::failure()};
            }

            auto const page_phys{mut_page_pool.virt_to_phys(pmut_ptr)};
            bsl::expects(page_phys.is_valid_and_checked());
            bsl::expects(page_phys.is_pos());

            auto const page_virt{(page_phys + OFFSET).checked()};
            bsl::expects(page_virt.is_valid_and_checked());
            bsl::expects(page_virt.is_pos());

            bsl::finally mut_deallocate_on_error{
                [&mut_tls, &mut_page_pool, &pmut_ptr]() noexcept -> void {
                    mut_page_pool.deallocate(mut_tls, pmut_ptr);
                }};

            auto *const pmut_entry{get_entry_from_entries<L0E_TYPE>(
                this->get_entries<L0E_TYPE>(mut_tls, mut_page_pool, page_virt))};

            if (bsl::unlikely(nullptr == pmut_entry)) {
                bsl::print<bsl::V>() << bsl::here();
                return {bsl::safe_umx::failure(), bsl::safe_umx::failure()};
            }

            if (bsl::unlikely(helpers::entry_status(pmut_entry) == basic_entry_status_t::present)) {
                bsl::error() << "the virtual address "             // --
                             << bsl::hex(page_virt)                // --
                             << " is already mapped to a block"    // --
                             << " and cannot be remapped"          // --
                             << bsl::endl                          // --
                             << bsl::here();                       // --

                return {bsl::safe_umx::failure(), bsl::safe_umx::failure()};
            }

            pmut_entry->auto_release = bsl::safe_u64::magic_1().get();
            pmut_entry->points_to_block = bsl::safe_u64::magic_1().get();
            pmut_entry->alias = bsl::safe_u64::magic_0().get();
            pmut_entry->phys = (page_phys >> BASIC_PAGE_4K_T_SHFT).get();
            pmut_entry->require_explicit_unmap = bsl::safe_u64::magic_0().get();
            helpers::configure_entry_as_ptr_to_block(pmut_entry, BASIC_MAP_PAGE_RW);

            mut_deallocate_on_error.ignore();
            return {page_virt, page_phys};
        }

        /// <!-- description -->
        ///   @brief Unmaps a page from the root page table.
        ///
        /// <!-- notes -->
        ///   @note IMPORTANT: This function is slow if a broadcast TLB is
        ///     requested. If you choose to use a local flush, you better
        ///     be sure other cores never saw the mapped address, otherwise
        ///     you will end up with a really hard bug to find.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam E the entry type to use. Valid inputs are L2E_TYPE, L1E_TYPE
        ///     and L0E_TYPE. If L2E_TYPE is provided, a 1G map is requested. If
        ///     L1E_TYPE is provided, a 2M map is requested. If L0E_TYPE is provided,
        ///     a 4K map is requested. Defaults to L0E_TYPE (i.e. 4k).
        ///   @param mut_tls the current TLS block
        ///   @param mut_page_pool the page_pool_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///   @param page_virt the virtual address to unmap
        ///   @param type the type of TLB flush to perform
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        template<typename E = L0E_TYPE>
        [[nodiscard]] constexpr auto
        unmap_page(
            TLS_TYPE &mut_tls,
            PAGE_POOL_TYPE &mut_page_pool,
            INTRINSIC_TYPE const &intrinsic,
            bsl::safe_u64 const &page_virt,
            basic_tlb_flush_type_t const type) noexcept -> bsl::errc_type
        {
            static_assert(bsl::is_one_of<E, L2E_TYPE, L1E_TYPE, L0E_TYPE>::value);

            bsl::expects(nullptr != m_l3t);
            bsl::expects(page_virt.is_valid_and_checked());
            bsl::expects(page_virt.is_pos());

            if constexpr (bsl::is_same<E, L2E_TYPE>::value) {
                bsl::expects(is_page_1g_aligned(page_virt));
            }

            if constexpr (bsl::is_same<E, L1E_TYPE>::value) {
                bsl::expects(is_page_2m_aligned(page_virt));
            }

            if constexpr (bsl::is_same<E, L0E_TYPE>::value) {
                bsl::expects(is_page_4k_aligned(page_virt));
            }

            basic_lock_guard_t mut_lock{mut_tls, m_lock};

            auto const ents{this->get_entries<E, false>(mut_tls, mut_page_pool, page_virt)};
            if (bsl::unlikely(nullptr == ents.l2e)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            if (bsl::unlikely(helpers::entry_status(ents.l2e) != basic_entry_status_t::present)) {
                bsl::error() << "the virtual address "    // --
                             << bsl::hex(page_virt)       // --
                             << " was never mapped"       // --
                             << bsl::endl                 // --
                             << bsl::here();              // --

                return bsl::errc_failure;
            }

            if constexpr (bsl::is_same<E, L2E_TYPE>::value) {
                if (bsl::safe_u64::magic_0() == ents.l2e->points_to_block) {
                    *ents.l2e = {};
                    release_entry(mut_tls, mut_page_pool, ents.l3e);

                    intrinsic.tlb_flush(type, page_virt);
                    return bsl::errc_success;
                }

                bsl::error() << "the virtual address "                   // --
                             << bsl::hex(page_virt)                      // --
                             << " was not mapped at this granularity"    // --
                             << bsl::endl                                // --
                             << bsl::here();                             // --

                return bsl::errc_failure;
            }

            if (bsl::unlikely(helpers::entry_status(ents.l1e) != basic_entry_status_t::present)) {
                bsl::error() << "the virtual address "    // --
                             << bsl::hex(page_virt)       // --
                             << " was never mapped"       // --
                             << bsl::endl                 // --
                             << bsl::here();              // --

                return bsl::errc_failure;
            }

            if constexpr (bsl::is_same<E, L1E_TYPE>::value) {
                if (bsl::safe_u64::magic_0() == ents.l1e->points_to_block) {
                    *ents.l1e = {};
                    release_entry(mut_tls, mut_page_pool, ents.l2e);
                    release_entry(mut_tls, mut_page_pool, ents.l3e);

                    intrinsic.tlb_flush(type, page_virt);
                    return bsl::errc_success;
                }

                bsl::error() << "the virtual address "                   // --
                             << bsl::hex(page_virt)                      // --
                             << " was not mapped at this granularity"    // --
                             << bsl::endl                                // --
                             << bsl::here();                             // --

                return bsl::errc_failure;
            }

            if (bsl::unlikely(helpers::entry_status(ents.l0e) != basic_entry_status_t::present)) {
                bsl::error() << "the virtual address "    // --
                             << bsl::hex(page_virt)       // --
                             << " was never mapped"       // --
                             << bsl::endl                 // --
                             << bsl::here();              // --

                return bsl::errc_failure;
            }

            if constexpr (bsl::is_same<E, L0E_TYPE>::value) {
                if (bsl::safe_u64::magic_0() == ents.l0e->points_to_block) {
                    *ents.l0e = {};
                    release_entry(mut_tls, mut_page_pool, ents.l1e);
                    release_entry(mut_tls, mut_page_pool, ents.l2e);
                    release_entry(mut_tls, mut_page_pool, ents.l3e);

                    intrinsic.tlb_flush(type, page_virt);
                    return bsl::errc_success;
                }

                bsl::error() << "the virtual address "                   // --
                             << bsl::hex(page_virt)                      // --
                             << " was not mapped at this granularity"    // --
                             << bsl::endl                                // --
                             << bsl::here();                             // --

                return bsl::errc_failure;
            }

            return bsl::errc_failure;
        }

        /// <!-- description -->
        ///   @brief Returns all of the entries that are identified during the
        ///     translation of the provided virtual address.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam E the entry type requested. L2E_TYPE for a 1G request,
        ///     L1E_TYPE for a 2M and L2E_TYPE for a 4K.
        ///   @param mut_tls the current TLS block
        ///   @param page_pool the page_pool_t to use
        ///   @param page_virt the virtual address to decode
        ///   @return Returns all of the entries that are identified during the
        ///     translation of the provided virtual address.
        ///
        template<typename E = L0E_TYPE>
        [[nodiscard]] constexpr auto
        entries(
            TLS_TYPE &mut_tls,
            PAGE_POOL_TYPE const &page_pool,
            bsl::safe_u64 const &page_virt) noexcept -> entries_t
        {
            static_assert(bsl::is_one_of<E, L2E_TYPE, L1E_TYPE, L0E_TYPE>::value);

            bsl::expects(nullptr != m_l3t);
            bsl::expects(page_virt.is_valid_and_checked());
            bsl::expects(page_virt.is_pos());

            if constexpr (bsl::is_same<E, L2E_TYPE>::value) {
                bsl::expects(is_page_1g_aligned(page_virt));
            }

            if constexpr (bsl::is_same<E, L1E_TYPE>::value) {
                bsl::expects(is_page_2m_aligned(page_virt));
            }

            if constexpr (bsl::is_same<E, L0E_TYPE>::value) {
                bsl::expects(is_page_4k_aligned(page_virt));
            }

            basic_lock_guard_t mut_lock{mut_tls, m_lock};
            return this->get_entries<E, false>(mut_tls, page_pool, page_virt);
        }

        /// <!-- description -->
        ///   @brief Given a root page table, the enties are aliased into
        ///     this root page table, allowing software using this root page
        ///     table to access the memory mapped into the provided root page
        ///     table. The additions are aliases only, meaning when this root
        ///     page table loses scope, aliased entries added by this function
        ///     are not returned back to the page_pool_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param l3t the l3t_t of the root page table to add aliases to
        ///
        constexpr void
        add_tables(TLS_TYPE &mut_tls, basic_page_table_t<L3E_TYPE> const *const l3t) noexcept
        {
            bsl::expects(nullptr != m_l3t);
            bsl::expects(nullptr != l3t);

            basic_lock_guard_t mut_lock{mut_tls, m_lock};

            for (bsl::safe_idx mut_i{}; mut_i < l3t->entries.size(); ++mut_i) {
                auto const *const src_l3e{l3t->entries.at_if(mut_i)};
                auto *const pmut_dst_l3e{m_l3t->entries.at_if(mut_i)};

                if (helpers::entry_status(src_l3e) == basic_entry_status_t::not_present) {
                    continue;
                }

                *pmut_dst_l3e = *src_l3e;
                pmut_dst_l3e->alias = bsl::safe_u64::magic_1().get();
            }
        }

        /// <!-- description -->
        ///   @brief Given a root page table, the L3E_TYPE enties are aliased
        ///     into this page table, allowing software using this root page
        ///     table to access the memory mapped into the provided root page
        ///     table. The additions are aliases only, meaning when this root
        ///     page table loses scope, aliased entries added by this function
        ///     are not returned back to the page_pool_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param rpt the root page table to add aliases to
        ///
        constexpr void
        add_tables(TLS_TYPE &mut_tls, basic_root_page_table_t const &rpt) noexcept
        {
            this->add_tables(mut_tls, rpt.m_l3t);
        }

        // template<typename E>
        // static constexpr auto
        // entry_to_virt(bsl::safe_idx const &i, bsl::safe_u64 const &addr) noexcept -> bsl::safe_u64
        // {
        //     static_assert(bsl::is_one_of<bsl::remove_const_t<E>, L3E_TYPE, L2E_TYPE, L1E_TYPE, L0E_TYPE>::value);

        //     if constexpr (bsl::is_same<bsl::remove_const_t<E>, L3E_TYPE>::value) {
        //         constexpr auto shift{39_u64};
        //         return (addr | (bsl::to_u64(i) << shift)).checked();
        //     }

        //     if constexpr (bsl::is_same<bsl::remove_const_t<E>, L2E_TYPE>::value) {
        //         constexpr auto shift{30_u64};
        //         return (addr | (bsl::to_u64(i) << shift)).checked();
        //     }

        //     if constexpr (bsl::is_same<bsl::remove_const_t<E>, L1E_TYPE>::value) {
        //         constexpr auto shift{21_u64};
        //         return (addr | (bsl::to_u64(i) << shift)).checked();
        //     }

        //     if constexpr (bsl::is_same<bsl::remove_const_t<E>, L0E_TYPE>::value) {
        //         constexpr auto shift{12_u64};
        //         return (addr | (bsl::to_u64(i) << shift)).checked();
        //     }
        // }

        // template<typename E>
        // static constexpr void
        // dump_entry(PAGE_POOL_TYPE const &page_pool, E const *const entry, bsl::safe_u64 const &addr, bsl::safe_idx const &i) noexcept
        // {
        //     auto const virt{entry_to_virt<E>(i, addr)};
        //     auto const data{*reinterpret_cast<bsl::uint64 const *>(entry)};

        //     bsl::safe_umx mut_idnt{};
        //     bsl::string_view mut_name{};

        //     if constexpr (bsl::is_same<bsl::remove_const_t<E>, L3E_TYPE>::value) {
        //         mut_idnt = 0_umx;
        //         mut_name = "L3E_TYPE";
        //     }

        //     if constexpr (bsl::is_same<bsl::remove_const_t<E>, L2E_TYPE>::value) {
        //         mut_idnt = 2_umx;
        //         mut_name = "L2E_TYPE";
        //     }

        //     if constexpr (bsl::is_same<bsl::remove_const_t<E>, L1E_TYPE>::value) {
        //         mut_idnt = 4_umx;
        //         mut_name = "L1E_TYPE";
        //     }

        //     if constexpr (bsl::is_same<bsl::remove_const_t<E>, L0E_TYPE>::value) {
        //         mut_idnt = 6_umx;
        //         mut_name = "L0E_TYPE";
        //     }

        //     for (bsl::safe_idx mut_i{}; mut_i < mut_idnt; ++mut_i) {
        //         bsl::print() << ' ';
        //     }

        //     bsl::print() << mut_name << " [" << bsl::hex(virt) << "]: " << bsl::hex(data) << bsl::endl;

        //     if (bsl::safe_u64::magic_0() != entry->points_to_block) {
        //         return;
        //     }

        //     if (helpers::entry_status(entry) == basic_entry_status_t::reserved) {
        //         return;
        //     }

        //     if constexpr (bsl::is_same<bsl::remove_const_t<E>, L3E_TYPE>::value) {
        //         dump_table(page_pool, entry_to_table(page_pool, entry), virt);
        //     }

        //     if constexpr (bsl::is_same<bsl::remove_const_t<E>, L2E_TYPE>::value) {
        //         dump_table(page_pool, entry_to_table(page_pool, entry), virt);
        //     }

        //     if constexpr (bsl::is_same<bsl::remove_const_t<E>, L1E_TYPE>::value) {
        //         dump_table(page_pool, entry_to_table(page_pool, entry), virt);
        //     }
        // }

        // template<typename T>
        // static constexpr void
        // dump_table(PAGE_POOL_TYPE const &page_pool, T const *const table, bsl::safe_u64 const &addr) noexcept
        // {
        //     for (bsl::safe_idx mut_i{}; mut_i < table->entries.size(); ++mut_i) {
        //         auto const *const entry{table->entries.at_if(mut_i)};
        //         if (helpers::entry_status(entry) == basic_entry_status_t::not_present) {
        //             continue;
        //         }

        //         dump_entry(page_pool, entry, addr, mut_i);
        //     }
        // }

        // constexpr void
        // dump(PAGE_POOL_TYPE const &page_pool) noexcept
        // {
        //     bsl::safe_u64 addr{};
        //     dump_table(page_pool, m_l3t, addr);
        // }
    };
}

#endif
