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

#if __has_include("root_page_table_helpers.hpp")
#include <root_page_table_helpers.hpp>    // IWYU pragma: export
#endif

#if __has_include("second_level_page_table_helpers.hpp")
#include <second_level_page_table_helpers.hpp>    // IWYU pragma: export
#endif

#if __has_include("basic_root_page_table_helpers.hpp")
#include <basic_root_page_table_helpers.hpp>    // IWYU pragma: export
#endif

// IWYU pragma: no_include "root_page_table_helpers.hpp"
// IWYU pragma: no_include "second_level_page_table_helpers.hpp"
// IWYU pragma: no_include "basic_root_page_table_helpers.hpp"

#include <basic_alloc_page_t.hpp>
#include <basic_entries_t.hpp>
#include <basic_page_1g_t.hpp>
#include <basic_page_2m_t.hpp>
#include <basic_page_4k_t.hpp>
#include <basic_page_pool_t.hpp>
#include <basic_page_table_t.hpp>

#include <bsl/array.hpp>
#include <bsl/convert.hpp>
#include <bsl/discard.hpp>
#include <bsl/dontcare_t.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/expects.hpp>
#include <bsl/is_one_of.hpp>
#include <bsl/is_pod.hpp>
#include <bsl/is_same.hpp>
#include <bsl/safe_idx.hpp>
#include <bsl/safe_integral.hpp>

namespace lib
{
    /// @brief defines the max number of allocations that's supported
    constexpr auto RPT_MAX_ALLOCATIONS{1000_umx};
    /// @brief defines a unit testing specific error code
    constexpr bsl::errc_type UNIT_TEST_RPT_FAIL_INITIALIZE{-1001};

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
    ///     - a 1bit explicit_unmap field, which tells the RPT that
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
    ///   @tparam SYS_TYPE the type of bf_syscall_t to use (optional)
    ///   @tparam PAGE_POOL_TYPE the type page_pool_t to use
    ///   @tparam INTRINSIC_TYPE the type intrinsic_t to use
    ///   @tparam L3E_TYPE the level-3 page table entry to use
    ///   @tparam L2E_TYPE the level-2 page table entry to use
    ///   @tparam L1E_TYPE the level-1 page table entry to use
    ///   @tparam L0E_TYPE the level-0 page table entry to use
    ///
    template<
        typename TLS_TYPE,
        typename SYS_TYPE,
        typename PAGE_POOL_TYPE,
        typename INTRINSIC_TYPE,
        typename L3E_TYPE,
        typename L2E_TYPE,
        typename L1E_TYPE,
        typename L0E_TYPE>
    class basic_root_page_table_t final
    {
        /// @brief define the type entries_t to use
        using entries_t = basic_entries_t<L3E_TYPE, L2E_TYPE, L1E_TYPE, L0E_TYPE>;

        /// @brief stores whether or not the RPT has been initialized
        bool m_initialized{};
        /// @brief stores all of the allocations made by this RPT
        bsl::array<helpers::page_pool_storage_t, RPT_MAX_ALLOCATIONS.get()> m_allocations{};
        /// @brief stores the index into m_allocations
        bsl::safe_idx m_allocations_idx{};

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

    public:
        /// <!-- description -->
        ///   @brief Initializes this basic_root_page_table_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param page_pool the page_pool_t to use
        ///   @param sys the bf_syscall_t to use (optional)
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        initialize(
            TLS_TYPE const &tls,
            PAGE_POOL_TYPE const &page_pool,
            SYS_TYPE const &sys = bsl::dontcare) noexcept -> bsl::errc_type
        {
            bsl::expects(!m_initialized);

            bsl::discard(tls);
            bsl::discard(page_pool);
            bsl::discard(sys);

            if (UNIT_TEST_RPT_FAIL_INITIALIZE == tls.test_ret) {
                return UNIT_TEST_RPT_FAIL_INITIALIZE;
            }

            m_initialized = true;
            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Releases all of the resources used by the RPT.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param mut_page_pool the page_pool_t to use
        ///
        constexpr void
        release(TLS_TYPE const &tls, PAGE_POOL_TYPE &mut_page_pool) noexcept
        {
            bsl::discard(tls);

            for (bsl::safe_idx mut_i; mut_i < m_allocations_idx; ++mut_i) {
                auto *const pmut_store{m_allocations.at_if(mut_i)};

                helpers::clr_page_pool_storage(mut_page_pool, *pmut_store);
                *pmut_store = {};
            }

            m_allocations_idx = {};
            m_initialized = {};
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
            return m_initialized;
        }

        /// <!-- description -->
        ///   @brief Sets the current root page table to this root page table.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param intrinsic the intrinsic_t to use
        ///
        constexpr void
        activate(TLS_TYPE &mut_tls, INTRINSIC_TYPE const &intrinsic) noexcept
        {
            bsl::discard(intrinsic);
            bsl::expects(m_initialized);

            mut_tls.active_rpt = this;
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
        ///   @brief Returns the system physical address of the RPT.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the system physical address of the RPT.
        ///
        [[nodiscard]] constexpr auto
        spa() const noexcept -> bsl::safe_umx
        {
            bsl::expects(m_initialized);
            return HYPERVISOR_PAGE_SIZE;
        }

        /// <!-- description -->
        ///   @brief Maps a 1g page into the root page table
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam E the entry type to use. Valid inputs are L2E_TYPE, L1E_TYPE
        ///     and L0E_TYPE. If L2E_TYPE is provided, a 1G map is requested. If
        ///     L1E_TYPE is provided, a 2M map is requested. If L0E_TYPE is provided,
        ///     a 4K map is requested. Defaults to L0E_TYPE (i.e. 4k).
        ///   @param tls the current TLS block
        ///   @param page_pool the page_pool_t to use
        ///   @param page_virt the virtual address to map the physical
        ///     address to
        ///   @param page_phys the physical address to map
        ///   @param page_flgs defines how memory should be mapped
        ///   @param explicit_unmap tells the RPT that the virtual
        ///   @param sys the bf_syscall_t to use (optional)
        ///     address must be explicitly unmapped before the RPT can be
        ///     released. Otherwise the release will fail.
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        template<typename E = L0E_TYPE>
        [[nodiscard]] constexpr auto
        map(TLS_TYPE const &tls,
            PAGE_POOL_TYPE const &page_pool,
            bsl::safe_u64 const &page_virt,
            bsl::safe_u64 const &page_phys,
            bsl::safe_u64 const &page_flgs,
            bool const explicit_unmap = false,
            SYS_TYPE const &sys = bsl::dontcare) noexcept -> bsl::errc_type
        {
            static_assert(bsl::is_one_of<E, L2E_TYPE, L1E_TYPE, L0E_TYPE>::value);

            bsl::discard(tls);
            bsl::discard(page_pool);
            bsl::discard(explicit_unmap);
            bsl::discard(sys);

            bsl::expects(m_initialized);
            bsl::expects(page_virt.is_valid_and_checked());
            bsl::expects(page_phys.is_valid_and_checked());
            bsl::expects(page_flgs.is_valid_and_checked());

            if constexpr (bsl::is_same<E, L2E_TYPE>::value) {
                bsl::expects(is_page_1g_aligned(page_virt));
                bsl::expects(is_page_1g_aligned(page_phys));
            }

            if constexpr (bsl::is_same<E, L1E_TYPE>::value) {
                bsl::expects(is_page_2m_aligned(page_virt));
                bsl::expects(is_page_2m_aligned(page_phys));
            }

            if constexpr (bsl::is_same<E, L0E_TYPE>::value) {
                bsl::expects(is_page_4k_aligned(page_virt));
                bsl::expects(is_page_4k_aligned(page_phys));
            }

            if (tls.test_virt == page_virt) {
                return bsl::errc_failure;
            }

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
        ///   @param tls the current TLS block
        ///   @param mut_page_pool the page_pool_t to use
        ///   @param page_virt the virtual address to map the allocated
        ///     basic_page_4k_t to
        ///   @param page_flgs defines how memory should be mapped
        ///   @param sys the bf_syscall_t to use (optional)
        ///   @return Returns a pointer to the newly allocated basic_page_4k_t as
        ///     a type T *, or a nullptr on failure.
        ///
        template<typename T>
        [[nodiscard]] constexpr auto
        allocate_page(
            TLS_TYPE const &tls,
            PAGE_POOL_TYPE &mut_page_pool,
            bsl::safe_u64 const &page_virt,
            bsl::safe_u64 const &page_flgs,
            SYS_TYPE const &sys = bsl::dontcare) noexcept -> T *
        {
            bsl::expects(m_allocations_idx < RPT_MAX_ALLOCATIONS);
            auto *const store{m_allocations.at_if(m_allocations_idx)};

            static_assert(bsl::is_pod<T>::value);
            static_assert(sizeof(T) == sizeof(basic_page_4k_t));

            bsl::discard(tls);
            bsl::discard(sys);

            bsl::expects(m_initialized);
            bsl::expects(page_virt.is_valid_and_checked());
            bsl::expects(is_page_4k_aligned(page_virt));
            bsl::expects(page_flgs.is_valid_and_checked());

            if (tls.test_virt == page_virt) {
                return nullptr;
            }

            auto *const virt{mut_page_pool.template allocate<T>(tls, sys)};
            bsl::expects(nullptr != virt);

            helpers::set_page_pool_storage(*store, virt, page_virt);
            ++m_allocations_idx;

            return virt;
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
        ///   @param tls the current TLS block
        ///   @param page_pool the page_pool_t to use
        ///   @param sys the bf_syscall_t to use (optional)
        ///   @return Returns a basic_alloc_page_t containing the virtual address
        ///     and physical address that was allocated and mapped using
        ///     OFFSET.
        ///
        template<bsl::uintmx OFFSET = HYPERVISOR_EXT_PAGE_POOL_ADDR.get()>
        [[nodiscard]] constexpr auto
        allocate_page(
            TLS_TYPE const &tls,
            PAGE_POOL_TYPE const &page_pool,
            SYS_TYPE const &sys = bsl::dontcare) noexcept -> basic_alloc_page_t
        {
            bsl::expects(m_initialized);

            bsl::discard(tls);
            bsl::discard(page_pool);
            bsl::discard(sys);

            if (tls.test_virt.is_invalid()) {
                return {bsl::safe_umx::failure(), bsl::safe_umx::failure()};
            }

            return {HYPERVISOR_PAGE_SIZE, HYPERVISOR_PAGE_SIZE};
        }

        /// <!-- description -->
        ///   @brief Unmaps a page from the root page table and returns a
        ///     list of all of the entries associated with the map. It is
        ///     the caller's responsibility to flush the TLB as needed. This
        ///     might include the need to flush the unmapped page on all PPs
        ///     that have touched the page.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam E the entry type to use. Valid inputs are L2E_TYPE, L1E_TYPE
        ///     and L0E_TYPE. If L2E_TYPE is provided, a 1G map is requested. If
        ///     L1E_TYPE is provided, a 2M map is requested. If L0E_TYPE is provided,
        ///     a 4K map is requested. Defaults to L0E_TYPE (i.e. 4k).
        ///   @param tls the current TLS block
        ///   @param page_pool the page_pool_t to use
        ///   @param page_virt the virtual address to unmap
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        template<typename E = L0E_TYPE>
        [[nodiscard]] constexpr auto
        unmap(
            TLS_TYPE const &tls,
            PAGE_POOL_TYPE const &page_pool,
            bsl::safe_u64 const &page_virt) noexcept -> bsl::errc_type
        {
            static_assert(bsl::is_one_of<E, L2E_TYPE, L1E_TYPE, L0E_TYPE>::value);

            bsl::discard(tls);
            bsl::discard(page_pool);

            bsl::expects(m_initialized);
            bsl::expects(page_virt.is_valid_and_checked());

            if constexpr (bsl::is_same<E, L2E_TYPE>::value) {
                bsl::expects(is_page_1g_aligned(page_virt));
            }

            if constexpr (bsl::is_same<E, L1E_TYPE>::value) {
                bsl::expects(is_page_2m_aligned(page_virt));
            }

            if constexpr (bsl::is_same<E, L0E_TYPE>::value) {
                bsl::expects(is_page_4k_aligned(page_virt));
            }

            if (tls.test_virt == page_virt) {
                return bsl::errc_failure;
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Returns all of the entries that are identified during the
        ///     translation of the provided virtual address.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam E the entry type requested. L2E_TYPE for a 1G request,
        ///     L1E_TYPE for a 2M and L2E_TYPE for a 4K.
        ///   @param tls the current TLS block
        ///   @param page_pool the page_pool_t to use
        ///   @param page_virt the virtual address to decode
        ///   @return Returns all of the entries that are identified during the
        ///     translation of the provided virtual address.
        ///
        template<typename E = L0E_TYPE>
        [[nodiscard]] constexpr auto
        entries(
            TLS_TYPE const &tls,
            PAGE_POOL_TYPE const &page_pool,
            bsl::safe_u64 const &page_virt) noexcept -> entries_t
        {
            static_assert(bsl::is_one_of<E, L2E_TYPE, L1E_TYPE, L0E_TYPE>::value);

            bsl::discard(tls);
            bsl::discard(page_pool);

            bsl::expects(m_initialized);
            bsl::expects(page_virt.is_valid_and_checked());

            if constexpr (bsl::is_same<E, L2E_TYPE>::value) {
                bsl::expects(is_page_1g_aligned(page_virt));
            }

            if constexpr (bsl::is_same<E, L1E_TYPE>::value) {
                bsl::expects(is_page_2m_aligned(page_virt));
            }

            if constexpr (bsl::is_same<E, L0E_TYPE>::value) {
                bsl::expects(is_page_4k_aligned(page_virt));
            }

            return tls.test_ents;
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
        ///   @param tls the current TLS block
        ///   @param l3t the l3t_t of the root page table to add aliases to
        ///
        constexpr void
        add_tables(TLS_TYPE const &tls, basic_page_table_t<L3E_TYPE> const *const l3t) noexcept
        {
            bsl::discard(tls);
            bsl::discard(l3t);
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
        ///   @param tls the current TLS block
        ///   @param rpt the root page table to add aliases to
        ///
        constexpr void
        add_tables(TLS_TYPE const &tls, basic_root_page_table_t const &rpt) noexcept
        {
            bsl::discard(tls);
            bsl::discard(rpt);
        }
    };
}

#endif
