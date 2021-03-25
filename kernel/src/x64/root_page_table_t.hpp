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

#ifndef ROOT_PAGE_TABLE_T_HPP
#define ROOT_PAGE_TABLE_T_HPP

#include "../lock_guard_t.hpp"
#include "../spinlock_t.hpp"

#include <allocate_tags.hpp>
#include <huge_pool_t.hpp>
#include <intrinsic_t.hpp>
#include <map_page_flags.hpp>
#include <page_pool_t.hpp>
#include <page_t.hpp>
#include <pdpt_t.hpp>
#include <pdpte_t.hpp>
#include <pdt_t.hpp>
#include <pdte_t.hpp>
#include <pml4t_t.hpp>
#include <pml4te_t.hpp>
#include <pt_t.hpp>
#include <pte_t.hpp>
#include <tls_t.hpp>

#include <bsl/convert.hpp>
#include <bsl/debug.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/finally.hpp>
#include <bsl/fmt.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/touch.hpp>
#include <bsl/unlikely.hpp>
#include <bsl/unlikely_assert.hpp>

namespace mk
{
    /// @class mk::root_page_table_t
    ///
    /// <!-- description -->
    ///   @brief Implements the root pages tables used by the microkernel
    ///     for mapping extension memory.
    ///
    class root_page_table_t final
    {
        /// @brief stores a pointer to the pml4t
        pml4t_t *m_pml4t{};
        /// @brief stores the physical address of the pml4t
        bsl::safe_uintmax m_pml4t_phys{bsl::safe_uintmax::failure()};
        /// @brief safe guards operations on the RPT.
        mutable spinlock_t m_lock{};

        /// <!-- description -->
        ///   @brief Returns the index of the last entry present in a page
        ///     table.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam TABLE_CONCEPT the type of page table to search
        ///   @param table the page table to search
        ///   @return Returns the index of the last entry present in a page
        ///     table.
        ///
        template<typename TABLE_CONCEPT>
        [[nodiscard]] static constexpr auto
        get_last_index(TABLE_CONCEPT const *const table) noexcept -> bsl::safe_uintmax
        {
            constexpr auto disabled{0_umax};

            bsl::safe_uintmax last_index{};
            for (auto const elem : table->entries) {
                if (disabled == elem.data->p) {
                    continue;
                }

                last_index = elem.index;
            }

            return last_index;
        }

        /// <!-- description -->
        ///   @brief Given index and the index of the last
        ///     present entry in the page table being dumped, this function
        ///     will output a decoration and the index.
        ///
        /// <!-- inputs/outputs -->
        ///   @param index the current index of the entry being dumped
        ///   @param last_index the index of the last present entry in the page
        ///     table being dumped.
        ///
        static constexpr void
        output_decoration_and_index(
            bsl::safe_uintmax const &index, bsl::safe_uintmax const &last_index) noexcept
        {
            bsl::print() << bsl::rst;

            if (index != last_index) {
                bsl::print() << "├── ";
            }
            else {
                bsl::print() << "└── ";
            }

            bsl::print() << "[" << bsl::ylw << bsl::fmt{"#05x", index} << bsl::rst << "] ";
        }

        /// <!-- description -->
        ///   @brief Given whether or not the page table
        ///     entry is the last entry in the table, this function will
        ///     either output whtspace, or a | and shitespace.
        ///
        /// <!-- inputs/outputs -->
        ///   @param is_last_index true if the entry being outputted is the
        ///     last index in the table.
        ///
        static constexpr void
        output_spacing(bool const is_last_index) noexcept
        {
            bsl::print() << bsl::rst;

            if (!is_last_index) {
                bsl::print() << "│   ";
            }
            else {
                bsl::print() << "    ";
            }
        }

        /// <!-- description -->
        ///   @brief Given a page table entry, this
        ///     function outputs the flags associated with the entry
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam ENTRY_CONCEPT the type of page table entry to output
        ///   @param entry the page table entry to output
        ///
        template<typename ENTRY_CONCEPT>
        static constexpr void
        output_entry_and_flags(ENTRY_CONCEPT const *const entry) noexcept
        {
            constexpr auto disabled{0_umax};
            bool add_comma{};

            bsl::print() << bsl::hex(
                *static_cast<bsl::uint64 const *>(static_cast<void const *>(entry)));
            bsl::print() << bsl::rst << " (";

            if (disabled != entry->rw) {
                bsl::print() << bsl::grn << 'W';
                add_comma = true;
            }
            else {
                bsl::touch();
            }

            if (disabled != entry->us) {
                if (add_comma) {
                    bsl::print() << bsl::rst << ", ";
                }
                else {
                    bsl::touch();
                }

                bsl::print() << bsl::grn << 'U';
                add_comma = true;
            }
            else {
                bsl::touch();
            }

            if (disabled != entry->nx) {
                if (add_comma) {
                    bsl::print() << bsl::rst << ", ";
                }
                else {
                    bsl::touch();
                }

                bsl::print() << bsl::grn << "NX";
                add_comma = true;
            }
            else {
                bsl::touch();
            }

            if constexpr (bsl::is_same<ENTRY_CONCEPT, pml4te_t>::value) {
                if (disabled != entry->alias) {
                    if (add_comma) {
                        bsl::print() << bsl::rst << ", ";
                    }
                    else {
                        bsl::touch();
                    }

                    bsl::print() << bsl::grn << "alias";
                    add_comma = true;
                }
                else {
                    bsl::touch();
                }
            }

            if constexpr (bsl::is_same<ENTRY_CONCEPT, pte_t>::value) {
                if (add_comma) {
                    bsl::print() << bsl::rst << ", ";
                }
                else {
                    bsl::touch();
                }

                switch (entry->auto_release) {
                    case MAP_PAGE_AUTO_RELEASE_ALLOC_PAGE.get(): {
                        bsl::print() << bsl::grn << "auto_release_alloc_page";
                        break;
                    }

                    case MAP_PAGE_AUTO_RELEASE_ALLOC_HUGE.get(): {
                        bsl::print() << bsl::grn << "auto_release_alloc_huge";
                        break;
                    }

                    case MAP_PAGE_AUTO_RELEASE_ALLOC_HEAP.get(): {
                        bsl::print() << bsl::grn << "auto_release_alloc_heap";
                        break;
                    }

                    case MAP_PAGE_AUTO_RELEASE_STACK.get(): {
                        bsl::print() << bsl::grn << "auto_release_stack";
                        break;
                    }

                    case MAP_PAGE_AUTO_RELEASE_TLS.get(): {
                        bsl::print() << bsl::grn << "auto_release_tls";
                        break;
                    }

                    case MAP_PAGE_AUTO_RELEASE_ELF.get(): {
                        bsl::print() << bsl::grn << "auto_release_elf";
                        break;
                    }

                    default: {
                        bsl::print() << bsl::grn << "manual";
                        break;
                    }
                }

                add_comma = true;
            }

            bsl::print() << bsl::rst << ')';
            bsl::print() << bsl::rst << bsl::endl;
        }

        /// <!-- description -->
        ///   @brief Returns the page-map level-4 (PML4T) offset given a
        ///     virtual address.
        ///
        /// <!-- inputs/outputs -->
        ///   @param virt the virtual address to get the PML4T offset from.
        ///   @return the PML4T offset from the virtual address
        ///
        [[nodiscard]] static constexpr auto
        pml4to(bsl::safe_uintmax const &virt) noexcept -> bsl::safe_uintmax
        {
            constexpr auto mask{0x1FF_umax};
            constexpr auto shft{39_umax};
            return (virt >> shft) & mask;
        }

        /// <!-- description -->
        ///   @brief Dumps the provided pml4t_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param page_pool the page_pool_t to use
        ///   @param pml4t the pml4t_t to dump
        ///
        constexpr void
        dump_pml4t(page_pool_t &page_pool, pml4t_t const *const pml4t) const noexcept
        {
            constexpr auto disabled{0_umax};
            bsl::safe_uintmax const last_index{get_last_index(pml4t)};

            bsl::print() << bsl::blu << bsl::hex(m_pml4t_phys);
            bsl::print() << bsl::rst << bsl::endl;

            for (auto const elem : pml4t->entries) {
                if (disabled == elem.data->p) {
                    continue;
                }

                output_decoration_and_index(elem.index, last_index);

                if (disabled != elem.data->us) {
                    bsl::print() << bsl::blu;
                    output_entry_and_flags(elem.data);
                }
                else {
                    bsl::print() << bsl::blk;
                    output_entry_and_flags(elem.data);
                }

                if (disabled != elem.data->us) {
                    dump_pdpt(page_pool, get_pdpt(page_pool, elem.data), elem.index == last_index);
                }
                else {
                    bsl::touch();
                }
            }
        }

        /// <!-- description -->
        ///   @brief Adds a pdpt_t to the provided pml4te_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param page_pool the page_pool_t to use
        ///   @param pml4te the pml4te_t to add a pdpt_t too
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] static constexpr auto
        add_pdpt(tls_t &tls, page_pool_t &page_pool, pml4te_t *const pml4te) noexcept
            -> bsl::errc_type
        {
            auto const *const table{page_pool.allocate<pdpt_t>(tls, ALLOCATE_TAG_PDPTS)};
            if (bsl::unlikely(nullptr == table)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            auto const table_phys{page_pool.virt_to_phys(table)};
            if (bsl::unlikely_assert(!table_phys)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            constexpr auto enable{1_umax};
            pml4te->phys = (table_phys >> HYPERVISOR_PAGE_SHIFT).get();
            pml4te->p = enable.get();
            pml4te->rw = enable.get();
            pml4te->us = enable.get();

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Adds a pdpt_t to the provided pml4te_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param page_pool the page_pool_t to use
        ///   @param pml4te the pml4te_t to add a pdpt_t too
        ///
        static constexpr void
        remove_pdpt(tls_t &tls, page_pool_t &page_pool, pml4te_t *const pml4te) noexcept
        {
            constexpr auto disabled{0_umax};
            for (auto const elem : get_pdpt(page_pool, pml4te)->entries) {
                if (disabled != elem.data->p) {
                    remove_pdt(tls, page_pool, elem.data);
                }
                else {
                    bsl::touch();
                }
            }

            page_pool.deallocate(tls, get_pdpt(page_pool, pml4te), ALLOCATE_TAG_PDPTS);
        }

        /// <!-- description -->
        ///   @brief Returns the pdpt_t associated with the provided
        ///     pml4te_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param page_pool the page_pool_t to use
        ///   @param pml4te the pml4te_t to get the pdpt_t from
        ///   @return A pointer to the requested pdpt_t
        ///
        [[nodiscard]] static constexpr auto
        get_pdpt(page_pool_t &page_pool, pml4te_t *const pml4te) noexcept -> pdpt_t *
        {
            bsl::safe_uintmax entry_phys{pml4te->phys};
            entry_phys <<= HYPERVISOR_PAGE_SHIFT;

            return page_pool.template phys_to_virt<pdpt_t>(entry_phys);
        }

        /// <!-- description -->
        ///   @brief Returns the pdpt_t associated with the provided
        ///     pml4te_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param page_pool the page_pool_t to use
        ///   @param pml4te the pml4te_t to get the pdpt_t from
        ///   @return A pointer to the requested pdpt_t
        ///
        [[nodiscard]] static constexpr auto
        get_pdpt(page_pool_t &page_pool, pml4te_t const *const pml4te) noexcept -> pdpt_t const *
        {
            bsl::safe_uintmax entry_phys{pml4te->phys};
            entry_phys <<= HYPERVISOR_PAGE_SHIFT;

            return page_pool.template phys_to_virt<pdpt_t const>(entry_phys);
        }

        /// <!-- description -->
        ///   @brief Returns the page-directory-pointer table (PDPT) offset
        ///     given a virtual address.
        ///
        /// <!-- inputs/outputs -->
        ///   @param virt the virtual address to get the PDPT offset from.
        ///   @return the PDPT offset from the virtual address
        ///
        [[nodiscard]] static constexpr auto
        pdpto(bsl::safe_uintmax const &virt) noexcept -> bsl::safe_uintmax
        {
            constexpr auto mask{0x1FF_umax};
            constexpr auto shft{30_umax};
            return (virt >> shft) & mask;
        }

        /// <!-- description -->
        ///   @brief Dumps the provided pdpt_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param page_pool the page_pool_t to use
        ///   @param pdpt the pdpt_t to dump
        ///   @param is_pml4te_last_index true if the parent pml4te was the
        ///     last pml4te in the table
        ///
        static constexpr void
        dump_pdpt(
            page_pool_t &page_pool, pdpt_t const *const pdpt, bool is_pml4te_last_index) noexcept
        {
            constexpr auto disabled{0_umax};
            auto const last_index{get_last_index(pdpt)};

            for (auto const elem : pdpt->entries) {
                if (disabled == elem.data->p) {
                    continue;
                }

                output_spacing(is_pml4te_last_index);
                output_decoration_and_index(elem.index, last_index);

                bsl::print() << bsl::blu;
                output_entry_and_flags(elem.data);

                dump_pdt(
                    page_pool,
                    get_pdt(page_pool, elem.data),
                    is_pml4te_last_index,
                    elem.index == last_index);
            }
        }

        /// <!-- description -->
        ///   @brief Adds a pdt_t to the provided pdpte_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param page_pool the page_pool_t to use
        ///   @param pdpte the pdpte_t to add a pdt_t too
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] static constexpr auto
        add_pdt(tls_t &tls, page_pool_t &page_pool, pdpte_t *const pdpte) noexcept -> bsl::errc_type
        {
            auto const *const table{page_pool.allocate<pdt_t>(tls, ALLOCATE_TAG_PDTS)};
            if (bsl::unlikely(nullptr == table)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            auto const table_phys{page_pool.virt_to_phys(table)};
            if (bsl::unlikely_assert(!table_phys)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            constexpr auto enable{1_umax};
            pdpte->phys = (table_phys >> HYPERVISOR_PAGE_SHIFT).get();
            pdpte->p = enable.get();
            pdpte->rw = enable.get();
            pdpte->us = enable.get();

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Adds a pdt_t to the provided pdpte_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param page_pool the page_pool_t to use
        ///   @param pdpte the pdpte_t to add a pdt_t too
        ///
        static constexpr void
        remove_pdt(tls_t &tls, page_pool_t &page_pool, pdpte_t *const pdpte) noexcept
        {
            constexpr auto disabled{0_umax};
            for (auto const elem : get_pdt(page_pool, pdpte)->entries) {
                if (disabled != elem.data->p) {
                    remove_pt(tls, page_pool, elem.data);
                }
                else {
                    bsl::touch();
                }
            }

            page_pool.deallocate(tls, get_pdt(page_pool, pdpte), ALLOCATE_TAG_PDTS);
        }

        /// <!-- description -->
        ///   @brief Returns the pdt_t associated with the provided
        ///     pdpte_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param pdpte the pdpte_t to get the pdt_t from
        ///   @param page_pool the page_pool_t to use
        ///   @return A pointer to the requested pdt_t
        ///
        [[nodiscard]] static constexpr auto
        get_pdt(page_pool_t &page_pool, pdpte_t *const pdpte) noexcept -> pdt_t *
        {
            bsl::safe_uintmax entry_phys{pdpte->phys};
            entry_phys <<= HYPERVISOR_PAGE_SHIFT;

            return page_pool.template phys_to_virt<pdt_t>(entry_phys);
        }

        /// <!-- description -->
        ///   @brief Returns the pdt_t associated with the provided
        ///     pdpte_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param pdpte the pdpte_t to get the pdt_t from
        ///   @param page_pool the page_pool_t to use
        ///   @return A pointer to the requested pdt_t
        ///
        [[nodiscard]] static constexpr auto
        get_pdt(page_pool_t &page_pool, pdpte_t const *const pdpte) noexcept -> pdt_t const *
        {
            bsl::safe_uintmax entry_phys{pdpte->phys};
            entry_phys <<= HYPERVISOR_PAGE_SHIFT;

            return page_pool.template phys_to_virt<pdt_t const>(entry_phys);
        }

        /// <!-- description -->
        ///   @brief Returns the page-directory table (PDT) offset given a
        ///     virtual address.
        ///
        /// <!-- inputs/outputs -->
        ///   @param virt the virtual address to get the PDT offset from.
        ///   @return the PDT offset from the virtual address
        ///
        [[nodiscard]] static constexpr auto
        pdto(bsl::safe_uintmax const &virt) noexcept -> bsl::safe_uintmax
        {
            constexpr auto mask{0x1FF_umax};
            constexpr auto shft{21_umax};
            return (virt >> shft) & mask;
        }

        /// <!-- description -->
        ///   @brief Dumps the provided pdt_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param page_pool the page_pool_t to use
        ///   @param pdt the pdt_t to dump
        ///   @param is_pml4te_last_index true if the parent pml4te was the
        ///     last pml4te in the table
        ///   @param is_pdpte_last_index true if the parent pdpte was the
        ///     last pdpte in the table
        ///
        static constexpr void
        dump_pdt(
            page_pool_t &page_pool,
            pdt_t const *const pdt,
            bool is_pml4te_last_index,
            bool is_pdpte_last_index) noexcept
        {
            bsl::safe_uintmax const last_index{get_last_index(pdt)};

            constexpr auto disabled{0_umax};
            for (auto const elem : pdt->entries) {
                if (disabled == elem.data->p) {
                    continue;
                }

                output_spacing(is_pml4te_last_index);
                output_spacing(is_pdpte_last_index);
                output_decoration_and_index(elem.index, last_index);

                bsl::print() << bsl::blu;
                output_entry_and_flags(elem.data);

                dump_pt(
                    get_pt(page_pool, elem.data),
                    is_pml4te_last_index,
                    is_pdpte_last_index,
                    elem.index == last_index);
            }
        }

        /// <!-- description -->
        ///   @brief Adds a pt_t to the provided pdte_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param page_pool the page_pool_t to use
        ///   @param pdte the pdte_t to add a pt_t too
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] static constexpr auto
        add_pt(tls_t &tls, page_pool_t &page_pool, pdte_t *const pdte) noexcept -> bsl::errc_type
        {
            auto const *const table{page_pool.allocate<pt_t>(tls, ALLOCATE_TAG_PTS)};
            if (bsl::unlikely(nullptr == table)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            auto const table_phys{page_pool.virt_to_phys(table)};
            if (bsl::unlikely_assert(!table_phys)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            constexpr auto enable{1_umax};
            pdte->phys = (table_phys >> HYPERVISOR_PAGE_SHIFT).get();
            pdte->p = enable.get();
            pdte->rw = enable.get();
            pdte->us = enable.get();

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Adds a pt_t to the provided pdte_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param page_pool the page_pool_t to use
        ///   @param pdte the pdte_t to add a pt_t too
        ///
        static constexpr void
        remove_pt(tls_t &tls, page_pool_t &page_pool, pdte_t *const pdte) noexcept
        {
            constexpr auto disabled{0_umax};
            for (auto const elem : get_pt(page_pool, pdte)->entries) {
                if (disabled == elem.data->p) {
                    continue;
                }

                switch (elem.data->auto_release) {
                    case MAP_PAGE_NO_AUTO_RELEASE.get(): {
                        break;
                    }

                    case MAP_PAGE_AUTO_RELEASE_ALLOC_PAGE.get(): {
                        page_pool.deallocate<page_t>(
                            tls,
                            pte_from_page_pool_to_virt(page_pool, elem.data),
                            ALLOCATE_TAG_BF_MEM_OP_ALLOC_PAGE);

                        break;
                    }

                    case MAP_PAGE_AUTO_RELEASE_ALLOC_HEAP.get(): {
                        page_pool.deallocate<page_t>(
                            tls,
                            pte_from_page_pool_to_virt(page_pool, elem.data),
                            ALLOCATE_TAG_BF_MEM_OP_ALLOC_HEAP);

                        break;
                    }

                    case MAP_PAGE_AUTO_RELEASE_STACK.get(): {
                        page_pool.deallocate<page_t>(
                            tls,
                            pte_from_page_pool_to_virt(page_pool, elem.data),
                            ALLOCATE_TAG_EXT_STACK);

                        break;
                    }

                    case MAP_PAGE_AUTO_RELEASE_TLS.get(): {
                        page_pool.deallocate<page_t>(
                            tls,
                            pte_from_page_pool_to_virt(page_pool, elem.data),
                            ALLOCATE_TAG_EXT_TLS);

                        break;
                    }

                    case MAP_PAGE_AUTO_RELEASE_ELF.get(): {
                        page_pool.deallocate<page_t>(
                            tls,
                            pte_from_page_pool_to_virt(page_pool, elem.data),
                            ALLOCATE_TAG_EXT_ELF);

                        break;
                    }

                    default: {
                        bsl::error() << "uknown tag\n" << bsl::here();
                        break;
                    }
                }
            }

            page_pool.deallocate(tls, get_pt(page_pool, pdte), ALLOCATE_TAG_PTS);
        }

        /// <!-- description -->
        ///   @brief Returns the pt_t associated with the provided
        ///     pdte_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param page_pool the page_pool_t to use
        ///   @param pdte the pdte_t to get the pt_t from
        ///   @return A pointer to the requested pt_t
        ///
        [[nodiscard]] static constexpr auto
        get_pt(page_pool_t &page_pool, pdte_t *const pdte) noexcept -> pt_t *
        {
            bsl::safe_uintmax entry_phys{pdte->phys};
            entry_phys <<= HYPERVISOR_PAGE_SHIFT;

            return page_pool.template phys_to_virt<pt_t>(entry_phys);
        }

        /// <!-- description -->
        ///   @brief Returns the pt_t associated with the provided
        ///     pdte_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param page_pool the page_pool_t to use
        ///   @param pdte the pdte_t to get the pt_t from
        ///   @return A pointer to the requested pt_t
        ///
        [[nodiscard]] static constexpr auto
        get_pt(page_pool_t &page_pool, pdte_t const *const pdte) noexcept -> pt_t const *
        {
            bsl::safe_uintmax entry_phys{pdte->phys};
            entry_phys <<= HYPERVISOR_PAGE_SHIFT;

            return page_pool.template phys_to_virt<pt_t const>(entry_phys);
        }

        /// <!-- description -->
        ///   @brief Returns the page-table (PT) offset given a
        ///     virtual address.
        ///
        /// <!-- inputs/outputs -->
        ///   @param virt the virtual address to get the PT offset from.
        ///   @return the PT offset from the virtual address
        ///
        [[nodiscard]] static constexpr auto
        pto(bsl::safe_uintmax const &virt) noexcept -> bsl::safe_uintmax
        {
            constexpr auto mask{0x1FF_umax};
            constexpr auto shft{12_umax};
            return (virt >> shft) & mask;
        }

        /// <!-- description -->
        ///   @brief Dumps the provided pt_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param pt the pt_t to dump
        ///   @param is_pml4te_last_index true if the parent pml4te was the
        ///     last pml4te in the table
        ///   @param is_pdpte_last_index true if the parent pdpte was the
        ///     last pdpte in the table
        ///   @param is_pdte_last_index true if the parent pdte was the
        ///     last pdte in the table
        ///
        static constexpr void
        dump_pt(
            pt_t const *const pt,
            bool is_pml4te_last_index,
            bool is_pdpte_last_index,
            bool is_pdte_last_index) noexcept
        {
            bsl::safe_uintmax const last_index{get_last_index(pt)};

            constexpr auto disabled{0_umax};
            for (auto const elem : pt->entries) {
                if (disabled == elem.data->p) {
                    continue;
                }

                output_spacing(is_pml4te_last_index);
                output_spacing(is_pdpte_last_index);
                output_spacing(is_pdte_last_index);
                output_decoration_and_index(elem.index, last_index);

                bsl::print() << bsl::rst;
                output_entry_and_flags(elem.data);
            }
        }

        /// <!-- description -->
        ///   @brief Returns the virtual address associated with a specific
        ///     pte that was allocated using the page pool.
        ///
        /// <!-- inputs/outputs -->
        ///   @param page_pool the page_pool_t to use
        ///   @param pte the pte_t to convert
        ///   @return Returns the virtual address associated with a specific
        ///     pte that was allocated using the page pool.
        ///
        [[nodiscard]] static constexpr auto
        pte_from_page_pool_to_virt(page_pool_t &page_pool, pte_t *const pte) noexcept -> page_t *
        {
            bsl::safe_uintmax entry_phys{pte->phys};
            entry_phys <<= HYPERVISOR_PAGE_SHIFT;

            return page_pool.phys_to_virt<page_t>(entry_phys);
        }

        /// <!-- description -->
        ///   @brief Returns the virtual address associated with a specific
        ///     pte that was allocated using the huge pool.
        ///
        /// <!-- inputs/outputs -->
        ///   @param huge_pool the huge_pool_t to use
        ///   @param pte the pte_t to convert
        ///   @return Returns the virtual address associated with a specific
        ///     pte that was allocated using the huge pool.
        ///
        [[nodiscard]] static constexpr auto
        pte_from_huge_pool_to_virt(huge_pool_t &huge_pool, pte_t *const pte) noexcept -> page_t *
        {
            bsl::safe_uintmax entry_phys{pte->phys};
            entry_phys <<= HYPERVISOR_PAGE_SHIFT;

            return huge_pool.phys_to_virt<page_t>(entry_phys);
        }

        /// <!-- description -->
        ///   @brief Returns the page aligned version of the addr
        ///
        /// <!-- inputs/outputs -->
        ///   @param addr the address to query
        ///   @return Returns the page aligned version of the addr
        ///
        [[nodiscard]] static constexpr auto
        page_aligned(bsl::safe_uintmax const &addr) noexcept -> bsl::safe_uintmax
        {
            constexpr auto one{1_umax};
            return (addr & ~(HYPERVISOR_PAGE_SIZE - one));
        }

        /// <!-- description -->
        ///   @brief Returns true if the provided address is page aligned
        ///
        /// <!-- inputs/outputs -->
        ///   @param addr the address to query
        ///   @return Returns true if the provided address is page aligned
        ///
        [[nodiscard]] static constexpr auto
        is_page_aligned(bsl::safe_uintmax const &addr) noexcept -> bool
        {
            constexpr auto one{1_umax};
            constexpr auto aligned{0_umax};
            return (addr & (HYPERVISOR_PAGE_SIZE - one)) == aligned;
        }

        /// <!-- description -->
        ///   @brief Allocates a page from the provided page pool and maps it
        ///     into the root page table being managed by this class The page
        ///     is marked as "auto release", meaning when this root page table
        ///     is released, the pages allocated by this function will
        ///     automatically be deallocated and put back into the provided
        ///     page pool.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param page_pool the page_pool_t to use
        ///   @param page_virt the virtual address to map the allocated
        ///     page to
        ///   @param page_flags defines how memory should be mapped
        ///   @param auto_release defines what auto release tag to use
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        allocate_page(
            tls_t &tls,
            page_pool_t &page_pool,
            bsl::safe_uintmax const &page_virt,
            bsl::safe_uintmax const &page_flags,
            bsl::safe_int32 const &auto_release) noexcept -> void *
        {
            bsl::errc_type ret{};

            page_t *page{};
            switch (auto_release.get()) {
                case MAP_PAGE_AUTO_RELEASE_STACK.get(): {
                    /// fixme, this should not be bsl::uint8
                    page = page_pool.allocate<page_t>(tls, ALLOCATE_TAG_EXT_STACK);
                    break;
                }

                case MAP_PAGE_AUTO_RELEASE_TLS.get(): {
                    /// fixme, this should not be bsl::uint8
                    page = page_pool.allocate<page_t>(tls, ALLOCATE_TAG_EXT_TLS);
                    break;
                }

                case MAP_PAGE_AUTO_RELEASE_ELF.get(): {
                    /// fixme, this should not be bsl::uint8
                    page = page_pool.allocate<page_t>(tls, ALLOCATE_TAG_EXT_ELF);
                    break;
                }

                default: {
                    bsl::error() << "unknown tag\n" << bsl::here();
                    break;
                }
            }

            if (bsl::unlikely(nullptr == page)) {
                bsl::print<bsl::V>() << bsl::here();
                return nullptr;
            }

            auto const page_phys{page_pool.virt_to_phys(page)};
            if (bsl::unlikely_assert(!page_phys)) {
                bsl::error() << "physical address is invalid "    // --
                             << bsl::hex(page_phys)               // --
                             << bsl::endl                         // --
                             << bsl::here();                      // --

                return nullptr;
            }

            ret = this->map_page(tls, page_pool, page_virt, page_phys, page_flags, auto_release);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return nullptr;
            }

            return page;
        }

        /// <!-- description -->
        ///   @brief Releases the memory allocated for tables
        ///
        /// <!-- inputs/outputs -->
        ///   @param page_pool the page_pool_t to use
        ///   @param tls the current TLS block
        ///
        constexpr void
        release_tables(tls_t &tls, page_pool_t &page_pool) noexcept
        {
            constexpr auto disabled{0_umax};
            for (auto const elem : m_pml4t->entries) {
                if (disabled == elem.data->p) {
                    continue;
                }

                if (disabled != elem.data->alias) {
                    continue;
                }

                this->remove_pdpt(tls, page_pool, elem.data);
            }

            page_pool.deallocate(tls, m_pml4t, ALLOCATE_TAG_PML4TS);
            m_pml4t = {};
            m_pml4t_phys = bsl::safe_uintmax::failure();
        }

    public:
        /// <!-- description -->
        ///   @brief Initializes this root_page_table_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param page_pool the page_pool_t to use
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        initialize(tls_t &tls, page_pool_t &page_pool) noexcept -> bsl::errc_type
        {
            if (bsl::unlikely_assert(m_pml4t_phys)) {
                bsl::error() << "root_page_table_t already initialized\n" << bsl::here();
                return bsl::errc_failure;
            }

            bsl::finally release_on_error{[this, &tls, &page_pool]() noexcept -> void {
                this->release(tls, page_pool);
            }};

            m_pml4t = page_pool.template allocate<pml4t_t>(tls, ALLOCATE_TAG_PML4TS);
            if (bsl::unlikely(nullptr == m_pml4t)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            m_pml4t_phys = page_pool.virt_to_phys(m_pml4t);
            if (bsl::unlikely_assert(!m_pml4t_phys)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            release_on_error.ignore();
            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Releases all of the resources used by the RPT.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param page_pool the page_pool_t to use
        ///
        constexpr void
        release(tls_t &tls, page_pool_t &page_pool) noexcept
        {
            lock_guard_t lock{tls, m_lock};
            this->release_tables(tls, page_pool);
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
            return !!m_pml4t_phys;
        }

        /// <!-- description -->
        ///   @brief Sets the current root page table to this root page table.
        ///
        /// <!-- inputs/outputs -->
        ///   @param intrinsic the intrinsic_t to use
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        activate(intrinsic_t &intrinsic) const noexcept -> bsl::errc_type
        {
            if (bsl::unlikely_assert(!m_pml4t_phys)) {
                bsl::error() << "root_page_table_t not initialized\n" << bsl::here();
                return bsl::errc_failure;
            }

            intrinsic.set_cr3(m_pml4t_phys);
            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Given a root page table, the pml4te_t enties are aliased
        ///     into this page table, allowing software using this root page
        ///     table to access the memory mapped into the provided root page
        ///     table. The additions are aliases only, meaning when this root
        ///     page table loses scope, aliased entries added by this function
        ///     are not returned back to the page pool.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param rpt the root page table to add aliases to
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        add_tables(tls_t &tls, void const *const rpt) noexcept -> bsl::errc_type
        {
            lock_guard_t lock{tls, m_lock};

            if (bsl::unlikely_assert(!m_pml4t_phys)) {
                bsl::error() << "root_page_table_t not initialized\n" << bsl::here();
                return bsl::errc_failure;
            }

            auto const *const pml4t{static_cast<pml4t_t const *>(rpt)};
            if (bsl::unlikely_assert(nullptr == pml4t)) {
                bsl::error() << "invalid rpt\n" << bsl::here();
                return bsl::errc_failure;
            }

            constexpr auto enable{1_umax};
            constexpr auto disabled{0_umax};

            for (auto const elem : pml4t->entries) {
                if (disabled != elem.data->p) {
                    auto *const pml4e_dst{m_pml4t->entries.at_if(elem.index)};

                    *pml4e_dst = *elem.data;
                    pml4e_dst->alias = enable.get();
                }
                else {
                    bsl::touch();
                }
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Given a root page table, the pml4te_t enties are aliased
        ///     into this page table, allowing software using this root page
        ///     table to access the memory mapped into the provided root page
        ///     table. The additions are aliases only, meaning when this root
        ///     page table loses scope, aliased entries added by this function
        ///     are not returned back to the page pool.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param rpt the root page table to add aliases to
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        add_tables(tls_t &tls, root_page_table_t const &rpt) noexcept -> bsl::errc_type
        {
            return this->add_tables(tls, rpt.m_pml4t);
        }

        /// <!-- description -->
        ///   @brief Maps a page into the root page table being managed
        ///     by this class.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param page_pool the page_pool_t to use
        ///   @param page_virt the virtual address to map the physical address
        ///     too.
        ///   @param page_phys the physical address to map.
        ///   @param page_flags defines how memory should be mapped
        ///   @param auto_release defines what auto release tag to use
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        map_page(
            tls_t &tls,
            page_pool_t &page_pool,
            bsl::safe_uintmax const &page_virt,
            bsl::safe_uintmax const &page_phys,
            bsl::safe_uintmax const &page_flags,
            bsl::safe_int32 const &auto_release) noexcept -> bsl::errc_type
        {
            constexpr auto disabled{0_umax};
            lock_guard_t lock{tls, m_lock};

            if (bsl::unlikely_assert(!m_pml4t_phys)) {
                bsl::error() << "root_page_table_t not initialized\n" << bsl::here();
                return bsl::errc_failure;
            }

            if (bsl::unlikely_assert(page_virt.is_zero())) {
                bsl::error() << "virtual address is invalid "    // --
                             << bsl::hex(page_virt)              // --
                             << bsl::endl                        // --
                             << bsl::here();                     // --

                return bsl::errc_failure;
            }

            if (bsl::unlikely_assert(!this->is_page_aligned(page_virt))) {
                bsl::error() << "virtual address is not page aligned "    // --
                             << bsl::hex(page_virt)                       // --
                             << bsl::endl                                 // --
                             << bsl::here();                              // --

                return bsl::errc_failure;
            }

            if (bsl::unlikely_assert(page_phys.is_zero())) {
                bsl::error() << "physical address is invalid "    // --
                             << bsl::hex(page_phys)               // --
                             << bsl::endl                         // --
                             << bsl::here();                      // --

                return bsl::errc_failure;
            }

            if (bsl::unlikely_assert(!this->is_page_aligned(page_phys))) {
                bsl::error() << "physical address is not page aligned "    // --
                             << bsl::hex(page_phys)                        // --
                             << bsl::endl                                  // --
                             << bsl::here();                               // --

                return bsl::errc_failure;
            }

            if (bsl::unlikely_assert(!page_flags)) {
                bsl::error() << "invalid flags "        // --
                             << bsl::hex(page_flags)    // --
                             << bsl::endl               // --
                             << bsl::here();            // --

                return bsl::errc_failure;
            }

            if (bsl::unlikely_assert(!auto_release)) {
                bsl::error() << "invalid auto release "    // --
                             << auto_release               // --
                             << bsl::endl                  // --
                             << bsl::here();               // --

                return bsl::errc_failure;
            }

            if ((page_flags & MAP_PAGE_WRITE).is_pos()) {
                if ((page_flags & MAP_PAGE_EXECUTE).is_pos()) {
                    bsl::error() << "invalid page_flags "    // --
                                 << bsl::hex(page_flags)     // --
                                 << bsl::endl                // --
                                 << bsl::here();             // --

                    return bsl::errc_failure;
                }

                bsl::touch();
            }
            else {
                bsl::touch();
            }

            auto *const pml4te{m_pml4t->entries.at_if(this->pml4to(page_virt))};
            if (disabled == pml4te->p) {
                if (bsl::unlikely(!this->add_pdpt(tls, page_pool, pml4te))) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                bsl::touch();
            }
            else {

                /// NOTE:
                /// - The loader doesn't map in the memory associated with
                ///   the microkernel's page tables. This means this code
                ///   cannot walk any pages mapped to the microkernel, it
                ///   can only alias these pages. For this reason, mapping
                ///   must always take place on userspace specific memory
                ///   and the address spaces must be distinct.
                ///

                if (disabled == pml4te->us) {
                    bsl::error() << "attempt to map the userspace address "              // --
                                 << bsl::hex(page_virt)                                  // --
                                 << " in an address range owned by the kernel failed"    // --
                                 << bsl::endl                                            // --
                                 << bsl::here();                                         // --

                    return bsl::errc_failure;
                }

                bsl::touch();
            }

            auto *const pdpt{get_pdpt(page_pool, pml4te)};
            auto *const pdpte{pdpt->entries.at_if(this->pdpto(page_virt))};
            if (disabled == pdpte->p) {
                if (bsl::unlikely(!this->add_pdt(tls, page_pool, pdpte))) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                bsl::touch();
            }
            else {
                bsl::touch();
            }

            auto *const pdt{get_pdt(page_pool, pdpte)};
            auto *const pdte{pdt->entries.at_if(this->pdto(page_virt))};
            if (disabled == pdte->p) {
                if (bsl::unlikely(!this->add_pt(tls, page_pool, pdte))) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                bsl::touch();
            }
            else {
                bsl::touch();
            }

            auto *const pt{get_pt(page_pool, pdte)};
            auto *const pte{pt->entries.at_if(this->pto(page_virt))};
            if (bsl::unlikely(disabled != pte->p)) {
                bsl::error() << "virtual address "     // --
                             << bsl::hex(page_virt)    // --
                             << " already mapped"      // --
                             << bsl::endl              // --
                             << bsl::here();           // --

                return bsl::errc_already_exists;
            }

            constexpr auto enable{1_umax};
            constexpr auto disable{0_umax};

            pte->phys = (page_phys >> HYPERVISOR_PAGE_SHIFT).get();
            pte->p = enable.get();
            pte->us = enable.get();
            pte->auto_release = auto_release.get();

            if (!(page_flags & MAP_PAGE_WRITE).is_zero()) {
                pte->rw = enable.get();
            }
            else {
                pte->rw = disable.get();
            }

            if (!(page_flags & MAP_PAGE_EXECUTE).is_zero()) {
                pte->nx = disable.get();
            }
            else {
                pte->nx = enable.get();
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Maps a page into the root page table being managed
        ///     by this class. This version allows for unaligned virtual and
        ///     physical addresses and will perform the alignment for you.
        ///     Note that you should only use this function if you actually
        ///     need unaligned support to ensure alignment mistakes are not
        ///     accidentally introduced.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param page_pool the page_pool_t to use
        ///   @param page_virt the virtual address to map the physical address
        ///     too.
        ///   @param page_phys the physical address to map. If the physical
        ///     address is set to 0, map_page will use the page pool to
        ///     determine the physical address.
        ///   @param page_flags defines how memory should be mapped
        ///   @param auto_release defines what auto release tag to use
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        map_page_unaligned(
            tls_t &tls,
            page_pool_t &page_pool,
            bsl::safe_uintmax const &page_virt,
            bsl::safe_uintmax const &page_phys,
            bsl::safe_uintmax const &page_flags,
            bsl::safe_int32 const &auto_release) noexcept -> bsl::errc_type
        {
            return this->map_page(
                tls,
                page_pool,
                this->page_aligned(page_virt),
                this->page_aligned(page_phys),
                page_flags,
                auto_release);
        }

        /// <!-- description -->
        ///   @brief Allocates a page from the provided page pool and maps it
        ///     into the root page table being managed by this class The page
        ///     is marked as "auto release", meaning when this root page table
        ///     is released, the pages allocated by this function will
        ///     automatically be deallocated and put back into the provided
        ///     page pool. Note that this version maps the memory in as
        ///     read/write.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param page_pool the page_pool_t to use
        ///   @param page_virt the virtual address to map the allocated
        ///     page to
        ///   @param auto_release defines what auto release tag to use
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        allocate_page_rw(
            tls_t &tls,
            page_pool_t &page_pool,
            bsl::safe_uintmax const &page_virt,
            bsl::safe_int32 const &auto_release) noexcept -> void *
        {
            if (bsl::unlikely_assert(!m_pml4t_phys)) {
                bsl::error() << "root_page_table_t not initialized\n" << bsl::here();
                return nullptr;
            }

            if (bsl::unlikely_assert(page_virt.is_zero())) {
                bsl::error() << "virtual address is invalid "    // --
                             << bsl::hex(page_virt)              // --
                             << bsl::endl                        // --
                             << bsl::here();                     // --

                return nullptr;
            }

            if (bsl::unlikely_assert(!this->is_page_aligned(page_virt))) {
                bsl::error() << "virtual address is not page aligned "    // --
                             << bsl::hex(page_virt)                       // --
                             << bsl::endl                                 // --
                             << bsl::here();                              // --

                return nullptr;
            }

            if (bsl::unlikely_assert(!auto_release)) {
                bsl::error() << "invalid auto release "    // --
                             << auto_release               // --
                             << bsl::endl                  // --
                             << bsl::here();               // --

                return nullptr;
            }

            return this->allocate_page(
                tls, page_pool, page_virt, MAP_PAGE_READ | MAP_PAGE_WRITE, auto_release);
        }

        /// <!-- description -->
        ///   @brief Allocates a page from the provided page pool and maps it
        ///     into the root page table being managed by this class The page
        ///     is marked as "auto release", meaning when this root page table
        ///     is released, the pages allocated by this function will
        ///     automatically be deallocated and put back into the provided
        ///     page pool. Note that this version maps the memory in as
        ///     read/execute.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param page_pool the page_pool_t to use
        ///   @param page_virt the virtual address to map the allocated
        ///     page to
        ///   @param auto_release defines what auto release tag to use
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        allocate_page_rx(
            tls_t &tls,
            page_pool_t &page_pool,
            bsl::safe_uintmax const &page_virt,
            bsl::safe_int32 const &auto_release) noexcept -> void *
        {
            if (bsl::unlikely_assert(!m_pml4t_phys)) {
                bsl::error() << "root_page_table_t not initialized\n" << bsl::here();
                return nullptr;
            }

            if (bsl::unlikely_assert(page_virt.is_zero())) {
                bsl::error() << "virtual address is invalid "    // --
                             << bsl::hex(page_virt)              // --
                             << bsl::endl                        // --
                             << bsl::here();                     // --

                return nullptr;
            }

            if (bsl::unlikely_assert(!this->is_page_aligned(page_virt))) {
                bsl::error() << "virtual address is not page aligned "    // --
                             << bsl::hex(page_virt)                       // --
                             << bsl::endl                                 // --
                             << bsl::here();                              // --

                return nullptr;
            }

            if (bsl::unlikely_assert(!auto_release)) {
                bsl::error() << "invalid auto release "    // --
                             << auto_release               // --
                             << bsl::endl                  // --
                             << bsl::here();               // --

                return nullptr;
            }

            return this->allocate_page(
                tls, page_pool, page_virt, MAP_PAGE_READ | MAP_PAGE_EXECUTE, auto_release);
        }

        /// <!-- description -->
        ///   @brief Dumps the provided pml4_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param page_pool the page_pool_t to use
        ///
        constexpr void
        dump(page_pool_t &page_pool) const noexcept
        {
            if constexpr (BSL_DEBUG_LEVEL == bsl::CRITICAL_ONLY) {
                return;
            }

            if (bsl::unlikely_assert(!m_pml4t_phys)) {
                bsl::print() << "[error]" << bsl::endl;
                return;
            }

            dump_pml4t(page_pool, m_pml4t);
        }
    };
}

#endif
