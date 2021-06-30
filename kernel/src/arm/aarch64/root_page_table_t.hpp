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

#include "../../lock_guard_t.hpp"
#include "../../spinlock_t.hpp"

#include <allocate_tags.hpp>
#include <huge_pool_t.hpp>
#include <intrinsic_t.hpp>
#include <l0t_t.hpp>
#include <l0te_t.hpp>
#include <l1t_t.hpp>
#include <l1te_t.hpp>
#include <l2t_t.hpp>
#include <l2te_t.hpp>
#include <l3t_t.hpp>
#include <l3te_t.hpp>
#include <map_page_flags.hpp>
#include <page_pool_t.hpp>
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
    /// <!-- descril3tion -->
    ///   @brief Implements the root pages tables used by the microkernel
    ///     for mapping extension memory.
    ///
    class root_page_table_t final
    {
        /// @brief stores true if initialized() has been executed
        bool m_initialized{};
        /// @brief stores a reference to the intrinsics to use
        intrinsic_t *m_intrinsic{};
        /// @brief stores a reference to the page pool to use
        page_pool_t *m_page_pool{};
        /// @brief stores a reference to the huge pool to use
        huge_pool_t *m_huge_pool{};
        /// @brief stores a pointer to the l0t
        l0t_t *m_l0t{};
        /// @brief stores the physical address of the l0t
        bsl::safe_uintmax m_l0t_phys{bsl::safe_uintmax::failure()};
        /// @brief safe guards operations on the RPT.
        mutable spinlock_t m_lock{};

        // /// <!-- descril3tion -->
        // ///   @brief Returns the index of the last entry present in a page
        // ///     table.
        // ///
        // /// <!-- inputs/outputs -->
        // ///   @tparam TABLE_CONCEPT the type of page table to search
        // ///   @param table the page table to search
        // ///   @return Returns the index of the last entry present in a page
        // ///     table.
        // ///
        // template<typename TABLE_CONCEPT>
        // [[nodiscard]] constexpr auto
        // get_last_index(TABLE_CONCEPT const *const table) const noexcept -> bsl::safe_uintmax
        // {
        //     bsl::safe_uintmax last_index{};
        //     for (auto const elem : table->entries) {
        //         if (bsl::ZERO_UMAX == elem.data->p) {
        //             continue;
        //         }

        //         last_index = elem.index;
        //     }

        //     return last_index;
        // }

        // /// <!-- descril3tion -->
        // ///   @brief Given index and the index of the last
        // ///     present entry in the page table being dumped, this function
        // ///     will output a decoration and the index.
        // ///
        // /// <!-- inputs/outputs -->
        // ///   @param index the current index of the entry being dumped
        // ///   @param last_index the index of the last present entry in the page
        // ///     table being dumped.
        // ///
        // constexpr void
        // output_decoration_and_index(
        //     bsl::safe_uintmax const &index, bsl::safe_uintmax const &last_index) const noexcept
        // {
        //     bsl::print() << bsl::rst;

        //     if (index != last_index) {
        //         bsl::print() << "├── ";
        //     }
        //     else {
        //         bsl::print() << "└── ";
        //     }

        //     bsl::print() << "[" << bsl::ylw << bsl::fmt{"#05x", index} << bsl::rst << "] ";
        // }

        // /// <!-- descril3tion -->
        // ///   @brief Given whether or not the page table
        // ///     entry is the last entry in the table, this function will
        // ///     either output whtspace, or a | and shitespace.
        // ///
        // /// <!-- inputs/outputs -->
        // ///   @param is_last_index true if the entry being outputted is the
        // ///     last index in the table.
        // ///
        // constexpr void
        // output_spacing(bool const is_last_index) const noexcept
        // {
        //     bsl::print() << bsl::rst;

        //     if (!is_last_index) {
        //         bsl::print() << "│   ";
        //     }
        //     else {
        //         bsl::print() << "    ";
        //     }
        // }

        // /// <!-- descril3tion -->
        // ///   @brief Given a page table entry, this
        // ///     function outputs the flags associated with the entry
        // ///
        // /// <!-- inputs/outputs -->
        // ///   @tparam ENTRY_CONCEPT the type of page table entry to output
        // ///   @param entry the page table entry to output
        // ///
        // template<typename ENTRY_CONCEPT>
        // constexpr void
        // output_entry_and_flags(ENTRY_CONCEPT const *const entry) const noexcept
        // {
        //     bool add_comma{};

        //     bsl::print() << bsl::hex(
        //         *static_cast<bsl::uint64 const *>(static_cast<void const *>(entry)));
        //     bsl::print() << bsl::rst << " (";

        //     if (bsl::ZERO_UMAX != entry->rw) {
        //         bsl::print() << bsl::grn << 'W';
        //         add_comma = true;
        //     }
        //     else {
        //         bsl::touch();
        //     }

        //     if (bsl::ZERO_UMAX != entry->us) {
        //         if (add_comma) {
        //             bsl::print() << bsl::rst << ", ";
        //         }
        //         else {
        //             bsl::touch();
        //         }

        //         bsl::print() << bsl::grn << 'U';
        //         add_comma = true;
        //     }
        //     else {
        //         bsl::touch();
        //     }

        //     if (bsl::ZERO_UMAX != entry->nx) {
        //         if (add_comma) {
        //             bsl::print() << bsl::rst << ", ";
        //         }
        //         else {
        //             bsl::touch();
        //         }

        //         bsl::print() << bsl::grn << "NX";
        //         add_comma = true;
        //     }
        //     else {
        //         bsl::touch();
        //     }

        //     if constexpr (bsl::is_same<ENTRY_CONCEPT, loader::l0te_t>::value) {
        //         if (bsl::ZERO_UMAX != entry->alias) {
        //             if (add_comma) {
        //                 bsl::print() << bsl::rst << ", ";
        //             }
        //             else {
        //                 bsl::touch();
        //             }

        //             bsl::print() << bsl::grn << "alias";
        //             add_comma = true;
        //         }
        //         else {
        //             bsl::touch();
        //         }
        //     }

        //     if constexpr (bsl::is_same<ENTRY_CONCEPT, loader::l3te_t>::value) {
        //         if (add_comma) {
        //             bsl::print() << bsl::rst << ", ";
        //         }
        //         else {
        //             bsl::touch();
        //         }

        //         switch (entry->auto_release) {
        //             case MAP_PAGE_AUTO_RELEASE_ALLOC_PAGE.get(): {
        //                 bsl::print() << bsl::grn << "auto_release_alloc_page";
        //                 break;
        //             }

        //             case MAP_PAGE_AUTO_RELEASE_ALLOC_HUGE.get(): {
        //                 bsl::print() << bsl::grn << "auto_release_alloc_huge";
        //                 break;
        //             }

        //             case MAP_PAGE_AUTO_RELEASE_ALLOC_HEAP.get(): {
        //                 bsl::print() << bsl::grn << "auto_release_alloc_heap";
        //                 break;
        //             }

        //             case MAP_PAGE_AUTO_RELEASE_STACK.get(): {
        //                 bsl::print() << bsl::grn << "auto_release_stack";
        //                 break;
        //             }

        //             case MAP_PAGE_AUTO_RELEASE_TLS.get(): {
        //                 bsl::print() << bsl::grn << "auto_release_tls";
        //                 break;
        //             }

        //             case MAP_PAGE_AUTO_RELEASE_ELF.get(): {
        //                 bsl::print() << bsl::grn << "auto_release_elf";
        //                 break;
        //             }

        //             default: {
        //                 bsl::print() << bsl::grn << "manual";
        //                 break;
        //             }
        //         }

        //         add_comma = true;
        //     }

        //     bsl::print() << bsl::rst << ')';
        //     bsl::print() << bsl::rst << bsl::endl;
        // }

        // /// <!-- descril3tion -->
        // ///   @brief Returns the page-map level-4 (PML4T) offset given a
        // ///     virtual address.
        // ///
        // /// <!-- inputs/outputs -->
        // ///   @param virt the virtual address to get the PML4T offset from.
        // ///   @return the PML4T offset from the virtual address
        // ///
        // [[nodiscard]] static constexpr auto
        // l0to(bsl::safe_uintmax const &virt) noexcept -> bsl::safe_uintmax
        // {
        //     constexpr bsl::safe_uintmax mask{bsl::to_umax(0x1FF)};
        //     constexpr bsl::safe_uintmax shift{bsl::to_umax(39)};
        //     return (virt >> shift) & mask;
        // }

        // /// <!-- descril3tion -->
        // ///   @brief Dumps the provided l0t_t
        // ///
        // /// <!-- inputs/outputs -->
        // ///   @param l0t the l0t_t to dump
        // ///
        // constexpr void
        // dump_l0t(l0t_t const *const l0t) const noexcept
        // {
        //     bsl::safe_uintmax const last_index{this->get_last_index(l0t)};

        //     bsl::print() << bsl::blu << bsl::hex(m_l0t_phys);
        //     bsl::print() << bsl::rst << bsl::endl;

        //     for (auto const elem : l0t->entries) {
        //         if (bsl::ZERO_UMAX == elem.data->p) {
        //             continue;
        //         }

        //         this->output_decoration_and_index(elem.index, last_index);

        //         if (bsl::ZERO_UMAX != elem.data->us) {
        //             bsl::print() << bsl::blu;
        //             this->output_entry_and_flags(elem.data);
        //         }
        //         else {
        //             bsl::print() << bsl::blk;
        //             this->output_entry_and_flags(elem.data);
        //         }

        //         if (bsl::ZERO_UMAX != elem.data->us) {
        //             this->dump_l1t(this->get_l1t(elem.data), elem.index == last_index);
        //         }
        //         else {
        //             bsl::touch();
        //         }
        //     }
        // }

        // /// <!-- descril3tion -->
        // ///   @brief Adds a l1t_t to the provided l0te_t.
        // ///
        // /// <!-- inputs/outputs -->
        // ///   @param tls the current TLS block
        // ///   @param l0te the l0te_t to add a l1t_t too
        // ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        // ///     and friends otherwise
        // ///
        // [[nodiscard]] constexpr auto
        // add_l1t(tls_t &tls, loader::l0te_t *const l0te) noexcept -> bsl::errc_type
        // {
        //     auto const *const table{m_page_pool->allocate(tls, ALLOCATE_TAG_PDPTS)};
        //     if (bsl::unlikely(nullptr == table)) {
        //         bsl::print<bsl::V>() << bsl::here();
        //         return bsl::errc_failure;
        //     }

        //     auto const table_phys{m_page_pool->virt_to_phys(table)};
        //     if (bsl::unlikely_assert(!table_phys)) {
        //         bsl::print<bsl::V>() << bsl::here();
        //         return bsl::errc_failure;
        //     }

        //     l0te->phys = (table_phys >> HYPERVISOR_PAGE_SHIFT).get();
        //     l0te->p = bsl::ONE_UMAX.get();
        //     l0te->rw = bsl::ONE_UMAX.get();
        //     l0te->us = bsl::ONE_UMAX.get();

        //     return bsl::errc_success;
        // }

        // /// <!-- descril3tion -->
        // ///   @brief Adds a l1t_t to the provided l0te_t.
        // ///
        // /// <!-- inputs/outputs -->
        // ///   @param tls the current TLS block
        // ///   @param l0te the l0te_t to add a l1t_t too
        // ///
        // constexpr void
        // remove_l1t(tls_t &tls, loader::l0te_t *const l0te) noexcept
        // {
        //     for (auto const elem : get_l1t(l0te)->entries) {
        //         if (elem.data->p != bsl::ZERO_UMAX) {
        //             this->remove_l2t(tls, elem.data);
        //         }
        //         else {
        //             bsl::touch();
        //         }
        //     }

        //     m_page_pool->deallocate(tls, get_l1t(l0te), ALLOCATE_TAG_PDPTS);
        // }

        // /// <!-- descril3tion -->
        // ///   @brief Returns the l1t_t associated with the provided
        // ///     l0te_t.
        // ///
        // /// <!-- inputs/outputs -->
        // ///   @param l0te the l0te_t to get the l1t_t from
        // ///   @return A pointer to the requested l1t_t
        // ///
        // [[nodiscard]] constexpr auto
        // get_l1t(loader::l0te_t *const l0te) noexcept -> l1t_t *
        // {
        //     bsl::safe_uintmax entry_phys{l0te->phys};
        //     entry_phys <<= HYPERVISOR_PAGE_SHIFT;

        //     return m_page_pool->template phys_to_virt<l1t_t>(entry_phys);
        // }

        // /// <!-- descril3tion -->
        // ///   @brief Returns the l1t_t associated with the provided
        // ///     l0te_t.
        // ///
        // /// <!-- inputs/outputs -->
        // ///   @param l0te the l0te_t to get the l1t_t from
        // ///   @return A pointer to the requested l1t_t
        // ///
        // [[nodiscard]] constexpr auto
        // get_l1t(loader::l0te_t const *const l0te) const noexcept -> l1t_t const *
        // {
        //     bsl::safe_uintmax entry_phys{l0te->phys};
        //     entry_phys <<= HYPERVISOR_PAGE_SHIFT;

        //     return m_page_pool->template phys_to_virt<l1t_t const>(entry_phys);
        // }

        // /// <!-- descril3tion -->
        // ///   @brief Returns the page-directory-pointer table (PDPT) offset
        // ///     given a virtual address.
        // ///
        // /// <!-- inputs/outputs -->
        // ///   @param virt the virtual address to get the PDPT offset from.
        // ///   @return the PDPT offset from the virtual address
        // ///
        // [[nodiscard]] static constexpr auto
        // l1to(bsl::safe_uintmax const &virt) noexcept -> bsl::safe_uintmax
        // {
        //     constexpr bsl::safe_uintmax mask{bsl::to_umax(0x1FF)};
        //     constexpr bsl::safe_uintmax shift{bsl::to_umax(30)};
        //     return (virt >> shift) & mask;
        // }

        // /// <!-- descril3tion -->
        // ///   @brief Dumps the provided l1t_t
        // ///
        // /// <!-- inputs/outputs -->
        // ///   @param l1t the l1t_t to dump
        // ///   @param is_l0te_last_index true if the parent l0te was the
        // ///     last l0te in the table
        // ///
        // constexpr void
        // dump_l1t(l1t_t const *const l1t, bool is_l0te_last_index) const noexcept
        // {
        //     bsl::safe_uintmax const last_index{this->get_last_index(l1t)};

        //     for (auto const elem : l1t->entries) {
        //         if (bsl::ZERO_UMAX == elem.data->p) {
        //             continue;
        //         }

        //         this->output_spacing(is_l0te_last_index);
        //         this->output_decoration_and_index(elem.index, last_index);

        //         bsl::print() << bsl::blu;
        //         this->output_entry_and_flags(elem.data);

        //         this->dump_l2t(
        //             this->get_l2t(elem.data), is_l0te_last_index, elem.index == last_index);
        //     }
        // }

        // /// <!-- descril3tion -->
        // ///   @brief Adds a l2t_t to the provided l1te_t.
        // ///
        // /// <!-- inputs/outputs -->
        // ///   @param tls the current TLS block
        // ///   @param l1te the l1te_t to add a l2t_t too
        // ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        // ///     and friends otherwise
        // ///
        // [[nodiscard]] constexpr auto
        // add_l2t(tls_t &tls, loader::l1te_t *const l1te) noexcept -> bsl::errc_type
        // {
        //     auto const *const table{m_page_pool->allocate(tls, ALLOCATE_TAG_PDTS)};
        //     if (bsl::unlikely(nullptr == table)) {
        //         bsl::print<bsl::V>() << bsl::here();
        //         return bsl::errc_failure;
        //     }

        //     auto const table_phys{m_page_pool->virt_to_phys(table)};
        //     if (bsl::unlikely_assert(!table_phys)) {
        //         bsl::print<bsl::V>() << bsl::here();
        //         return bsl::errc_failure;
        //     }

        //     l1te->phys = (table_phys >> HYPERVISOR_PAGE_SHIFT).get();
        //     l1te->p = bsl::ONE_UMAX.get();
        //     l1te->rw = bsl::ONE_UMAX.get();
        //     l1te->us = bsl::ONE_UMAX.get();

        //     return bsl::errc_success;
        // }

        // /// <!-- descril3tion -->
        // ///   @brief Adds a l2t_t to the provided l1te_t.
        // ///
        // /// <!-- inputs/outputs -->
        // ///   @param tls the current TLS block
        // ///   @param l1te the l1te_t to add a l2t_t too
        // ///
        // constexpr void
        // remove_l2t(tls_t &tls, loader::l1te_t *const l1te) noexcept
        // {
        //     for (auto const elem : get_l2t(l1te)->entries) {
        //         if (elem.data->p != bsl::ZERO_UMAX) {
        //             this->remove_l3t(tls, elem.data);
        //         }
        //         else {
        //             bsl::touch();
        //         }
        //     }

        //     m_page_pool->deallocate(tls, get_l2t(l1te), ALLOCATE_TAG_PDTS);
        // }

        // /// <!-- descril3tion -->
        // ///   @brief Returns the l2t_t associated with the provided
        // ///     l1te_t.
        // ///
        // /// <!-- inputs/outputs -->
        // ///   @param l1te the l1te_t to get the l2t_t from
        // ///   @return A pointer to the requested l2t_t
        // ///
        // [[nodiscard]] constexpr auto
        // get_l2t(loader::l1te_t *const l1te) noexcept -> l2t_t *
        // {
        //     bsl::safe_uintmax entry_phys{l1te->phys};
        //     entry_phys <<= HYPERVISOR_PAGE_SHIFT;

        //     return m_page_pool->template phys_to_virt<l2t_t>(entry_phys);
        // }

        // /// <!-- descril3tion -->
        // ///   @brief Returns the l2t_t associated with the provided
        // ///     l1te_t.
        // ///
        // /// <!-- inputs/outputs -->
        // ///   @param l1te the l1te_t to get the l2t_t from
        // ///   @return A pointer to the requested l2t_t
        // ///
        // [[nodiscard]] constexpr auto
        // get_l2t(loader::l1te_t const *const l1te) const noexcept -> l2t_t const *
        // {
        //     bsl::safe_uintmax entry_phys{l1te->phys};
        //     entry_phys <<= HYPERVISOR_PAGE_SHIFT;

        //     return m_page_pool->template phys_to_virt<l2t_t const>(entry_phys);
        // }

        // /// <!-- descril3tion -->
        // ///   @brief Returns the page-directory table (PDT) offset given a
        // ///     virtual address.
        // ///
        // /// <!-- inputs/outputs -->
        // ///   @param virt the virtual address to get the PDT offset from.
        // ///   @return the PDT offset from the virtual address
        // ///
        // [[nodiscard]] static constexpr auto
        // l2to(bsl::safe_uintmax const &virt) noexcept -> bsl::safe_uintmax
        // {
        //     constexpr bsl::safe_uintmax mask{bsl::to_umax(0x1FF)};
        //     constexpr bsl::safe_uintmax shift{bsl::to_umax(21)};
        //     return (virt >> shift) & mask;
        // }

        // /// <!-- descril3tion -->
        // ///   @brief Dumps the provided l2t_t
        // ///
        // /// <!-- inputs/outputs -->
        // ///   @param l2t the l2t_t to dump
        // ///   @param is_l0te_last_index true if the parent l0te was the
        // ///     last l0te in the table
        // ///   @param is_l1te_last_index true if the parent l1te was the
        // ///     last l1te in the table
        // ///
        // constexpr void
        // dump_l2t(l2t_t const *const l2t, bool is_l0te_last_index, bool is_l1te_last_index)
        //     const noexcept
        // {
        //     bsl::safe_uintmax const last_index{this->get_last_index(l2t)};

        //     for (auto const elem : l2t->entries) {
        //         if (bsl::ZERO_UMAX == elem.data->p) {
        //             continue;
        //         }

        //         this->output_spacing(is_l0te_last_index);
        //         this->output_spacing(is_l1te_last_index);
        //         this->output_decoration_and_index(elem.index, last_index);

        //         bsl::print() << bsl::blu;
        //         this->output_entry_and_flags(elem.data);

        //         this->dump_l3t(
        //             this->get_l3t(elem.data),
        //             is_l0te_last_index,
        //             is_l1te_last_index,
        //             elem.index == last_index);
        //     }
        // }

        // /// <!-- descril3tion -->
        // ///   @brief Adds a l3t_t to the provided l2te_t.
        // ///
        // /// <!-- inputs/outputs -->
        // ///   @param tls the current TLS block
        // ///   @param l2te the l2te_t to add a l3t_t too
        // ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        // ///     and friends otherwise
        // ///
        // [[nodiscard]] constexpr auto
        // add_l3t(tls_t &tls, loader::l2te_t *const l2te) noexcept -> bsl::errc_type
        // {
        //     auto const *const table{m_page_pool->allocate(tls, ALLOCATE_TAG_PTS)};
        //     if (bsl::unlikely(nullptr == table)) {
        //         bsl::print<bsl::V>() << bsl::here();
        //         return bsl::errc_failure;
        //     }

        //     auto const table_phys{m_page_pool->virt_to_phys(table)};
        //     if (bsl::unlikely_assert(!table_phys)) {
        //         bsl::print<bsl::V>() << bsl::here();
        //         return bsl::errc_failure;
        //     }

        //     l2te->phys = (table_phys >> HYPERVISOR_PAGE_SHIFT).get();
        //     l2te->p = bsl::ONE_UMAX.get();
        //     l2te->rw = bsl::ONE_UMAX.get();
        //     l2te->us = bsl::ONE_UMAX.get();

        //     return bsl::errc_success;
        // }

        // /// <!-- descril3tion -->
        // ///   @brief Adds a l3t_t to the provided l2te_t.
        // ///
        // /// <!-- inputs/outputs -->
        // ///   @param tls the current TLS block
        // ///   @param l2te the l2te_t to add a l3t_t too
        // ///
        // constexpr void
        // remove_l3t(tls_t &tls, loader::l2te_t *const l2te) noexcept
        // {
        //     for (auto const elem : get_l3t(l2te)->entries) {
        //         if (elem.data->p == bsl::ZERO_UMAX) {
        //             continue;
        //         }

        //         switch (elem.data->auto_release) {
        //             case MAP_PAGE_NO_AUTO_RELEASE.get(): {
        //                 break;
        //             }

        //             case MAP_PAGE_AUTO_RELEASE_ALLOC_PAGE.get(): {
        //                 m_page_pool->deallocate(
        //                     tls,
        //                     this->l3te_from_page_pool_to_virt(elem.data),
        //                     ALLOCATE_TAG_BF_MEM_OP_ALLOC_PAGE);

        //                 break;
        //             }

        //             case MAP_PAGE_AUTO_RELEASE_ALLOC_HUGE.get(): {
        //                 m_huge_pool->deallocate(tls, this->l3te_from_huge_pool_to_virt(elem.data));
        //                 break;
        //             }

        //             case MAP_PAGE_AUTO_RELEASE_ALLOC_HEAP.get(): {
        //                 m_page_pool->deallocate(
        //                     tls,
        //                     this->l3te_from_page_pool_to_virt(elem.data),
        //                     ALLOCATE_TAG_BF_MEM_OP_ALLOC_HEAP);

        //                 break;
        //             }

        //             case MAP_PAGE_AUTO_RELEASE_STACK.get(): {
        //                 m_page_pool->deallocate(
        //                     tls,
        //                     this->l3te_from_page_pool_to_virt(elem.data),
        //                     ALLOCATE_TAG_EXT_STACK);

        //                 break;
        //             }

        //             case MAP_PAGE_AUTO_RELEASE_TLS.get(): {
        //                 m_page_pool->deallocate(
        //                     tls, this->l3te_from_page_pool_to_virt(elem.data), ALLOCATE_TAG_EXT_TLS);

        //                 break;
        //             }

        //             case MAP_PAGE_AUTO_RELEASE_ELF.get(): {
        //                 m_page_pool->deallocate(
        //                     tls, this->l3te_from_page_pool_to_virt(elem.data), ALLOCATE_TAG_EXT_ELF);

        //                 break;
        //             }

        //             default: {
        //                 bsl::error() << "uknown tag\n" << bsl::here();
        //                 break;
        //             }
        //         }
        //     }

        //     m_page_pool->deallocate(tls, get_l3t(l2te), ALLOCATE_TAG_PTS);
        // }

        // /// <!-- descril3tion -->
        // ///   @brief Returns the l3t_t associated with the provided
        // ///     l2te_t.
        // ///
        // /// <!-- inputs/outputs -->
        // ///   @param l2te the l2te_t to get the l3t_t from
        // ///   @return A pointer to the requested l3t_t
        // ///
        // [[nodiscard]] constexpr auto
        // get_l3t(loader::l2te_t *const l2te) noexcept -> l3t_t *
        // {
        //     bsl::safe_uintmax entry_phys{l2te->phys};
        //     entry_phys <<= HYPERVISOR_PAGE_SHIFT;

        //     return m_page_pool->template phys_to_virt<l3t_t>(entry_phys);
        // }

        // /// <!-- descril3tion -->
        // ///   @brief Returns the l3t_t associated with the provided
        // ///     l2te_t.
        // ///
        // /// <!-- inputs/outputs -->
        // ///   @param l2te the l2te_t to get the l3t_t from
        // ///   @return A pointer to the requested l3t_t
        // ///
        // [[nodiscard]] constexpr auto
        // get_l3t(loader::l2te_t const *const l2te) const noexcept -> l3t_t const *
        // {
        //     bsl::safe_uintmax entry_phys{l2te->phys};
        //     entry_phys <<= HYPERVISOR_PAGE_SHIFT;

        //     return m_page_pool->template phys_to_virt<l3t_t const>(entry_phys);
        // }

        // /// <!-- descril3tion -->
        // ///   @brief Returns the page-table (PT) offset given a
        // ///     virtual address.
        // ///
        // /// <!-- inputs/outputs -->
        // ///   @param virt the virtual address to get the PT offset from.
        // ///   @return the PT offset from the virtual address
        // ///
        // [[nodiscard]] static constexpr auto
        // l3to(bsl::safe_uintmax const &virt) noexcept -> bsl::safe_uintmax
        // {
        //     constexpr bsl::safe_uintmax mask{bsl::to_umax(0x1FF)};
        //     constexpr bsl::safe_uintmax shift{bsl::to_umax(12)};
        //     return (virt >> shift) & mask;
        // }

        // /// <!-- descril3tion -->
        // ///   @brief Dumps the provided l3t_t
        // ///
        // /// <!-- inputs/outputs -->
        // ///   @param l3t the l3t_t to dump
        // ///   @param is_l0te_last_index true if the parent l0te was the
        // ///     last l0te in the table
        // ///   @param is_l1te_last_index true if the parent l1te was the
        // ///     last l1te in the table
        // ///   @param is_l2te_last_index true if the parent l2te was the
        // ///     last l2te in the table
        // ///
        // constexpr void
        // dump_l3t(
        //     l3t_t const *const l3t,
        //     bool is_l0te_last_index,
        //     bool is_l1te_last_index,
        //     bool is_l2te_last_index) const noexcept
        // {
        //     bsl::safe_uintmax const last_index{this->get_last_index(l3t)};

        //     for (auto const elem : l3t->entries) {
        //         if (bsl::ZERO_UMAX == elem.data->p) {
        //             continue;
        //         }

        //         this->output_spacing(is_l0te_last_index);
        //         this->output_spacing(is_l1te_last_index);
        //         this->output_spacing(is_l2te_last_index);
        //         this->output_decoration_and_index(elem.index, last_index);

        //         bsl::print() << bsl::rst;
        //         this->output_entry_and_flags(elem.data);
        //     }
        // }

        // /// <!-- descril3tion -->
        // ///   @brief Returns the virtual address associated with a specific
        // ///     l3te that was allocated using the page pool.
        // ///
        // /// <!-- inputs/outputs -->
        // ///   @param l3te the l3te_t to convert
        // ///   @return Returns the virtual address associated with a specific
        // ///     l3te that was allocated using the page pool.
        // ///
        // [[nodiscard]] constexpr auto
        // l3te_from_page_pool_to_virt(loader::l3te_t *const l3te) noexcept -> void *
        // {
        //     bsl::safe_uintmax entry_phys{l3te->phys};
        //     entry_phys <<= HYPERVISOR_PAGE_SHIFT;

        //     return m_page_pool->phys_to_virt(entry_phys);
        // }

        // /// <!-- descril3tion -->
        // ///   @brief Returns the virtual address associated with a specific
        // ///     l3te that was allocated using the huge pool.
        // ///
        // /// <!-- inputs/outputs -->
        // ///   @param l3te the l3te_t to convert
        // ///   @return Returns the virtual address associated with a specific
        // ///     l3te that was allocated using the huge pool.
        // ///
        // [[nodiscard]] constexpr auto
        // l3te_from_huge_pool_to_virt(loader::l3te_t *const l3te) noexcept -> void *
        // {
        //     bsl::safe_uintmax entry_phys{l3te->phys};
        //     entry_phys <<= HYPERVISOR_PAGE_SHIFT;

        //     return m_huge_pool->phys_to_virt(entry_phys);
        // }

        /// <!-- descril3tion -->
        ///   @brief Returns the page aligned version of the addr
        ///
        /// <!-- inputs/outputs -->
        ///   @param addr the address to query
        ///   @return Returns the page aligned version of the addr
        ///
        [[nodiscard]] static constexpr auto
        page_aligned(bsl::safe_uintmax const &addr) noexcept -> bsl::safe_uintmax
        {
            return (addr & ~(HYPERVISOR_PAGE_SIZE - bsl::ONE_UMAX));
        }

        /// <!-- descril3tion -->
        ///   @brief Returns true if the provided address is page aligned
        ///
        /// <!-- inputs/outputs -->
        ///   @param addr the address to query
        ///   @return Returns true if the provided address is page aligned
        ///
        [[nodiscard]] static constexpr auto
        is_page_aligned(bsl::safe_uintmax const &addr) noexcept -> bool
        {
            return (addr & (HYPERVISOR_PAGE_SIZE - bsl::ONE_UMAX)) == bsl::ZERO_UMAX;
        }

        /// <!-- descril3tion -->
        ///   @brief Allocates a page from the provided page pool and maps it
        ///     into the root page table being managed by this class The page
        ///     is marked as "auto release", meaning when this root page table
        ///     is released, the pages allocated by this function will
        ///     automatically be deallocated and put back into the provided
        ///     page pool.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
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
            bsl::safe_uintmax const &page_virt,
            bsl::safe_uintmax const &page_flags,
            bsl::safe_int32 const &auto_release) noexcept -> void *
        {
            // bsl::errc_type ret{};

            void *page{};

            bsl::discard(tls);
            bsl::discard(page_virt);
            bsl::discard(page_flags);
            bsl::discard(auto_release);
            // switch (auto_release.get()) {
            //     case MAP_PAGE_AUTO_RELEASE_STACK.get(): {
            //         page = m_page_pool->allocate(tls, ALLOCATE_TAG_EXT_STACK);
            //         break;
            //     }

            //     case MAP_PAGE_AUTO_RELEASE_TLS.get(): {
            //         page = m_page_pool->allocate(tls, ALLOCATE_TAG_EXT_TLS);
            //         break;
            //     }

            //     case MAP_PAGE_AUTO_RELEASE_ELF.get(): {
            //         page = m_page_pool->allocate(tls, ALLOCATE_TAG_EXT_ELF);
            //         break;
            //     }

            //     default: {
            //         bsl::error() << "unknown tag\n" << bsl::here();
            //         break;
            //     }
            // }

            // if (bsl::unlikely(nullptr == page)) {
            //     bsl::print<bsl::V>() << bsl::here();
            //     return nullptr;
            // }

            // auto const page_phys{m_page_pool->virt_to_phys(page)};
            // if (bsl::unlikely_assert(!page_phys)) {
            //     bsl::error() << "physical address is invalid "    // --
            //                  << bsl::hex(page_phys)                // --
            //                  << bsl::endl                          // --
            //                  << bsl::here();                       // --

            //     return nullptr;
            // }

            // ret = this->map_page(tls, page_virt, page_phys, page_flags, auto_release);
            // if (bsl::unlikely(!ret)) {
            //     bsl::print<bsl::V>() << bsl::here();
            //     return nullptr;
            // }

            return page;
        }

        // /// <!-- descril3tion -->
        // ///   @brief Releases the memory allocated for tables
        // ///
        // /// <!-- inputs/outputs -->
        // ///   @param tls the current TLS block
        // ///
        // constexpr void
        // release_tables(tls_t &tls) noexcept
        // {
        //     if (bsl::unlikely(nullptr == m_l0t)) {
        //         return;
        //     }

        //     if (bsl::unlikely(nullptr == m_page_pool)) {
        //         return;
        //     }

        //     if (bsl::unlikely(nullptr == m_huge_pool)) {
        //         return;
        //     }

        //     for (auto const elem : m_l0t->entries) {
        //         if (elem.data->p == bsl::ZERO_UMAX) {
        //             continue;
        //         }

        //         if (elem.data->alias != bsl::ZERO_UMAX) {
        //             continue;
        //         }

        //         this->remove_l1t(tls, elem.data);
        //     }

        //     m_page_pool->deallocate(tls, m_l0t, ALLOCATE_TAG_PML4TS);
        //     m_l0t = {};
        //     m_l0t_phys = bsl::safe_uintmax::failure();
        // }

    public:
        /// <!-- descril3tion -->
        ///   @brief Initializes this root_page_table_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param intrinsic the intrinsics to use
        ///   @param page_pool the page pool to use
        ///   @param huge_pool the huge pool to use
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        initialize(
            tls_t &tls,
            intrinsic_t *const intrinsic,
            page_pool_t *const page_pool,
            huge_pool_t *const huge_pool) noexcept -> bsl::errc_type
        {
            bsl::print() << bsl::rst << "Hello from ARMv8 on a Raspberry Pi 4!!!\n";
            bsl::print() << bsl::endl;

            bsl::error() << "aarch64 support not complete"    // --
                         << bsl::endl                         // --
                         << bsl::here();                      // --

            return bsl::errc_failure;

            bsl::discard(tls);
            bsl::discard(intrinsic);
            bsl::discard(page_pool);
            bsl::discard(huge_pool);

            // if (bsl::unlikely_assert(m_initialized)) {
            //     bsl::error() << "root_page_table_t already initialized\n" << bsl::here();
            //     return bsl::errc_failure;
            // }

            // bsl::finally release_on_error{[this, &tls]() noexcept -> void {
            //     this->release(tls);
            // }};

            // m_intrinsic = intrinsic;
            // if (bsl::unlikely_assert(nullptr == intrinsic)) {
            //     bsl::error() << "invalid intrinsic\n" << bsl::here();
            //     return bsl::errc_failure;
            // }

            // m_page_pool = page_pool;
            // if (bsl::unlikely_assert(nullptr == page_pool)) {
            //     bsl::error() << "invalid page_pool\n" << bsl::here();
            //     return bsl::errc_failure;
            // }

            // m_huge_pool = huge_pool;
            // if (bsl::unlikely_assert(nullptr == huge_pool)) {
            //     bsl::error() << "invalid huge_pool\n" << bsl::here();
            //     return bsl::errc_failure;
            // }

            // m_l0t = m_page_pool->template allocate<l0t_t>(tls, ALLOCATE_TAG_PML4TS);
            // if (bsl::unlikely(nullptr == m_l0t)) {
            //     bsl::print<bsl::V>() << bsl::here();
            //     return bsl::errc_failure;
            // }

            // m_l0t_phys = m_page_pool->virt_to_phys(m_l0t);
            // if (bsl::unlikely_assert(!m_l0t_phys)) {
            //     bsl::print<bsl::V>() << bsl::here();
            //     return bsl::errc_failure;
            // }

            // release_on_error.ignore();
            // m_initialized = true;

            // return bsl::errc_success;
        }

        /// <!-- descril3tion -->
        ///   @brief Releases all of the resources used by the RPT.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///
        constexpr void
        release(tls_t &tls) noexcept
        {
            lock_guard_t lock{tls, m_lock};

            // this->release_tables(tls);

            m_huge_pool = {};
            m_page_pool = {};
            m_intrinsic = {};
            m_initialized = false;
        }

        /// <!-- descril3tion -->
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

        /// <!-- descril3tion -->
        ///   @brief Sets the current root page table to this root page table.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        activate() const noexcept -> bsl::errc_type
        {
            if (bsl::unlikely_assert(!m_initialized)) {
                bsl::error() << "root_page_table_t not initialized\n" << bsl::here();
                return bsl::errc_failure;
            }

            // m_intrinsic->set_cr3(m_l0t_phys);
            return bsl::errc_success;
        }

        /// <!-- descril3tion -->
        ///   @brief Given a root page table, the l0te_t enties are aliased
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

            if (bsl::unlikely_assert(!m_initialized)) {
                bsl::error() << "root_page_table_t not initialized\n" << bsl::here();
                return bsl::errc_failure;
            }

            bsl::discard(rpt);
            // auto const *const l0t{static_cast<l0t_t const *>(rpt)};
            // if (bsl::unlikely_assert(nullptr == l0t)) {
            //     bsl::error() << "invalid rpt\n" << bsl::here();
            //     return bsl::errc_failure;
            // }

            // for (auto const elem : l0t->entries) {
            //     if (elem.data->p != bsl::ZERO_UMAX) {
            //         auto *const pml4e_dst{m_l0t->entries.at_if(elem.index)};

            //         *pml4e_dst = *elem.data;
            //         pml4e_dst->alias = bsl::ONE_UMAX.get();
            //     }
            //     else {
            //         bsl::touch();
            //     }
            // }

            return bsl::errc_success;
        }

        /// <!-- descril3tion -->
        ///   @brief Given a root page table, the l0te_t enties are aliased
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
            return this->add_tables(tls, rpt.m_l0t);
        }

        /// <!-- descril3tion -->
        ///   @brief Maps a page into the root page table being managed
        ///     by this class.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
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
            bsl::safe_uintmax const &page_virt,
            bsl::safe_uintmax const &page_phys,
            bsl::safe_uintmax const &page_flags,
            bsl::safe_int32 const &auto_release) noexcept -> bsl::errc_type
        {
            lock_guard_t lock{tls, m_lock};

            if (bsl::unlikely_assert(!m_initialized)) {
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

            // auto *const l0te{m_l0t->entries.at_if(this->l0to(page_virt))};
            // if (l0te->p == bsl::ZERO_UMAX) {
            //     if (bsl::unlikely(!this->add_l1t(tls, l0te))) {
            //         bsl::print<bsl::V>() << bsl::here();
            //         return bsl::errc_failure;
            //     }

            //     bsl::touch();
            // }
            // else {

            //     /// NOTE:
            //     /// - The loader doesn't map in the memory associated with
            //     ///   the microkernel's page tables. This means this code
            //     ///   cannot walk any pages mapped to the microkernel, it
            //     ///   can only alias these pages. For this reason, mapping
            //     ///   must always take place on userspace specific memory
            //     ///   and the address spaces must be distinct.
            //     ///

            //     if (l0te->us == bsl::ZERO_UMAX) {
            //         bsl::error() << "atteml3t to map the userspace address "              // --
            //                      << bsl::hex(page_virt)                                  // --
            //                      << " in an address range owned by the kernel failed"    // --
            //                      << bsl::endl                                            // --
            //                      << bsl::here();                                         // --

            //         return bsl::errc_failure;
            //     }

            //     bsl::touch();
            // }

            // auto *const l1t{this->get_l1t(l0te)};
            // auto *const l1te{l1t->entries.at_if(this->l1to(page_virt))};
            // if (l1te->p == bsl::ZERO_UMAX) {
            //     if (bsl::unlikely(!this->add_l2t(tls, l1te))) {
            //         bsl::print<bsl::V>() << bsl::here();
            //         return bsl::errc_failure;
            //     }

            //     bsl::touch();
            // }
            // else {
            //     bsl::touch();
            // }

            // auto *const l2t{this->get_l2t(l1te)};
            // auto *const l2te{l2t->entries.at_if(this->l2to(page_virt))};
            // if (l2te->p == bsl::ZERO_UMAX) {
            //     if (bsl::unlikely(!this->add_l3t(tls, l2te))) {
            //         bsl::print<bsl::V>() << bsl::here();
            //         return bsl::errc_failure;
            //     }

            //     bsl::touch();
            // }
            // else {
            //     bsl::touch();
            // }

            // auto *const l3t{this->get_l3t(l2te)};
            // auto *const l3te{l3t->entries.at_if(this->l3to(page_virt))};
            // if (bsl::unlikely(l3te->p != bsl::ZERO_UMAX)) {
            //     bsl::error() << "virtual address "     // --
            //                  << bsl::hex(page_virt)    // --
            //                  << " already mapped"      // --
            //                  << bsl::endl              // --
            //                  << bsl::here();           // --

            //     return bsl::errc_already_exists;
            // }

            // l3te->phys = (page_phys >> HYPERVISOR_PAGE_SHIFT).get();
            // l3te->p = bsl::ONE_UMAX.get();
            // l3te->us = bsl::ONE_UMAX.get();
            // l3te->auto_release = auto_release.get();

            // if (!(page_flags & MAP_PAGE_WRITE).is_zero()) {
            //     l3te->rw = bsl::ONE_UMAX.get();
            // }
            // else {
            //     l3te->rw = bsl::ZERO_UMAX.get();
            // }

            // if (!(page_flags & MAP_PAGE_EXECUTE).is_zero()) {
            //     l3te->nx = bsl::ZERO_UMAX.get();
            // }
            // else {
            //     l3te->nx = bsl::ONE_UMAX.get();
            // }

            return bsl::errc_success;
        }

        /// <!-- descril3tion -->
        ///   @brief Maps a page into the root page table being managed
        ///     by this class. This version allows for unaligned virtual and
        ///     physical addresses and will perform the alignment for you.
        ///     Note that you should only use this function if you actually
        ///     need unaligned support to ensure alignment mistakes are not
        ///     accidentally introduced.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
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
            bsl::safe_uintmax const &page_virt,
            bsl::safe_uintmax const &page_phys,
            bsl::safe_uintmax const &page_flags,
            bsl::safe_int32 const &auto_release) noexcept -> bsl::errc_type
        {
            return this->map_page(
                tls,
                this->page_aligned(page_virt),
                this->page_aligned(page_phys),
                page_flags,
                auto_release);
        }

        /// <!-- descril3tion -->
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
        ///   @param page_virt the virtual address to map the allocated
        ///     page to
        ///   @param auto_release defines what auto release tag to use
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        allocate_page_rw(
            tls_t &tls,
            bsl::safe_uintmax const &page_virt,
            bsl::safe_int32 const &auto_release) noexcept -> void *
        {
            if (bsl::unlikely_assert(!m_initialized)) {
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
                tls, page_virt, MAP_PAGE_READ | MAP_PAGE_WRITE, auto_release);
        }

        /// <!-- descril3tion -->
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
        ///   @param page_virt the virtual address to map the allocated
        ///     page to
        ///   @param auto_release defines what auto release tag to use
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        allocate_page_rx(
            tls_t &tls,
            bsl::safe_uintmax const &page_virt,
            bsl::safe_int32 const &auto_release) noexcept -> void *
        {
            if (bsl::unlikely_assert(!m_initialized)) {
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
                tls, page_virt, MAP_PAGE_READ | MAP_PAGE_EXECUTE, auto_release);
        }

        /// <!-- descril3tion -->
        ///   @brief Dumps the provided pml4_t
        ///
        constexpr void
        dump() const noexcept
        {
            if constexpr (BSL_DEBUG_LEVEL == bsl::CRITICAL_ONLY) {
                return;
            }

            if (bsl::unlikely_assert(!m_initialized)) {
                bsl::print() << "[error]" << bsl::endl;
                return;
            }

            // this->dump_l0t(m_l0t);
            bsl::touch();
        }
    };
}

#endif
