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

#include <pdpt_t.hpp>
#include <pdpte_t.hpp>
#include <pdt_t.hpp>
#include <pdte_t.hpp>
#include <pml4t_t.hpp>
#include <pml4te_t.hpp>
#include <pt_t.hpp>
#include <pte_t.hpp>

#include <bsl/convert.hpp>
#include <bsl/debug.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/finally.hpp>
#include <bsl/fmt.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/touch.hpp>
#include <bsl/unlikely.hpp>

namespace mk
{
    /// @class mk::root_page_table_t
    ///
    /// <!-- description -->
    ///   @brief TODO
    ///
    /// <!-- template parameters -->
    ///   @tparam INTRINSIC_CONCEPT defines the type of intrinsics to use
    ///   @tparam PAGE_POOL_CONCEPT defines the type of page pool to use
    ///   @tparam PAGE_SIZE defines the size of a page
    ///   @tparam PAGE_SHIFT defines number of bits in a page
    ///
    template<
        typename INTRINSIC_CONCEPT,
        typename PAGE_POOL_CONCEPT,
        bsl::uintmax PAGE_SIZE,
        bsl::uintmax PAGE_SHIFT>
    class root_page_table_t final
    {
        /// @brief stores true if initialized() has been executed
        bool m_initialized{};
        /// @brief stores a reference to the intrinsics to use
        INTRINSIC_CONCEPT *m_intrinsic{};
        /// @brief stores a reference to the page pool to use
        PAGE_POOL_CONCEPT *m_page_pool{};
        /// @brief stores a pointer to the pml4t
        pml4t_t *m_pml4t{};
        /// @brief stores the CR3 value used to activate this RPT
        bsl::safe_uintmax m_pml4t_phys;

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
        [[nodiscard]] constexpr auto
        get_last_index(TABLE_CONCEPT const *const table) const noexcept -> bsl::safe_uintmax
        {
            bsl::safe_uintmax last_index{};
            for (auto const elem : table->entries) {
                if (bsl::ZERO_UMAX == elem.data->p) {
                    continue;
                }

                last_index = elem.index;
            }

            return last_index;
        }

        /// <!-- description -->
        ///   @brief Given an outputter, index and the index of the last
        ///     present entry in the page table being dumped, this function
        ///     will output a decoration and the index.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam T the type of outputter provided
        ///   @param o the instance of the outputter used to output the value.
        ///   @param index the current index of the entry being dumped
        ///   @param last_index the index of the last present entry in the page
        ///     table being dumped.
        ///
        template<typename T>
        constexpr void
        output_decoration_and_index(
            bsl::out<T> const o,
            bsl::safe_uintmax const &index,
            bsl::safe_uintmax const &last_index) const noexcept
        {
            o << bsl::reset_color;

            if (index != last_index) {
                o << "├── ";
            }
            else {
                o << "└── ";
            }

            o << "[" << bsl::yellow << bsl::fmt("#05x", index) << bsl::reset_color << "] ";
        }

        /// <!-- description -->
        ///   @brief Given an outputter, and whether or not the page table
        ///     entry is the last entry in the table, this function will
        ///     either output whitespace, or a | and shitespace.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam T the type of outputter provided
        ///   @param o the instance of the outputter used to output the value.
        ///   @param is_last_index true if the entry being outputted is the
        ///     last index in the table.
        ///
        template<typename T>
        constexpr void
        output_spacing(bsl::out<T> const o, bool const is_last_index) const noexcept
        {
            o << bsl::reset_color;

            if (!is_last_index) {
                o << "│   ";
            }
            else {
                o << "    ";
            }
        }

        /// <!-- description -->
        ///   @brief Given and outputter and a page table entry, this
        ///     function outputs the flags associated with the entry
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam T the type of outputter provided
        ///   @tparam ENTRY_CONCEPT the type of page table entry to output
        ///   @param o the instance of the outputter used to output the value.
        ///   @param entry the page table entry to output
        ///
        template<typename T, typename ENTRY_CONCEPT>
        constexpr void
        output_entry_and_flags(bsl::out<T> const o, ENTRY_CONCEPT const *const entry) const noexcept
        {
            bool add_comma{};

            o << bsl::hex(*static_cast<bsl::uint64 const *>(static_cast<void const *>(entry)));
            o << bsl::reset_color << " (";

            if (bsl::ZERO_UMAX != entry->rw) {
                o << bsl::green << "W" << bsl::reset_color;
                add_comma = true;
            }
            else {
                bsl::touch();
            }

            if (bsl::ZERO_UMAX != entry->us) {
                if (add_comma) {
                    o << ", ";
                }
                else {
                    bsl::touch();
                }

                o << bsl::green << "U" << bsl::reset_color;
                add_comma = true;
            }
            else {
                bsl::touch();
            }

            if (bsl::ZERO_UMAX != entry->nx) {
                if (add_comma) {
                    o << ", ";
                }
                else {
                    bsl::touch();
                }

                o << bsl::green << "NX" << bsl::reset_color;
                add_comma = true;
            }
            else {
                bsl::touch();
            }

            if constexpr (bsl::is_same<ENTRY_CONCEPT, loader::pml4te_t>::value) {
                if (bsl::ZERO_UMAX != entry->alias) {
                    if (add_comma) {
                        o << ", ";
                    }
                    else {
                        bsl::touch();
                    }

                    o << bsl::green << "alias" << bsl::reset_color;
                }
                else {
                    bsl::touch();
                }
            }

            if constexpr (bsl::is_same<ENTRY_CONCEPT, loader::pte_t>::value) {
                if (bsl::ZERO_UMAX != entry->auto_release) {
                    if (add_comma) {
                        o << ", ";
                    }
                    else {
                        bsl::touch();
                    }

                    o << bsl::green << "auto_release" << bsl::reset_color;
                }
                else {
                    bsl::touch();
                }
            }

            o << ")" << bsl::endl;
        }

        /// <!-- description -->
        ///   @brief Returns the page-map level-4 (PML4T) offset given a
        ///     virtual address.
        ///
        /// <!-- inputs/outputs -->
        ///   @param virt the virtual address to get the PML4T offset from.
        ///   @return the PML4T offset from the virtual address
        ///
        [[nodiscard]] constexpr auto
        pml4to(bsl::safe_uintmax const &virt) const noexcept -> bsl::safe_uintmax
        {
            constexpr bsl::safe_uintmax mask{bsl::to_umax(0x1FF)};
            constexpr bsl::safe_uintmax shift{bsl::to_umax(39)};
            return (virt >> shift) & mask;
        }

        /// <!-- description -->
        ///   @brief Dumps the provided pml4t_t
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam T the type of outputter provided
        ///   @param o the instance of the outputter used to output the value.
        ///   @param pml4t the pml4t_t to dump
        ///
        template<typename T>
        constexpr void
        dump_pml4t(bsl::out<T> const o, pml4t_t const *const pml4t) const noexcept
        {
            bsl::safe_uintmax const last_index{this->get_last_index(pml4t)};

            o << bsl::blue                                     // --
              << bsl::hex(m_page_pool->virt_to_phys(pml4t))    // --
              << ": "                                          // --
              << bsl::endl;                                    // --

            for (auto const elem : pml4t->entries) {
                if (bsl::ZERO_UMAX == elem.data->p) {
                    continue;
                }

                this->output_decoration_and_index(o, elem.index, last_index);

                if (bsl::ZERO_UMAX != elem.data->us) {
                    o << bsl::blue;
                }
                else {
                    o << bsl::black;
                }

                this->output_entry_and_flags(o, elem.data);

                if (bsl::ZERO_UMAX != elem.data->us) {
                    this->dump_pdpt(o, this->get_pdpt(elem.data), elem.index == last_index);
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
        ///   @param pml4te the pml4te_t to add a pdpt_t too
        ///   @param us if true, this function will map the table with
        ///     userspace privileges.
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] constexpr auto
        add_pdpt(loader::pml4te_t *const pml4te, bool const us) noexcept -> bsl::errc_type
        {
            auto const *const table{m_page_pool->template allocate<void>()};
            if (bsl::unlikely(nullptr == table)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            auto const table_phys{m_page_pool->virt_to_phys(table)};
            if (bsl::unlikely(!table_phys)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            pml4te->phys = (table_phys >> PAGE_SHIFT).get();
            pml4te->p = bsl::ONE_UMAX.get();
            pml4te->rw = bsl::ONE_UMAX.get();

            if (us) {
                pml4te->us = bsl::ONE_UMAX.get();
            }
            else {
                pml4te->us = bsl::ZERO_UMAX.get();
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Adds a pdpt_t to the provided pml4te_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param pml4te the pml4te_t to add a pdpt_t too
        ///
        constexpr void
        remove_pdpt(loader::pml4te_t *const pml4te) noexcept
        {
            for (auto const elem : get_pdpt(pml4te)->entries) {
                if (elem.data->p != bsl::ZERO_UMAX) {
                    this->remove_pdt(elem.data);
                }
                else {
                    bsl::touch();
                }
            }

            m_page_pool->deallocate(get_pdpt(pml4te));
        }

        /// <!-- description -->
        ///   @brief Returns the pdpt_t associated with the provided
        ///     pml4te_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param pml4te the pml4te_t to get the pdpt_t from
        ///   @return A pointer to the requested pdpt_t
        ///
        [[nodiscard]] constexpr auto
        get_pdpt(loader::pml4te_t *const pml4te) noexcept -> pdpt_t *
        {
            bsl::safe_uintmax entry_phys{pml4te->phys};
            entry_phys <<= PAGE_SHIFT;

            return m_page_pool->template phys_to_virt<pdpt_t *>(entry_phys);
        }

        /// <!-- description -->
        ///   @brief Returns the pdpt_t associated with the provided
        ///     pml4te_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param pml4te the pml4te_t to get the pdpt_t from
        ///   @return A pointer to the requested pdpt_t
        ///
        [[nodiscard]] constexpr auto
        get_pdpt(loader::pml4te_t const *const pml4te) const noexcept -> pdpt_t const *
        {
            bsl::safe_uintmax entry_phys{pml4te->phys};
            entry_phys <<= PAGE_SHIFT;

            return m_page_pool->template phys_to_virt<pdpt_t const *>(entry_phys);
        }

        /// <!-- description -->
        ///   @brief Returns the page-directory-pointer table (PDPT) offset
        ///     given a virtual address.
        ///
        /// <!-- inputs/outputs -->
        ///   @param virt the virtual address to get the PDPT offset from.
        ///   @return the PDPT offset from the virtual address
        ///
        [[nodiscard]] constexpr auto
        pdpto(bsl::safe_uintmax const &virt) const noexcept -> bsl::safe_uintmax
        {
            constexpr bsl::safe_uintmax mask{bsl::to_umax(0x1FF)};
            constexpr bsl::safe_uintmax shift{bsl::to_umax(30)};
            return (virt >> shift) & mask;
        }

        /// <!-- description -->
        ///   @brief Dumps the provided pdpt_t
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam T the type of outputter provided
        ///   @param o the instance of the outputter used to output the value.
        ///   @param pdpt the pdpt_t to dump
        ///   @param is_pml4te_last_index true if the parent pml4te was the
        ///     last pml4te in the table
        ///
        template<typename T>
        constexpr void
        dump_pdpt(
            bsl::out<T> const o, pdpt_t const *const pdpt, bool is_pml4te_last_index) const noexcept
        {
            bsl::safe_uintmax const last_index{this->get_last_index(pdpt)};

            for (auto const elem : pdpt->entries) {
                if (bsl::ZERO_UMAX == elem.data->p) {
                    continue;
                }

                this->output_spacing(o, is_pml4te_last_index);
                this->output_decoration_and_index(o, elem.index, last_index);

                o << bsl::blue;
                this->output_entry_and_flags(o, elem.data);

                this->dump_pdt(
                    o, this->get_pdt(elem.data), is_pml4te_last_index, elem.index == last_index);
            }
        }

        /// <!-- description -->
        ///   @brief Adds a pdt_t to the provided pdpte_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param pdpte the pdpte_t to add a pdt_t too
        ///   @param us if true, this function will map the table with
        ///     userspace privileges.
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] constexpr auto
        add_pdt(loader::pdpte_t *const pdpte, bool const us) noexcept -> bsl::errc_type
        {
            auto const *const table{m_page_pool->template allocate<void>()};
            if (bsl::unlikely(nullptr == table)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            auto const table_phys{m_page_pool->virt_to_phys(table)};
            if (bsl::unlikely(!table_phys)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            pdpte->phys = (table_phys >> PAGE_SHIFT).get();
            pdpte->p = bsl::ONE_UMAX.get();
            pdpte->rw = bsl::ONE_UMAX.get();

            if (us) {
                pdpte->us = bsl::ONE_UMAX.get();
            }
            else {
                pdpte->us = bsl::ZERO_UMAX.get();
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Adds a pdt_t to the provided pdpte_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param pdpte the pdpte_t to add a pdt_t too
        ///
        constexpr void
        remove_pdt(loader::pdpte_t *const pdpte) noexcept
        {
            for (auto const elem : get_pdt(pdpte)->entries) {
                if (elem.data->p != bsl::ZERO_UMAX) {
                    this->remove_pt(elem.data);
                }
                else {
                    bsl::touch();
                }
            }

            m_page_pool->deallocate(get_pdt(pdpte));
        }

        /// <!-- description -->
        ///   @brief Returns the pdt_t associated with the provided
        ///     pdpte_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param pdpte the pdpte_t to get the pdt_t from
        ///   @return A pointer to the requested pdt_t
        ///
        [[nodiscard]] constexpr auto
        get_pdt(loader::pdpte_t *const pdpte) noexcept -> pdt_t *
        {
            bsl::safe_uintmax entry_phys{pdpte->phys};
            entry_phys <<= PAGE_SHIFT;

            return m_page_pool->template phys_to_virt<pdt_t *>(entry_phys);
        }

        /// <!-- description -->
        ///   @brief Returns the pdt_t associated with the provided
        ///     pdpte_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param pdpte the pdpte_t to get the pdt_t from
        ///   @return A pointer to the requested pdt_t
        ///
        [[nodiscard]] constexpr auto
        get_pdt(loader::pdpte_t const *const pdpte) const noexcept -> pdt_t const *
        {
            bsl::safe_uintmax entry_phys{pdpte->phys};
            entry_phys <<= PAGE_SHIFT;

            return m_page_pool->template phys_to_virt<pdt_t const *>(entry_phys);
        }

        /// <!-- description -->
        ///   @brief Returns the page-directory table (PDT) offset given a
        ///     virtual address.
        ///
        /// <!-- inputs/outputs -->
        ///   @param virt the virtual address to get the PDT offset from.
        ///   @return the PDT offset from the virtual address
        ///
        [[nodiscard]] constexpr auto
        pdto(bsl::safe_uintmax const &virt) const noexcept -> bsl::safe_uintmax
        {
            constexpr bsl::safe_uintmax mask{bsl::to_umax(0x1FF)};
            constexpr bsl::safe_uintmax shift{bsl::to_umax(21)};
            return (virt >> shift) & mask;
        }

        /// <!-- description -->
        ///   @brief Dumps the provided pdt_t
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam T the type of outputter provided
        ///   @param o the instance of the outputter used to output the value.
        ///   @param pdt the pdt_t to dump
        ///   @param is_pml4te_last_index true if the parent pml4te was the
        ///     last pml4te in the table
        ///   @param is_pdpte_last_index true if the parent pdpte was the
        ///     last pdpte in the table
        ///
        template<typename T>
        constexpr void
        dump_pdt(
            bsl::out<T> const o,
            pdt_t const *const pdt,
            bool is_pml4te_last_index,
            bool is_pdpte_last_index) const noexcept
        {
            bsl::safe_uintmax const last_index{this->get_last_index(pdt)};

            for (auto const elem : pdt->entries) {
                if (bsl::ZERO_UMAX == elem.data->p) {
                    continue;
                }

                this->output_spacing(o, is_pml4te_last_index);
                this->output_spacing(o, is_pdpte_last_index);
                this->output_decoration_and_index(o, elem.index, last_index);

                o << bsl::blue;
                this->output_entry_and_flags(o, elem.data);

                this->dump_pt(
                    o,
                    this->get_pt(elem.data),
                    is_pml4te_last_index,
                    is_pdpte_last_index,
                    elem.index == last_index);
            }
        }

        /// <!-- description -->
        ///   @brief Adds a pt_t to the provided pdte_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param pdte the pdte_t to add a pt_t too
        ///   @param us if true, this function will map the table with
        ///     userspace privileges.
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] constexpr auto
        add_pt(loader::pdte_t *const pdte, bool const us) noexcept -> bsl::errc_type
        {
            auto const *const table{m_page_pool->template allocate<void>()};
            if (bsl::unlikely(nullptr == table)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            auto const table_phys{m_page_pool->virt_to_phys(table)};
            if (bsl::unlikely(!table_phys)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            pdte->phys = (table_phys >> PAGE_SHIFT).get();
            pdte->p = bsl::ONE_UMAX.get();
            pdte->rw = bsl::ONE_UMAX.get();

            if (us) {
                pdte->us = bsl::ONE_UMAX.get();
            }
            else {
                pdte->us = bsl::ZERO_UMAX.get();
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Adds a pt_t to the provided pdte_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param pdte the pdte_t to add a pt_t too
        ///
        constexpr void
        remove_pt(loader::pdte_t *const pdte) noexcept
        {
            m_page_pool->deallocate(get_pt(pdte));
        }

        /// <!-- description -->
        ///   @brief Returns the pt_t associated with the provided
        ///     pdte_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param pdte the pdte_t to get the pt_t from
        ///   @return A pointer to the requested pt_t
        ///
        [[nodiscard]] constexpr auto
        get_pt(loader::pdte_t *const pdte) noexcept -> pt_t *
        {
            bsl::safe_uintmax entry_phys{pdte->phys};
            entry_phys <<= PAGE_SHIFT;

            return m_page_pool->template phys_to_virt<pt_t *>(entry_phys);
        }

        /// <!-- description -->
        ///   @brief Returns the pt_t associated with the provided
        ///     pdte_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param pdte the pdte_t to get the pt_t from
        ///   @return A pointer to the requested pt_t
        ///
        [[nodiscard]] constexpr auto
        get_pt(loader::pdte_t const *const pdte) const noexcept -> pt_t const *
        {
            bsl::safe_uintmax entry_phys{pdte->phys};
            entry_phys <<= PAGE_SHIFT;

            return m_page_pool->template phys_to_virt<pt_t const *>(entry_phys);
        }

        /// <!-- description -->
        ///   @brief Returns the page-table (PT) offset given a
        ///     virtual address.
        ///
        /// <!-- inputs/outputs -->
        ///   @param virt the virtual address to get the PT offset from.
        ///   @return the PT offset from the virtual address
        ///
        [[nodiscard]] constexpr auto
        pto(bsl::safe_uintmax const &virt) const noexcept -> bsl::safe_uintmax
        {
            constexpr bsl::safe_uintmax mask{bsl::to_umax(0x1FF)};
            constexpr bsl::safe_uintmax shift{bsl::to_umax(12)};
            return (virt >> shift) & mask;
        }

        /// <!-- description -->
        ///   @brief Dumps the provided pt_t
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam T the type of outputter provided
        ///   @param o the instance of the outputter used to output the value.
        ///   @param pt the pt_t to dump
        ///   @param is_pml4te_last_index true if the parent pml4te was the
        ///     last pml4te in the table
        ///   @param is_pdpte_last_index true if the parent pdpte was the
        ///     last pdpte in the table
        ///   @param is_pdte_last_index true if the parent pdte was the
        ///     last pdte in the table
        ///
        template<typename T>
        constexpr void
        dump_pt(
            bsl::out<T> const o,
            pt_t const *const pt,
            bool is_pml4te_last_index,
            bool is_pdpte_last_index,
            bool is_pdte_last_index) const noexcept
        {
            bsl::safe_uintmax const last_index{this->get_last_index(pt)};

            for (auto const elem : pt->entries) {
                if (bsl::ZERO_UMAX == elem.data->p) {
                    continue;
                }

                this->output_spacing(o, is_pml4te_last_index);
                this->output_spacing(o, is_pdpte_last_index);
                this->output_spacing(o, is_pdte_last_index);
                this->output_decoration_and_index(o, elem.index, last_index);

                o << bsl::white;
                this->output_entry_and_flags(o, elem.data);
            }
        }

        /// <!-- description -->
        ///   @brief Returns the page aligned version of the addr
        ///
        /// <!-- inputs/outputs -->
        ///   @param addr the address to query
        ///   @return Returns the page aligned version of the addr
        ///
        [[nodiscard]] constexpr auto
        page_aligned(bsl::safe_uintmax const &addr) const noexcept -> bsl::safe_uintmax
        {
            return (addr & ~(PAGE_SIZE - bsl::ONE_UMAX));
        }

        /// <!-- description -->
        ///   @brief Returns true if the provided address is page aligned
        ///
        /// <!-- inputs/outputs -->
        ///   @param addr the address to query
        ///   @return Returns true if the provided address is page aligned
        ///
        [[nodiscard]] constexpr auto
        is_page_aligned(bsl::safe_uintmax const &addr) const noexcept -> bool
        {
            return (addr & (PAGE_SIZE - bsl::ONE_UMAX)) == bsl::ZERO_UMAX;
        }

        /// <!-- description -->
        ///   @brief Maps a page into the root page table being managed
        ///     by this class.
        ///
        /// <!-- inputs/outputs -->
        ///   @param page_virt the virtual address to map the physical address
        ///     too
        ///   @param page_phys the physical address to map
        ///   @param executable if true, the page is mapped as read/execute,
        ///     otherwise the page is mapped as read/write
        ///   @param us if true, map_page will map the page with userspace
        ///     privileges.
        ///   @param auto_release if true, the page is mapped as auto_release
        ///     meaning the page will be deallocated when the root page table
        ///     loses scope.
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] constexpr auto
        map_page(
            bsl::safe_uintmax const &page_virt,
            bsl::safe_uintmax const &page_phys,
            bool const executable,
            bool const us,
            bool const auto_release) noexcept -> bsl::errc_type
        {
            auto *const pml4te{m_pml4t->entries.at_if(this->pml4to(page_virt))};
            if (pml4te->p == bsl::ZERO_UMAX) {
                if (bsl::unlikely(!this->add_pdpt(pml4te, us))) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                bsl::touch();
            }
            else {
                if (us) {
                    if (pml4te->us == bsl::ZERO_UMAX) {
                        bsl::error() << "attempt to map the userspace address "              // --
                                     << bsl::hex(page_virt)                                  // --
                                     << " in an address range owned by the kernel failed"    // --
                                     << bsl::endl                                            // --
                                     << bsl::here();                                         // --

                        return bsl::errc_failure;
                    }

                    bsl::touch();
                }
                else {
                    if (pml4te->us == bsl::ONE_UMAX) {
                        bsl::error() << "attempt to map the kernel address "                // --
                                     << bsl::hex(page_virt)                                 // --
                                     << " in an address range owned by userspace failed"    // --
                                     << bsl::endl                                           // --
                                     << bsl::here();                                        // --

                        return bsl::errc_failure;
                    }

                    bsl::touch();
                }
            }

            auto *const pdpt{this->get_pdpt(pml4te)};
            auto *const pdpte{pdpt->entries.at_if(this->pdpto(page_virt))};
            if (pdpte->p == bsl::ZERO_UMAX) {
                if (bsl::unlikely(!this->add_pdt(pdpte, us))) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                bsl::touch();
            }
            else {
                bsl::touch();
            }

            auto *const pdt{this->get_pdt(pdpte)};
            auto *const pdte{pdt->entries.at_if(this->pdto(page_virt))};
            if (pdte->p == bsl::ZERO_UMAX) {
                if (bsl::unlikely(!this->add_pt(pdte, us))) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                bsl::touch();
            }
            else {
                bsl::touch();
            }

            auto *const pt{this->get_pt(pdte)};
            auto *const pte{pt->entries.at_if(this->pto(page_virt))};
            if (bsl::unlikely(pte->p != bsl::ZERO_UMAX)) {
                bsl::error() << "virtual address "     // --
                             << bsl::hex(page_virt)    // --
                             << " already mapped"      // --
                             << bsl::endl              // --
                             << bsl::here();           // --

                return bsl::errc_failure;
            }

            pte->phys = (page_phys >> PAGE_SHIFT).get();
            pte->p = bsl::ONE_UMAX.get();

            if (executable) {
                pte->rw = bsl::ZERO_UMAX.get();
                pte->nx = bsl::ZERO_UMAX.get();
            }
            else {
                pte->rw = bsl::ONE_UMAX.get();
                pte->nx = bsl::ONE_UMAX.get();
            }

            if (us) {
                pte->us = bsl::ONE_UMAX.get();
            }
            else {
                pte->us = bsl::ZERO_UMAX.get();
            }

            if (auto_release) {
                pte->auto_release = bsl::ONE_UMAX.get();
            }
            else {
                pte->auto_release = bsl::ZERO_UMAX.get();
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Unmaps a previously mapped page.
        ///
        /// <!-- inputs/outputs -->
        ///   @param page_virt the virtual address to unmap
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] constexpr auto
        unmap_page(bsl::safe_uintmax const &page_virt) noexcept -> bsl::errc_type
        {
            auto *const pml4te{m_pml4t->entries.at_if(this->pml4to(page_virt))};
            if (bsl::unlikely(pml4te->p == bsl::ZERO_UMAX)) {
                bsl::error() << "virtual address "     // --
                             << bsl::hex(page_virt)    // --
                             << " not mapped"          // --
                             << bsl::endl              // --
                             << bsl::here();           // --

                return bsl::errc_failure;
            }

            auto *const pdpt{this->get_pdpt(pml4te)};
            auto *const pdpte{pdpt->entries.at_if(this->pdpto(page_virt))};
            if (bsl::unlikely(pdpte->p == bsl::ZERO_UMAX)) {
                bsl::error() << "virtual address "     // --
                             << bsl::hex(page_virt)    // --
                             << " not mapped"          // --
                             << bsl::endl              // --
                             << bsl::here();           // --

                return bsl::errc_failure;
            }

            auto *const pdt{this->get_pdt(pdpte)};
            auto *const pdte{pdt->entries.at_if(this->pdto(page_virt))};
            if (bsl::unlikely(pdte->p == bsl::ZERO_UMAX)) {
                bsl::error() << "virtual address "     // --
                             << bsl::hex(page_virt)    // --
                             << " not mapped"          // --
                             << bsl::endl              // --
                             << bsl::here();           // --

                return bsl::errc_failure;
            }

            auto *const pt{this->get_pt(pdte)};
            auto *const pte{pt->entries.at_if(this->pto(page_virt))};
            if (bsl::unlikely(pte->p == bsl::ZERO_UMAX)) {
                bsl::error() << "virtual address "     // --
                             << bsl::hex(page_virt)    // --
                             << " not mapped"          // --
                             << bsl::endl              // --
                             << bsl::here();           // --

                return bsl::errc_failure;
            }

            *pte = {};

            bool remove_pt{true};
            for (auto const elem : pt->entries) {
                if (elem.data->p != bsl::ZERO_UMAX) {
                    remove_pt = false;
                    break;
                }
            }

            if (remove_pt) {
                m_page_pool->deallocate(pt);
                *pdte = {};
            }

            bool remove_pdt{true};
            for (auto const elem : pdt->entries) {
                if (elem.data->p != bsl::ZERO_UMAX) {
                    remove_pdt = false;
                    break;
                }
            }

            if (remove_pdt) {
                m_page_pool->deallocate(pdt);
                *pdpte = {};
            }

            bool remove_pdpt{true};
            for (auto const elem : pdpt->entries) {
                if (elem.data->p != bsl::ZERO_UMAX) {
                    remove_pdpt = false;
                    break;
                }
            }

            if (remove_pdpt) {
                m_page_pool->deallocate(pdpt);
                *pml4te = {};
            }

            m_intrinsic->invlpg(page_virt);
            return bsl::errc_success;
        }

    public:
        /// @brief an alias for INTRINSIC_CONCEPT
        using intrinsic_type = INTRINSIC_CONCEPT;
        /// @brief an alias for PAGE_POOL_CONCEPT
        using page_pool_type = PAGE_POOL_CONCEPT;

        /// <!-- description -->
        ///   @brief Creates a root_page_table_t
        ///
        constexpr root_page_table_t() noexcept = default;

        /// <!-- description -->
        ///   @brief Initializes this root_page_table_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param intrinsic the intrinsics to use
        ///   @param page_pool the page pool to use
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] constexpr auto
        initialize(INTRINSIC_CONCEPT *const intrinsic, PAGE_POOL_CONCEPT *const page_pool) &noexcept
            -> bsl::errc_type
        {
            if (bsl::unlikely(m_initialized)) {
                bsl::error() << "root_page_table_t already initialized\n" << bsl::here();
                return bsl::errc_failure;
            }

            bsl::finally release_on_error{[this]() noexcept -> void {
                this->release();
            }};

            m_intrinsic = intrinsic;
            if (bsl::unlikely(nullptr == intrinsic)) {
                bsl::error() << "invalid intrinsic\n" << bsl::here();
                return bsl::errc_failure;
            }

            m_page_pool = page_pool;
            if (bsl::unlikely(nullptr == page_pool)) {
                bsl::error() << "invalid page_pool\n" << bsl::here();
                return bsl::errc_failure;
            }

            m_pml4t = m_page_pool->template allocate<pml4t_t>();
            if (bsl::unlikely(nullptr == m_pml4t)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            m_pml4t_phys = m_page_pool->virt_to_phys(m_pml4t);
            if (bsl::unlikely(!m_pml4t_phys)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            release_on_error.ignore();
            m_initialized = true;

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Releases the memory allocated in this root page table
        ///
        constexpr void
        release() &noexcept
        {
            if (nullptr != m_page_pool) {
                if (nullptr != m_pml4t) {
                    for (auto const elem : m_pml4t->entries) {
                        if (elem.data->p == bsl::ZERO_UMAX) {
                            continue;
                        }

                        if (elem.data->alias != bsl::ZERO_UMAX) {
                            continue;
                        }

                        this->remove_pdpt(elem.data);
                    }
                }
                else {
                    bsl::touch();
                }

                m_page_pool->deallocate(m_pml4t);
            }
            else {
                bsl::touch();
            }

            m_pml4t = {};
            m_page_pool = {};
            m_intrinsic = {};
            m_initialized = false;
        }

        /// <!-- description -->
        ///   @brief Destructor
        ///
        constexpr ~root_page_table_t() noexcept = default;

        /// <!-- description -->
        ///   @brief copy constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///
        constexpr root_page_table_t(root_page_table_t const &o) noexcept = delete;

        /// <!-- description -->
        ///   @brief move constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being moved
        ///
        constexpr root_page_table_t(root_page_table_t &&o) noexcept = default;

        /// <!-- description -->
        ///   @brief copy assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///   @return a reference to *this
        ///
        [[maybe_unused]] constexpr auto operator=(root_page_table_t const &o) &noexcept
            -> root_page_table_t & = delete;

        /// <!-- description -->
        ///   @brief move assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being moved
        ///   @return a reference to *this
        ///
        [[maybe_unused]] constexpr auto operator=(root_page_table_t &&o) &noexcept
            -> root_page_table_t & = default;

        /// <!-- description -->
        ///   @brief Sets the current root page table to this root page table.
        ///
        constexpr void
        activate() const noexcept
        {
            m_intrinsic->set_cr3(m_pml4t_phys);
        }

        /// <!-- description -->
        ///   @brief Returns true if the current root page table is this root
        ///     page table.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if the current root page table is this root
        ///     page table.
        ///
        [[nodiscard]] constexpr auto
        is_active() const noexcept -> bool
        {
            return (m_intrinsic->cr3() == m_pml4t_phys);
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
        ///   @param rpt the root page table to add aliases to
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] constexpr auto
        add_tables(void const *const rpt) &noexcept -> bsl::errc_type
        {
            if (bsl::unlikely(!m_initialized)) {
                bsl::error() << "root_page_table_t not initialized\n" << bsl::here();
                return bsl::errc_failure;
            }

            auto const *const pml4t{static_cast<pml4t_t const *>(rpt)};
            if (bsl::unlikely(nullptr == pml4t)) {
                bsl::error() << "invalid rpt\n" << bsl::here();
                return bsl::errc_failure;
            }

            for (auto const elem : pml4t->entries) {
                if (elem.data->p != bsl::ZERO_UMAX) {
                    auto *const pml4e_dst{m_pml4t->entries.at_if(elem.index)};
                    if (bsl::unlikely(pml4e_dst->p != bsl::ZERO_UMAX)) {
                        bsl::error() << "unable to merge page tables\n" << bsl::here();
                        return bsl::errc_failure;
                    }

                    *pml4e_dst = *elem.data;
                    pml4e_dst->alias = bsl::ONE_UMAX.get();
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
        ///   @param rpt the root page table to add aliases to
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] constexpr auto
        add_tables(root_page_table_t const &rpt) &noexcept -> bsl::errc_type
        {
            return this->add_tables(rpt.m_pml4t);
        }

        /// <!-- description -->
        ///   @brief Maps a page into the root page table being managed
        ///     by this class using read/write permissions.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam T defines the type of virtual address being mapped
        ///   @param page_virt the virtual address to map the physical address
        ///     too
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        template<typename T>
        [[nodiscard]] constexpr auto
        map_page_rw(T const page_virt) &noexcept -> bsl::errc_type
        {
            static_assert(bsl::is_pointer<T>::value);
            static_assert(bsl::is_standard_layout<T>::value);

            if (bsl::unlikely(!m_initialized)) {
                bsl::error() << "root_page_table_t not initialized\n" << bsl::here();
                return bsl::errc_failure;
            }

            if (bsl::unlikely(!page_virt)) {
                bsl::error() << "virtual address is invalid: "    // --
                             << bsl::hex(page_virt)               // --
                             << bsl::endl                         // --
                             << bsl::here();                      // --

                return bsl::errc_failure;
            }

            if (bsl::unlikely(!this->is_page_aligned(page_virt))) {
                bsl::error() << "virtual address is not page aligned: "    // --
                             << bsl::hex(page_virt)                        // --
                             << bsl::endl                                  // --
                             << bsl::here();                               // --

                return bsl::errc_failure;
            }

            auto const page_phys{m_page_pool->virt_to_phys(page_virt)};
            if (bsl::unlikely(!page_phys)) {
                bsl::error() << "physical address is invalid: "    // --
                             << bsl::hex(page_phys)                // --
                             << bsl::endl                          // --
                             << bsl::here();                       // --

                return bsl::errc_failure;
            }

            return this->map_page(bsl::to_umax(page_virt), page_phys, false, true, false);
        }

        /// <!-- description -->
        ///   @brief Maps a page into the root page table being managed
        ///     by this class using read/write permissions.
        ///
        /// <!-- inputs/outputs -->
        ///   @param page_virt the virtual address to map the physical address too
        ///   @param page_phys the physical address to map
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] constexpr auto
        map_page_rw(
            bsl::safe_uintmax const &page_virt, bsl::safe_uintmax const &page_phys) &noexcept
            -> bsl::errc_type
        {
            if (bsl::unlikely(!m_initialized)) {
                bsl::error() << "root_page_table_t not initialized\n" << bsl::here();
                return bsl::errc_failure;
            }

            if (bsl::unlikely(!page_virt)) {
                bsl::error() << "virtual address is invalid: "    // --
                             << bsl::hex(page_virt)               // --
                             << bsl::endl                         // --
                             << bsl::here();                      // --

                return bsl::errc_failure;
            }

            if (bsl::unlikely(!this->is_page_aligned(page_virt))) {
                bsl::error() << "virtual address is not page aligned: "    // --
                             << bsl::hex(page_virt)                        // --
                             << bsl::endl                                  // --
                             << bsl::here();                               // --

                return bsl::errc_failure;
            }

            if (bsl::unlikely(!page_phys)) {
                bsl::error() << "physical address is invalid: "    // --
                             << bsl::hex(page_phys)                // --
                             << bsl::endl                          // --
                             << bsl::here();                       // --

                return bsl::errc_failure;
            }

            if (bsl::unlikely(!this->is_page_aligned(page_phys))) {
                bsl::error() << "physical address is not page aligned: "    // --
                             << bsl::hex(page_phys)                         // --
                             << bsl::endl                                   // --
                             << bsl::here();                                // --

                return bsl::errc_failure;
            }

            return this->map_page(page_virt, page_phys, false, true, false);
        }

        /// <!-- description -->
        ///   @brief Maps a page into the root page table being managed
        ///     by this class using read/execute permissions.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam T defines the type of virtual address being mapped
        ///   @param page_virt the virtual address to map the physical address too
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        template<typename T>
        [[nodiscard]] constexpr auto
        map_page_rx(T const page_virt) &noexcept -> bsl::errc_type
        {
            static_assert(bsl::is_pointer<T>::value);
            static_assert(bsl::is_standard_layout<T>::value);

            if (bsl::unlikely(!m_initialized)) {
                bsl::error() << "root_page_table_t not initialized\n" << bsl::here();
                return bsl::errc_failure;
            }

            if (bsl::unlikely(!page_virt)) {
                bsl::error() << "virtual address is invalid: "    // --
                             << bsl::hex(page_virt)               // --
                             << bsl::endl                         // --
                             << bsl::here();                      // --

                return bsl::errc_failure;
            }

            if (bsl::unlikely(!this->is_page_aligned(page_virt))) {
                bsl::error() << "virtual address is not page aligned: "    // --
                             << bsl::hex(page_virt)                        // --
                             << bsl::endl                                  // --
                             << bsl::here();                               // --

                return bsl::errc_failure;
            }

            auto const page_phys{m_page_pool->virt_to_phys(page_virt)};
            if (bsl::unlikely(!page_phys)) {
                bsl::error() << "physical address is invalid: "    // --
                             << bsl::hex(page_phys)                // --
                             << bsl::endl                          // --
                             << bsl::here();                       // --

                return bsl::errc_failure;
            }

            return this->map_page(bsl::to_umax(page_virt), page_phys, true, true, false);
        }

        /// <!-- description -->
        ///   @brief Maps a page into the root page table being managed
        ///     by this class using read/execute permissions.
        ///
        /// <!-- inputs/outputs -->
        ///   @param page_virt the virtual address to map the physical address too
        ///   @param page_phys the physical address to map
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] constexpr auto
        map_page_rx(
            bsl::safe_uintmax const &page_virt, bsl::safe_uintmax const &page_phys) &noexcept
            -> bsl::errc_type
        {
            if (bsl::unlikely(!m_initialized)) {
                bsl::error() << "root_page_table_t not initialized\n" << bsl::here();
                return bsl::errc_failure;
            }

            if (bsl::unlikely(!page_virt)) {
                bsl::error() << "virtual address is invalid: "    // --
                             << bsl::hex(page_virt)               // --
                             << bsl::endl                         // --
                             << bsl::here();                      // --

                return bsl::errc_failure;
            }

            if (bsl::unlikely(!this->is_page_aligned(page_virt))) {
                bsl::error() << "virtual address is not page aligned: "    // --
                             << bsl::hex(page_virt)                        // --
                             << bsl::endl                                  // --
                             << bsl::here();                               // --

                return bsl::errc_failure;
            }

            if (bsl::unlikely(!page_phys)) {
                bsl::error() << "physical address is invalid: "    // --
                             << bsl::hex(page_phys)                // --
                             << bsl::endl                          // --
                             << bsl::here();                       // --

                return bsl::errc_failure;
            }

            if (bsl::unlikely(!this->is_page_aligned(page_phys))) {
                bsl::error() << "physical address is not page aligned: "    // --
                             << bsl::hex(page_phys)                         // --
                             << bsl::endl                                   // --
                             << bsl::here();                                // --

                return bsl::errc_failure;
            }

            return this->map_page(page_virt, page_phys, true, true, false);
        }

        /// <!-- description -->
        ///   @brief Allocates a page from the provided page pool and maps it
        ///     into the root page table being managed by this class using
        ///     read/write permissions. The page is marked as "auto release",
        ///     meaning when this root page table is released, the pages
        ///     allocated by this function will automatically be deallocated
        ///     and put back into the provided page pool.
        ///
        /// <!-- inputs/outputs -->
        ///   @param page_virt the virtual address to map the page too
        ///   @return Returns a pointer to the allocated page, or a nullptr
        ///     on failure.
        ///
        [[nodiscard]] constexpr auto
        allocate_rw(bsl::safe_uintmax const &page_virt) &noexcept -> void *
        {
            if (bsl::unlikely(!m_initialized)) {
                bsl::error() << "root_page_table_t not initialized\n" << bsl::here();
                return nullptr;
            }

            if (bsl::unlikely(!page_virt)) {
                bsl::error() << "virtual address is invalid: "    // --
                             << bsl::hex(page_virt)               // --
                             << bsl::endl                         // --
                             << bsl::here();                      // --

                return nullptr;
            }

            if (bsl::unlikely(!this->is_page_aligned(page_virt))) {
                bsl::error() << "virtual address is not page aligned: "    // --
                             << bsl::hex(page_virt)                        // --
                             << bsl::endl                                  // --
                             << bsl::here();                               // --

                return nullptr;
            }

            auto *const page{m_page_pool->template allocate<void>()};
            if (bsl::unlikely(nullptr == page)) {
                bsl::print<bsl::V>() << bsl::here();
                return nullptr;
            }

            auto const page_phys{m_page_pool->virt_to_phys(page)};
            if (bsl::unlikely(!page_phys)) {
                bsl::error() << "physical address is invalid: "    // --
                             << bsl::hex(page_phys)                // --
                             << bsl::endl                          // --
                             << bsl::here();                       // --

                return nullptr;
            }

            if (bsl::unlikely(!this->map_page(page_virt, page_phys, false, true, true))) {
                bsl::print<bsl::V>() << bsl::here();
                return nullptr;
            }

            return page;
        }

        /// <!-- description -->
        ///   @brief Allocates a page from the provided page pool and maps it
        ///     into the root page table being managed by this class using
        ///     read/execute permissions. The page is marked as "auto release",
        ///     meaning when this root page table is released, the pages
        ///     allocated by this function will automatically be deallocated
        ///     and put back into the provided page pool.
        ///
        /// <!-- inputs/outputs -->
        ///   @param page_virt the virtual address to map the page too
        ///   @return Returns a pointer to the allocated page, or a nullptr
        ///     on failure.
        ///
        [[nodiscard]] constexpr auto
        allocate_rx(bsl::safe_uintmax const &page_virt) &noexcept -> void *
        {
            if (bsl::unlikely(!m_initialized)) {
                bsl::error() << "root_page_table_t not initialized\n" << bsl::here();
                return nullptr;
            }

            if (bsl::unlikely(!page_virt)) {
                bsl::error() << "virtual address is invalid: "    // --
                             << bsl::hex(page_virt)               // --
                             << bsl::endl                         // --
                             << bsl::here();                      // --

                return nullptr;
            }

            if (bsl::unlikely(!this->is_page_aligned(page_virt))) {
                bsl::error() << "virtual address is not page aligned: "    // --
                             << bsl::hex(page_virt)                        // --
                             << bsl::endl                                  // --
                             << bsl::here();                               // --

                return nullptr;
            }

            auto *const page{m_page_pool->template allocate<void>()};
            if (bsl::unlikely(nullptr == page)) {
                bsl::print<bsl::V>() << bsl::here();
                return nullptr;
            }

            auto const page_phys{m_page_pool->virt_to_phys(page)};
            if (bsl::unlikely(!page_phys)) {
                bsl::error() << "physical address is invalid: "    // --
                             << bsl::hex(page_phys)                // --
                             << bsl::endl                          // --
                             << bsl::here();                       // --

                return nullptr;
            }

            if (bsl::unlikely(!this->map_page(page_virt, page_phys, true, true, true))) {
                bsl::print<bsl::V>() << bsl::here();
                return nullptr;
            }

            return page;
        }

        /// <!-- description -->
        ///   @brief Converts the provided virtual address to a physical
        ///     address by walking the page table. If the resulting conversion
        ///     is a microkernel address, or the virtual address is not mapped,
        ///     this function will return an error.
        ///
        /// <!-- inputs/outputs -->
        ///   @param page_virt the virtual address to convert
        ///   @return Returns the resulting physical address.
        ///
        [[nodiscard]] constexpr auto
        virt_to_phys(bsl::safe_uintmax const &page_virt) &noexcept -> bsl::safe_uintmax
        {
            if (bsl::unlikely(!m_initialized)) {
                bsl::error() << "root_page_table_t not initialized\n" << bsl::here();
                return bsl::safe_uintmax::zero(true);
            }

            if (bsl::unlikely(!page_virt)) {
                bsl::error() << "virtual address is invalid: "    // --
                             << bsl::hex(page_virt)               // --
                             << bsl::endl                         // --
                             << bsl::here();                      // --

                return bsl::safe_uintmax::zero(true);
            }

            if (bsl::unlikely(!this->is_page_aligned(page_virt))) {
                bsl::error() << "virtual address is not page aligned: "    // --
                             << bsl::hex(page_virt)                        // --
                             << bsl::endl                                  // --
                             << bsl::here();                               // --

                return bsl::safe_uintmax::zero(true);
            }

            auto *const pml4te{m_pml4t->entries.at_if(this->pml4to(page_virt))};
            if (pml4te->p == bsl::ZERO_UMAX) {
                bsl::error() << "virtual address "     // --
                             << bsl::hex(page_virt)    // --
                             << " was never mapped"    // --
                             << bsl::endl              // --
                             << bsl::here();           // --

                return bsl::safe_uintmax::zero(true);
            }

            if (pml4te->us == bsl::ZERO_UMAX) {
                bsl::error() << "unable to convert the kernel virtual address: "    // --
                             << bsl::hex(page_virt)                                 // --
                             << bsl::endl                                           // --
                             << bsl::here();                                        // --

                return bsl::safe_uintmax::zero(true);
            }

            auto *const pdpte{this->get_pdpt(pml4te)->entries.at_if(this->pdpto(page_virt))};
            if (pdpte->p == bsl::ZERO_UMAX) {
                bsl::error() << "virtual address "     // --
                             << bsl::hex(page_virt)    // --
                             << " was never mapped"    // --
                             << bsl::endl              // --
                             << bsl::here();           // --

                return bsl::safe_uintmax::zero(true);
            }

            auto *const pdte{this->get_pdt(pdpte)->entries.at_if(this->pdto(page_virt))};
            if (pdte->p == bsl::ZERO_UMAX) {
                bsl::error() << "virtual address "     // --
                             << bsl::hex(page_virt)    // --
                             << " was never mapped"    // --
                             << bsl::endl              // --
                             << bsl::here();           // --

                return bsl::safe_uintmax::zero(true);
            }

            auto *const pte{this->get_pt(pdte)->entries.at_if(this->pto(page_virt))};
            if (bsl::unlikely(pte->p != bsl::ZERO_UMAX)) {
                bsl::error() << "virtual address "     // --
                             << bsl::hex(page_virt)    // --
                             << " was never mapped"    // --
                             << bsl::endl              // --
                             << bsl::here();           // --

                return bsl::safe_uintmax::zero(true);
            }

            return bsl::safe_uintmax{pte->phys} << PAGE_SHIFT;
        }

        /// <!-- description -->
        ///   @brief Dumps the provided pml4_t
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam T the type of outputter provided
        ///   @param o the instance of the outputter used to output the value.
        ///
        template<typename T>
        constexpr void
        dump(bsl::out<T> const o) const noexcept
        {
            if (bsl::unlikely(!m_initialized)) {
                o << "[error]" << bsl::endl;
                return;
            }

            this->dump_pml4t(o, m_pml4t);
        }
    };

    /// <!-- description -->
    ///   @brief Outputs the provided mk::root_page_table_t to the provided
    ///     output type.
    ///   @related mk::root_page_table_t
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of outputter provided
    ///   @tparam INTRINSIC_CONCEPT defines the type of intrinsics to use
    ///   @tparam PAGE_POOL_CONCEPT defines the type of page pool to use
    ///   @tparam PAGE_SIZE defines the size of a page
    ///   @tparam PAGE_SHIFT defines number of bits in a page
    ///   @param o the instance of the outputter used to output the value.
    ///   @param rpt the root_page_table_t to output
    ///   @return return o
    ///
    template<
        typename T,
        typename INTRINSIC_CONCEPT,
        typename PAGE_POOL_CONCEPT,
        bsl::uintmax PAGE_SIZE,
        bsl::uintmax PAGE_SHIFT>
    [[maybe_unused]] constexpr auto
    operator<<(
        bsl::out<T> const o,
        mk::root_page_table_t<INTRINSIC_CONCEPT, PAGE_POOL_CONCEPT, PAGE_SIZE, PAGE_SHIFT> const
            &rpt) noexcept -> bsl::out<T>
    {
        if constexpr (!o) {
            return o;
        }

        rpt.dump(o);
        return o;
    }
}

#endif
