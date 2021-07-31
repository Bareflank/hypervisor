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

#ifndef ROOT_PAGE_TABLE_HELPERS_HPP
#define ROOT_PAGE_TABLE_HELPERS_HPP

#include <basic_entry_status_t.hpp>
#include <basic_map_page_flags.hpp>

#include <bsl/ensures.hpp>
#include <bsl/safe_integral.hpp>

namespace helpers
{
    /// <!-- description -->
    ///   @brief Returns basic_entry_status_t::present if the entry is valid. Returns
    ///     basic_entry_status_t::not_present if the entry is invalid. Returns
    ///     basic_entry_status_t::unsupported if the entry cannot be touched.
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam E the type of entry to query
    ///   @param pudm_entry the entry to query
    ///   @return Returns basic_entry_status_t::present if the entry is valid. Returns
    ///     basic_entry_status_t::not_present if the entry is invalid. Returns
    ///     basic_entry_status_t::unsupported if the entry cannot be touched.
    ///
    template<typename E>
    [[nodiscard]] constexpr auto
    entry_status(E *const pudm_entry) noexcept -> lib::basic_entry_status_t
    {
        bsl::expects(nullptr != pudm_entry);

        if (bsl::safe_u64::magic_0() == pudm_entry->p) {
            return lib::basic_entry_status_t::not_present;
        }

        if (bsl::safe_u64::magic_0() == pudm_entry->us) {
            return lib::basic_entry_status_t::reserved;
        }

        return lib::basic_entry_status_t::present;
    }

    /// <!-- description -->
    ///   @brief Configures an entry as a pointer to a block.
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam E the type of entry to configure
    ///   @param pmut_entry the entry to configure
    ///   @param page_flgs defines how memory should be mapped
    ///
    template<typename E>
    constexpr void
    configure_entry_as_ptr_to_block(E *const pmut_entry, bsl::safe_u64 const &page_flgs) noexcept
    {
        bsl::expects(nullptr != pmut_entry);
        bsl::expects(page_flgs.is_valid_and_checked());

        pmut_entry->p = bsl::safe_u64::magic_1().get();
        pmut_entry->us = bsl::safe_u64::magic_1().get();

        if ((page_flgs & lib::BASIC_MAP_PAGE_WRITE).is_zero()) {
            pmut_entry->rw = bsl::safe_u64::magic_0().get();
        }
        else {
            pmut_entry->rw = bsl::safe_u64::magic_1().get();
        }

        if ((page_flgs & lib::BASIC_MAP_PAGE_EXECUTE).is_zero()) {
            pmut_entry->nx = bsl::safe_u64::magic_1().get();
        }
        else {
            pmut_entry->nx = bsl::safe_u64::magic_0().get();
        }
    }

    /// <!-- description -->
    ///   @brief Configures an entry as a pointer to a table.
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam E the type of entry to configure
    ///   @param pmut_entry the entry to configure
    ///
    template<typename E>
    constexpr void
    configure_entry_as_ptr_to_table(E *const pmut_entry) noexcept
    {
        bsl::expects(nullptr != pmut_entry);

        pmut_entry->p = bsl::safe_u64::magic_1().get();
        pmut_entry->rw = bsl::safe_u64::magic_1().get();
        pmut_entry->us = bsl::safe_u64::magic_1().get();
    }
}

#endif
