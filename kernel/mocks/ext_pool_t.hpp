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

#ifndef MOCKS_EXT_POOL_T_HPP
#define MOCKS_EXT_POOL_T_HPP

#include <huge_pool_t.hpp>
#include <intrinsic_t.hpp>
#include <mk_args_t.hpp>
#include <page_pool_t.hpp>
#include <root_page_table_t.hpp>
#include <tls_t.hpp>

#include <bsl/discard.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/safe_integral.hpp>

namespace mk
{
    /// @brief defines a unit testing specific error code
    constexpr bsl::errc_type UNIT_TEST_EXT_POOL_FAIL_INITIALIZE{-2001};
    /// @brief defines a unit testing specific error code
    constexpr bsl::errc_type UNIT_TEST_EXT_POOL_FAIL_START{-2002};
    /// @brief defines a unit testing specific error code
    constexpr bsl::errc_type UNIT_TEST_EXT_POOL_FAIL_BOOTSTRAP{-2003};

    /// <!-- description -->
    ///   @brief Defines the microkernel's extension pool
    ///
    class ext_pool_t final
    {
    public:
        /// <!-- description -->
        ///   @brief Initializes this ext_pool_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param page_pool the page_pool_t to use
        ///   @param huge_pool the huge_pool_t to use
        ///   @param system_rpt the system RPT provided by the loader
        ///   @param elf_files the ext_elf_files provided by the loader
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] static constexpr auto
        initialize(
            tls_t const &tls,
            page_pool_t const &page_pool,
            huge_pool_t const &huge_pool,
            root_page_table_t const &system_rpt,
            loader::ext_elf_files_t const &elf_files) noexcept -> bsl::errc_type
        {
            bsl::discard(page_pool);
            bsl::discard(huge_pool);
            bsl::discard(system_rpt);
            bsl::discard(elf_files);

            if (UNIT_TEST_EXT_POOL_FAIL_INITIALIZE == tls.test_ret) {
                return UNIT_TEST_EXT_POOL_FAIL_INITIALIZE;
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Release the ext_pool_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param page_pool the page_pool_t to use
        ///   @param huge_pool the huge_pool_t to use
        ///
        static constexpr void
        release(
            tls_t const &tls, page_pool_t const &page_pool, huge_pool_t const &huge_pool) noexcept
        {
            bsl::discard(tls);
            bsl::discard(page_pool);
            bsl::discard(huge_pool);
        }

        /// <!-- description -->
        ///   @brief Tells each extension that a VM was created so that it
        ///     can initialize it's VM specific resources.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param page_pool the page_pool_t to use
        ///   @param vmid the ID of the VM that was created.
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] static constexpr auto
        signal_vm_created(
            tls_t const &tls, page_pool_t const &page_pool, bsl::safe_u16 const &vmid) noexcept
            -> bsl::errc_type
        {
            bsl::discard(page_pool);
            bsl::discard(vmid);

            return tls.test_ret;
        }

        /// <!-- description -->
        ///   @brief Tells each extension that a VM was destroyed so that it
        ///     can release it's VM specific resources.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param page_pool the page_pool_t to use
        ///   @param vmid the ID of the VM that was destroyed.
        ///
        static constexpr void
        signal_vm_destroyed(
            tls_t const &tls, page_pool_t const &page_pool, bsl::safe_u16 const &vmid) noexcept
        {
            bsl::discard(tls);
            bsl::discard(page_pool);
            bsl::discard(vmid);
        }

        /// <!-- description -->
        ///   @brief Tells the extensions that the requested VM was set to
        ///     active and therefore it's memory map should change on this PP.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param intrinsic the intrinsic_t to use
        ///   @param vmid the ID of the VM that was created.
        ///
        static constexpr void
        signal_vm_active(
            tls_t const &tls, intrinsic_t const &intrinsic, bsl::safe_u16 const &vmid) noexcept
        {
            bsl::discard(tls);
            bsl::discard(intrinsic);
            bsl::discard(vmid);
        }

        /// <!-- description -->
        ///   @brief Starts this ext_pool_t by calling all of the
        ///     extension's _start entry points.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param intrinsic the intrinsic_t to use
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] static constexpr auto
        start(tls_t const &tls, intrinsic_t const &intrinsic) noexcept -> bsl::errc_type
        {
            bsl::discard(intrinsic);

            if (UNIT_TEST_EXT_POOL_FAIL_START == tls.test_ret) {
                return UNIT_TEST_EXT_POOL_FAIL_START;
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Bootstraps this ext_pool_t by calling all of the
        ///     registered bootstrap callbacks for each extension.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param intrinsic the intrinsic_t to use
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] static constexpr auto
        bootstrap(tls_t &mut_tls, intrinsic_t const &intrinsic) noexcept -> bsl::errc_type
        {
            bsl::discard(intrinsic);

            mut_tls.active_vmid = {};
            mut_tls.active_vpid = {};
            mut_tls.active_vsid = {};
            mut_tls.active_extid = {};

            if (UNIT_TEST_EXT_POOL_FAIL_BOOTSTRAP == mut_tls.test_ret) {
                return UNIT_TEST_EXT_POOL_FAIL_BOOTSTRAP;
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Dumps the requested extension
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param extid the ID of the extension to dump
        ///
        static constexpr void
        dump(tls_t const &tls, bsl::safe_u16 const &extid) noexcept
        {
            bsl::discard(tls);
            bsl::discard(extid);
        }
    };
}

#endif
