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

#include "../../../src/basic_root_page_table_t.hpp"

#include <basic_page_4k_t.hpp>
#include <basic_page_pool_t.hpp>
#include <basic_page_table_t.hpp>
#include <intrinsic_t.hpp>
#include <l0e_t.hpp>
#include <l1e_t.hpp>
#include <l2e_t.hpp>
#include <l3e_t.hpp>
#include <tls_t.hpp>

#include <bsl/discard.hpp>
#include <bsl/dontcare_t.hpp>
#include <bsl/ut.hpp>

namespace
{
    /// @brief defines the page_pool_t used by the microkernel
    using page_pool_t = lib::basic_page_pool_t<lib::tls_t>;

    /// @brief defines the root_page_table_t used by the microkernel
    using root_page_table_t = lib::basic_root_page_table_t<
        lib::tls_t,
        bsl::dontcare_t,
        page_pool_t,
        lib::intrinsic_t,
        lib::l3e_t,
        lib::l2e_t,
        lib::l1e_t,
        lib::l0e_t>;

    /// @brief verify constinit it supported
    constinit root_page_table_t const g_verify_constinit{};
}

/// <!-- description -->
///   @brief Main function for this unit test. If a call to bsl::ut_check() fails
///     the application will fast fail. If all calls to bsl::ut_check() pass, this
///     function will successfully return with bsl::exit_success.
///
/// <!-- inputs/outputs -->
///   @return Always returns bsl::exit_success.
///
[[nodiscard]] auto
main() noexcept -> bsl::exit_code
{
    bsl::ut_scenario{"verify supports constinit/constexpr"} = []() noexcept {
        bsl::discard(g_verify_constinit);
    };

    bsl::ut_scenario{"verify noexcept"} = []() noexcept {
        bsl::ut_given{} = []() noexcept {
            root_page_table_t mut_rpt{};
            root_page_table_t const rpt{};
            lib::tls_t mut_tls{};
            page_pool_t mut_page_pool{};
            lib::intrinsic_t mut_intrinsic{};
            lib::basic_page_table_t<lib::l3e_t> const l3e{};
            bsl::ut_then{} = []() noexcept {
                static_assert(noexcept(root_page_table_t{}));

                static_assert(noexcept(mut_rpt.initialize(mut_tls, mut_page_pool)));
                static_assert(noexcept(mut_rpt.release(mut_tls, mut_page_pool)));
                static_assert(noexcept(mut_rpt.is_initialized()));
                static_assert(noexcept(mut_rpt.activate(mut_tls, mut_intrinsic)));
                static_assert(noexcept(mut_rpt.is_inactive(mut_tls)));
                static_assert(noexcept(mut_rpt.spa()));
                static_assert(noexcept(mut_rpt.map(mut_tls, mut_page_pool, {}, {}, {})));
                static_assert(noexcept(
                    mut_rpt.allocate_page<lib::basic_page_4k_t>(mut_tls, mut_page_pool, {}, {})));
                static_assert(noexcept(mut_rpt.allocate_page<>(mut_tls, mut_page_pool)));
                static_assert(noexcept(mut_rpt.unmap(mut_tls, mut_page_pool, {})));
                static_assert(noexcept(mut_rpt.entries(mut_tls, mut_page_pool, {})));
                static_assert(noexcept(mut_rpt.add_tables(mut_tls, &l3e)));
                static_assert(noexcept(mut_rpt.add_tables(mut_tls, rpt)));

                static_assert(noexcept(rpt.is_initialized()));
                static_assert(noexcept(rpt.is_inactive(mut_tls)));
                static_assert(noexcept(rpt.spa()));
            };
        };
    };

    return bsl::ut_success();
}
