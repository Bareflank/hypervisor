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

#include "../../../src/basic_page_pool_t.hpp"

#include <basic_page_4k_t.hpp>
#include <tls_t.hpp>

#include <bsl/discard.hpp>
#include <bsl/span.hpp>
#include <bsl/ut.hpp>

namespace
{
    /// @brief verify constinit it supported
    constinit lib::basic_page_pool_t<lib::tls_t> const g_verify_constinit{};
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
            lib::basic_page_pool_t<lib::tls_t> mut_pool{};
            lib::basic_page_pool_t<lib::tls_t> const pool{};
            bsl::span<lib::basic_page_pool_node_t> mut_view{};
            lib::tls_t mut_tls{};
            lib::basic_page_4k_t mut_page{};
            bsl::ut_then{} = []() noexcept {
                static_assert(noexcept(lib::basic_page_pool_t<lib::tls_t>{}));

                static_assert(noexcept(mut_pool.initialize(mut_view)));
                static_assert(noexcept(mut_pool.allocate<lib::basic_page_4k_t>(mut_tls)));
                static_assert(noexcept(mut_pool.deallocate<lib::basic_page_4k_t>(mut_tls, {})));
                static_assert(noexcept(mut_pool.size()));
                static_assert(noexcept(mut_pool.allocated(mut_tls)));
                static_assert(noexcept(mut_pool.remaining(mut_tls)));
                static_assert(noexcept(mut_pool.virt_to_phys<lib::basic_page_4k_t>(&mut_page)));
                static_assert(noexcept(mut_pool.phys_to_virt<lib::basic_page_4k_t>({})));
                static_assert(noexcept(mut_pool.dump(mut_tls)));

                static_assert(noexcept(pool.size()));
                static_assert(noexcept(pool.allocated(mut_tls)));
                static_assert(noexcept(pool.remaining(mut_tls)));
                static_assert(noexcept(pool.dump(mut_tls)));
            };
        };
    };

    return bsl::ut_success();
}
